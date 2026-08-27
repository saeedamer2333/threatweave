import { Injectable, Logger } from '@nestjs/common';
import { PipelineSettings } from '../settings/settings.service';

/**
 * Talks to Jenkins' own REST API so the dashboard's "Run scan" button can
 * trigger the real DevSecOps pipeline (scanners -> engine), not just
 * re-process whatever is already in findings/scan-inputs/ (that remains
 * available via EngineService for a fast local re-score, e.g. after
 * suppressing a finding).
 *
 * Reachability differs by how ThreatWeave is deployed: a sibling container
 * on the compose network (JENKINS_URL=http://jenkins:8080) or the same
 * container in the all-in-one image (http://127.0.0.1:8080, its default).
 */
const JENKINS_URL = (process.env.JENKINS_URL ?? 'http://127.0.0.1:8080').replace(/\/+$/, '');
const JOB_NAME = 'threatweave-pipeline';

/** Per-request timeout, so one hung connection fails fast rather than
 * hanging indefinitely. */
const POLL_TIMEOUT_MS = 8_000;
const QUEUE_POLL_MS = 2_000;
const CONSOLE_POLL_MS = 3_000;

/** While queued (no build number yet, no console to check), a stall can
 * only be measured by "did Jenkins answer at all" - three minutes of that
 * failing genuinely means something is wrong, since going from queued to
 * running should not itself take long once an executor is free. */
const QUEUE_STALL_LIMIT_MS = 3 * 60_000;

/** Once running, a build can legitimately go a while between console lines
 * under CPU contention (observed in practice: SonarQube parsing ~1000
 * TypeScript files on a loaded host made the *status* endpoint slow enough
 * to trip a flat 90s "no response" rule, even though the build's own
 * console was advancing the whole time). Progress is measured by new
 * console output instead of by whether one particular HTTP call answered
 * quickly, so a slow-but-genuinely-working build is not mistaken for a
 * stuck one; 5 minutes with *zero* new output is a much more reliable
 * "actually stuck" signal (the real stuck-SonarQube incident this was
 * built to catch went 13+ minutes with no new lines at all). */
const RUNNING_STALL_LIMIT_MS = 5 * 60_000;

export interface PipelineStatus {
  state: 'idle' | 'queued' | 'running' | 'success' | 'failed';
  buildNumber?: number;
  buildUrl?: string;
  startedAt?: string;
  finishedAt?: string;
  error?: string;
  /** Most recent line of real output from the build - not just "running",
   * but what it is actually doing right now (e.g. which scanner, which
   * file). Only present while a build is actively running. */
  currentActivity?: string;
}

@Injectable()
export class JenkinsService {
  private readonly logger = new Logger(JenkinsService.name);
  private status: PipelineStatus = { state: 'idle' };
  private pollTimer?: ReturnType<typeof setInterval>;

  private auth(): string {
    const id = process.env.JENKINS_ADMIN_ID ?? 'admin';
    const password = process.env.JENKINS_ADMIN_PASSWORD ?? 'admin';
    return 'Basic ' + Buffer.from(`${id}:${password}`).toString('base64');
  }

  /**
   * `Connection: close` on every request, deliberately trading a little
   * per-request overhead for never reusing a pooled connection. Confirmed
   * live, twice: this long-running process's default keep-alive connection
   * to Jenkins can go stale after a network blip (or, apparently, just under
   * heavy CPU load elsewhere on the host) and then fail on every subsequent
   * request with a generic "fetch failed" - while a brand-new process making
   * the identical call to the identical URL succeeds immediately. The
   * AbortSignal timeout and stall-detection above turn that into a visible,
   * actionable failure instead of an infinite silent retry, but they were
   * still symptom management; this addresses the actual cause by never
   * letting a connection live long enough to go stale in the first place.
   */
  private fetchJenkins(url: string, init: RequestInit = {}): Promise<Response> {
    return fetch(url, {
      ...init,
      headers: { Authorization: this.auth(), Connection: 'close', ...init.headers },
      signal: AbortSignal.timeout(POLL_TIMEOUT_MS),
    });
  }

  getStatus(): PipelineStatus {
    return this.status;
  }

  /** Build query params from settings, honouring per-call overrides. */
  private buildParams(settings: PipelineSettings): URLSearchParams {
    return new URLSearchParams({
      SOURCE_DIR: settings.sourceDir,
      IAC_DIR: settings.iacDir,
      TARGET_IMAGE: settings.targetImage,
      SONAR_PROJECT_KEY: settings.sonarProjectKey,
      RUN_AWS_MONITOR: String(settings.runAwsMonitor),
      FAIL_ON_CRITICAL: String(settings.failOnCritical),
    });
  }

  /**
   * Trigger a build and start tracking it. Returns immediately - the queue
   * item is not yet a real build number, so getStatus() reports "queued"
   * until the background poll resolves it to one.
   *
   * Idempotent while one is already active: returns the current status
   * rather than throwing. It used to throw a plain Error here, which Nest's
   * default exception filter turns into a bare 500 "Internal server error"
   * with no detail - the one call in this service that did not honour the
   * "always resolves to a status object" contract every other failure path
   * here follows, and the one most likely to be hit by an accidental
   * double-click or a repeated request while a build is genuinely still
   * running.
   */
  async triggerBuild(settings: PipelineSettings): Promise<PipelineStatus> {
    if (this.status.state === 'queued' || this.status.state === 'running') {
      return this.status;
    }

    const startedAt = new Date().toISOString();
    this.status = { state: 'queued', startedAt };

    try {
      const crumb = await this.getCrumb();
      const params = this.buildParams(settings);
      const res = await this.fetchJenkins(
        `${JENKINS_URL}/job/${JOB_NAME}/buildWithParameters?${params.toString()}`,
        {
          method: 'POST',
          headers: crumb ? { [crumb.field]: crumb.value, Cookie: crumb.cookie } : {},
        },
      );
      if (!res.ok) {
        throw new Error(`Jenkins returned ${res.status} triggering the build`);
      }
      const queueUrl = res.headers.get('Location');
      if (!queueUrl) {
        throw new Error('Jenkins did not return a queue item location');
      }
      this.pollQueueThenBuild(queueUrl, startedAt);
    } catch (err) {
      this.status = {
        state: 'failed',
        startedAt,
        finishedAt: new Date().toISOString(),
        error: this.describeFailure(err),
      };
      this.logger.error(`Failed to trigger pipeline: ${(err as Error).message}`);
    }
    return this.status;
  }

  /** A timeout/network error reads very differently to a user than an HTTP
   * error - say so plainly rather than surfacing a raw exception message. */
  private describeFailure(err: unknown): string {
    if (err instanceof Error && err.name === 'TimeoutError') {
      return `Jenkins did not respond within ${POLL_TIMEOUT_MS / 1000}s. It may be starting up, overloaded, or unreachable at ${JENKINS_URL}.`;
    }
    return (err as Error).message;
  }

  /**
   * CSRF crumb, required for POST when Jenkins' default protection is on.
   *
   * The crumb alone is not enough over Basic Auth: Jenkins' DefaultCrumbIssuer
   * ties the crumb to a session, and Basic Auth carries no session by itself
   * - each request gets a fresh anonymous one unless the Set-Cookie from this
   * GET is captured and replayed on the POST that uses the crumb. Skipping
   * this produces a confusing "No valid crumb was included in the request"
   * 403 even though the crumb value itself is genuinely correct.
   */
  private async getCrumb(): Promise<{ field: string; value: string; cookie: string } | null> {
    try {
      const res = await this.fetchJenkins(`${JENKINS_URL}/crumbIssuer/api/json`);
      if (!res.ok) return null;
      const cookie = res.headers.get('set-cookie');
      if (!cookie) return null;
      const body = (await res.json()) as { crumbRequestField: string; crumb: string };
      return { field: body.crumbRequestField, value: body.crumb, cookie };
    } catch {
      // No crumb issuer (CSRF protection disabled) - proceed without one.
      return null;
    }
  }

  /** A queued item only becomes a real build once Jenkins has an executor free. */
  private pollQueueThenBuild(queueUrl: string, startedAt: string): void {
    const normalized = queueUrl.endsWith('/') ? queueUrl : `${queueUrl}/`;
    let lastContactAt = Date.now();

    this.pollTimer = setInterval(async () => {
      try {
        const res = await this.fetchJenkins(`${normalized}api/json`);
        lastContactAt = Date.now();
        if (!res.ok) return;
        const body = (await res.json()) as {
          executable?: { number: number; url: string };
          cancelled?: boolean;
        };
        if (body.cancelled) {
          this.stopPolling();
          this.status = { state: 'failed', startedAt, finishedAt: new Date().toISOString(), error: 'Build was cancelled while queued' };
          return;
        }
        if (body.executable) {
          this.stopPolling();
          this.status = {
            state: 'running',
            startedAt,
            buildNumber: body.executable.number,
            buildUrl: body.executable.url,
          };
          this.pollBuild(body.executable.number, body.executable.url, startedAt);
        }
      } catch (err) {
        this.logger.warn(`Queue poll failed: ${(err as Error).message}`);
        if (Date.now() - lastContactAt >= QUEUE_STALL_LIMIT_MS) {
          this.stopPolling();
          const minutes = Math.round(QUEUE_STALL_LIMIT_MS / 60_000);
          this.status = {
            state: 'failed', startedAt, finishedAt: new Date().toISOString(),
            error: `Lost contact with Jenkins while queued - no response for over ${minutes} minute(s). Check that Jenkins is reachable at ${JENKINS_URL}.`,
          };
        }
      }
    }, QUEUE_POLL_MS);
  }

  /**
   * Once a build is running, progress is tracked via its *console output*
   * (Jenkins' progressiveText log API) rather than the structured status
   * endpoint alone - both because it gives a genuine "what is it doing
   * right now" signal for the UI, and because it is a far more reliable
   * stall indicator than "did this one status check respond in time": a
   * CPU-heavy stage (SonarQube parsing hundreds of files) can legitimately
   * make individual HTTP calls slow without the build itself being stuck.
   */
  private pollBuild(buildNumber: number, buildUrl: string, startedAt: string): void {
    let consoleOffset = 0;
    let lastProgressAt = Date.now();

    this.pollTimer = setInterval(async () => {
      try {
        const res = await this.fetchJenkins(`${buildUrl}logText/progressiveText?start=${consoleOffset}`);
        if (res.ok) {
          const chunk = await res.text();
          const nextOffset = Number(res.headers.get('X-Text-Size') ?? consoleOffset);
          const moreData = res.headers.get('X-More-Data') === 'true';
          consoleOffset = Number.isFinite(nextOffset) ? nextOffset : consoleOffset;

          if (chunk.trim()) {
            lastProgressAt = Date.now();
            const activity = latestLine(chunk);
            if (activity) this.status = { ...this.status, currentActivity: activity };
          }

          if (!moreData) {
            // The console is done, but only the structured endpoint carries
            // the actual pass/fail result.
            const statusRes = await this.fetchJenkins(`${buildUrl}api/json`);
            const body = statusRes.ok
              ? ((await statusRes.json()) as { result: string | null })
              : { result: null };
            this.stopPolling();
            this.status = {
              state: body.result === 'SUCCESS' ? 'success' : 'failed',
              startedAt,
              finishedAt: new Date().toISOString(),
              buildNumber,
              buildUrl,
              ...(body.result !== 'SUCCESS' ? { error: `Build result: ${body.result ?? 'unknown'}` } : {}),
            };
            return;
          }
        }
      } catch (err) {
        this.logger.warn(`Build console poll failed: ${(err as Error).message}`);
      }

      if (Date.now() - lastProgressAt >= RUNNING_STALL_LIMIT_MS) {
        this.stopPolling();
        const minutes = Math.round(RUNNING_STALL_LIMIT_MS / 60_000);
        this.status = {
          state: 'failed',
          startedAt,
          finishedAt: new Date().toISOString(),
          buildNumber,
          buildUrl,
          error: `No new output from the build for over ${minutes} minute(s) - it may be stuck. The build itself may still be running; check ${buildUrl} directly.`,
        };
        this.logger.error(`Gave up on build #${buildNumber}: no new console output for ${minutes}+ minutes`);
      }
    }, CONSOLE_POLL_MS);
  }

  private stopPolling(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = undefined;
    }
  }
}

/** The last non-blank line of a console chunk, with Jenkins' timestamp
 * prefix (from the `timestamps()` pipeline option) stripped, trimmed to a
 * reasonable length for a one-line UI display. */
function latestLine(chunk: string): string | null {
  const lines = chunk.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (!lines.length) return null;
  const last = lines[lines.length - 1].replace(/^\[\d{4}-\d{2}-\d{2}T[\d:.]+Z]\s*/, '');
  return last.length > 160 ? `${last.slice(0, 160)}…` : last;
}
