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
 * hanging indefinitely - a long-lived process's pooled HTTP connection can
 * go bad after a network blip (observed in practice: Jenkins itself was
 * healthy again, but the API's own connection to it was not, and kept
 * retrying into the same dead connection). */
const POLL_TIMEOUT_MS = 8_000;

/** Give up and report failure if no successful response has been seen for
 * this long, rather than polling silently forever. Without this, the only
 * symptom of a stuck connection is the dashboard sitting on "Scanning..."
 * with no indication anything is wrong - worse than the crash it's
 * protecting against, since a crash is at least visible. */
const STALL_LIMIT_MS = 90_000;

export interface PipelineStatus {
  state: 'idle' | 'queued' | 'running' | 'success' | 'failed';
  buildNumber?: number;
  buildUrl?: string;
  startedAt?: string;
  finishedAt?: string;
  error?: string;
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

  private fetchJenkins(url: string, init: RequestInit = {}): Promise<Response> {
    return fetch(url, {
      ...init,
      headers: { Authorization: this.auth(), ...init.headers },
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
   */
  async triggerBuild(settings: PipelineSettings): Promise<PipelineStatus> {
    if (this.status.state === 'queued' || this.status.state === 'running') {
      throw new Error('A pipeline run is already in progress');
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
        this.giveUpIfStalled(lastContactAt, startedAt);
      }
    }, 2000);
  }

  private pollBuild(buildNumber: number, buildUrl: string, startedAt: string): void {
    let lastContactAt = Date.now();

    this.pollTimer = setInterval(async () => {
      try {
        const res = await this.fetchJenkins(`${buildUrl}api/json`);
        lastContactAt = Date.now();
        if (!res.ok) return;
        const body = (await res.json()) as { building: boolean; result: string | null };
        if (!body.building) {
          this.stopPolling();
          this.status = {
            state: body.result === 'SUCCESS' ? 'success' : 'failed',
            startedAt,
            finishedAt: new Date().toISOString(),
            buildNumber,
            buildUrl,
            ...(body.result !== 'SUCCESS' ? { error: `Build result: ${body.result}` } : {}),
          };
        }
      } catch (err) {
        this.logger.warn(`Build poll failed: ${(err as Error).message}`);
        this.giveUpIfStalled(lastContactAt, startedAt, buildNumber, buildUrl);
      }
    }, 3000);
  }

  /** Stop retrying and report a clear, actionable failure once contact has
   * genuinely been lost for a while - rather than an unbounded silent retry
   * loop the dashboard has no way to distinguish from "still working". */
  private giveUpIfStalled(lastContactAt: number, startedAt: string, buildNumber?: number, buildUrl?: string): void {
    const stalledFor = Date.now() - lastContactAt;
    if (stalledFor < STALL_LIMIT_MS) return;

    this.stopPolling();
    const minutes = Math.round(STALL_LIMIT_MS / 60_000);
    this.status = {
      state: 'failed',
      startedAt,
      finishedAt: new Date().toISOString(),
      ...(buildNumber ? { buildNumber, buildUrl } : {}),
      error: `Lost contact with Jenkins - no response for over ${minutes} minute(s). ` +
        (buildUrl
          ? `The build itself may still be running; check ${buildUrl} directly.`
          : `Check that Jenkins is reachable at ${JENKINS_URL}.`),
    };
    this.logger.error(`Gave up polling after ${Math.round(stalledFor / 1000)}s with no response from Jenkins`);
  }

  private stopPolling(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = undefined;
    }
  }
}
