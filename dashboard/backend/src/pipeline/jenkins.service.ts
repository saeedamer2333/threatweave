import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { Agent, fetch as undiciFetch, type RequestInit, type Response } from 'undici';
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

/** How often to check whether Jenkins is running a build this service
 * doesn't already know about, while otherwise idle. Frequent enough that a
 * cron-triggered build is reflected on the dashboard within a reasonable
 * window of it actually starting, without hammering Jenkins between real
 * scans. */
const IDLE_RECONCILE_MS = 15_000;

/** States where nothing is actively in flight - safe to reconcile against
 * Jenkins, and where triggerBuild is allowed to proceed. */
const SETTLED_STATES = new Set(['idle', 'success', 'skipped', 'failed']);

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

/** Hitting the stall limit does not mean the build is actually dead - it
 * has since been observed live that a scanner stage (GitLeaks walking full
 * git history) can peg the host's CPU heavily enough that Jenkins itself
 * stops answering HTTP requests for the *entire* stall window, while the
 * build underneath keeps running and finishes successfully moments later.
 * So a stall only flips the UI into a non-fatal warning (`stalled: true`,
 * state stays 'running') and polling continues - it self-clears the moment
 * new console output shows up. Only after this much longer ceiling with
 * still nothing does it give up for real; kept just under the pipeline's
 * own 45-minute `timeout()` so a genuinely dead build is not tracked
 * forever. */
const HARD_GIVEUP_MS = 40 * 60_000;

export interface PipelineStatus {
  /** 'skipped' is deliberately its own state, not folded into 'failed' -
   * NOT_BUILT is the Jenkinsfile's own intentional result for "no new
   * commits since the last scan, nothing to do" (Checkout stage), not an
   * error. Confirmed live: before this distinction existed, a routine
   * auto-skip showed on the dashboard as a red "The last scan attempt
   * failed" banner, indistinguishable from Jenkins genuinely being broken. */
  state: 'idle' | 'queued' | 'running' | 'success' | 'skipped' | 'failed';
  buildNumber?: number;
  buildUrl?: string;
  startedAt?: string;
  finishedAt?: string;
  error?: string;
  /** Most recent line of real output from the build - not just "running",
   * but what it is actually doing right now (e.g. which scanner, which
   * file). Only present while a build is actively running. */
  currentActivity?: string;
  /** No new console output for RUNNING_STALL_LIMIT_MS, but not yet given up
   * - the build may well still be alive and just slow to respond (e.g. a
   * CPU-heavy scanner stage starving Jenkins of the ability to answer HTTP
   * requests). state stays 'running'; this clears itself the moment new
   * output arrives, so the UI can show a warning without abandoning the
   * build the way a hard 'failed' would. */
  stalled?: boolean;
  /** Which declared Jenkinsfile stage ("SAST - SonarQube", "Secrets -
   * GitLeaks", ...) most recently started, parsed from the console's own
   * `[Pipeline] { (Stage Name)` markers. Lets the UI show which scanner is
   * actually running right now, not just a generic "Scanning...". */
  currentStage?: string;
  /** Every scanner that has produced output so far this run. The four
   * scanners run as parallel branches, so more than one is often genuinely
   * active at once - unlike currentStage (the single most recent line),
   * this is the right signal for "which chips should show as running". */
  activeStages?: string[];
}

@Injectable()
export class JenkinsService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(JenkinsService.name);
  private status: PipelineStatus = { state: 'idle' };
  private pollTimer?: ReturnType<typeof setInterval>;
  private idleReconcileTimer?: ReturnType<typeof setInterval>;

  /** The highest Jenkins build number this service has ever reported a
   * result for - see reconcileWithJenkins's "flew by" branch. `null` until
   * baselined at startup, specifically so that branch never mistakes
   * "haven't looked yet" for "build #0 was the last one seen" and reports
   * whatever Jenkins' last build happens to be the moment this service
   * boots, rather than only genuinely new ones from here on. */
  private lastReportedBuildNumber: number | null = null;

  /**
   * Tracking lives only in memory - a redeploy of this container (which
   * happens on every code change, including to this file) wipes it. Without
   * this, that looks identical to the dashboard silently losing track of a
   * build that is, from Jenkins' own point of view, running perfectly
   * normally: reproduced live when redeploying mid-build left the sidebar
   * frozen on "Scanning..." forever while Jenkins had already finished the
   * build with SUCCESS minutes earlier. On startup, ask Jenkins what its own
   * last build is actually doing and resume tracking it if it is still
   * running, instead of just assuming idle.
   */
  async onModuleInit(): Promise<void> {
    const attached = await this.reconcileWithJenkins();
    if (attached && this.status.state === 'running') {
      this.logger.log(`Resuming tracking of build #${this.status.buildNumber}, already running at startup`);
    }

    // Reconciling only here (and inside triggerBuild's own edge case)
    // misses every build this service did not itself kick off - confirmed
    // live: a cron-triggered build ran and finished entirely (skipped, in
    // that instance, but the same gap applies to a real scan) while the
    // dashboard sat showing "idle, last run #309" throughout, with nothing
    // telling a viewer that real Jenkins activity was happening or that
    // clicking "Run scan" right then would queue a redundant second build
    // behind it. Only reconciles while genuinely idle, so this never
    // fights triggerBuild's own faster (2s) queue poll once a build this
    // service *did* start is actually in flight.
    this.idleReconcileTimer = setInterval(() => {
      if (SETTLED_STATES.has(this.status.state)) {
        void this.reconcileWithJenkins().then((attached) => {
          if (!attached) void this.checkJenkinsQueue();
        });
      }
    }, IDLE_RECONCILE_MS);
  }

  onModuleDestroy(): void {
    if (this.idleReconcileTimer) clearInterval(this.idleReconcileTimer);
  }

  /**
   * Asks Jenkins directly whether its own last build is still running, and
   * if so, attaches this service's tracking to it. Shared by onModuleInit
   * (this container's own state was wiped by a redeploy) and by
   * triggerBuild's "Jenkins returned 200 but no Location header" case
   * (see the comment there) - both are really the same situation: this
   * service does not know what Jenkins is currently doing and needs to find
   * out, rather than assume idle or assume failure.
   *
   * Also catches a build that started AND finished entirely between two
   * idle-reconcile ticks - confirmed live: a routine auto-skip build
   * finishes in ~7s, well inside this timer's 15s interval, so "was it ever
   * seen building" (the check this used to stop at) missed most of them
   * outright - the dashboard just never showed a skip banner for that
   * cycle, with nothing wrong logged anywhere to suggest why. Comparing
   * build numbers instead of relying on catching it mid-flight is what
   * survives missing the live window - see lastReportedBuildNumber.
   */
  private async reconcileWithJenkins(): Promise<boolean> {
    try {
      const res = await this.fetchJenkins(`${JENKINS_URL}/job/${JOB_NAME}/lastBuild/api/json`);
      if (!res.ok) {
        await this.drain(res);
        return false;
      }
      const body = (await res.json()) as {
        building: boolean; number: number; url: string; timestamp: number;
        result?: string | null; duration?: number;
      };

      if (body.building) {
        const startedAt = new Date(body.timestamp).toISOString();
        const buildUrl = rebase(body.url);
        this.status = { state: 'running', startedAt, buildNumber: body.number, buildUrl };
        this.pollBuild(body.number, buildUrl, startedAt);
        return true;
      }

      // First call ever (service just started): baseline silently rather
      // than treating whatever Jenkins' last build already was as
      // something that "just happened" the moment this service booted.
      if (this.lastReportedBuildNumber === null) {
        this.lastReportedBuildNumber = body.number;
        return false;
      }

      if (body.number > this.lastReportedBuildNumber) {
        const startedAt = new Date(body.timestamp).toISOString();
        const finishedAt = new Date(body.timestamp + (body.duration ?? 0)).toISOString();
        this.status = {
          state: body.result === 'SUCCESS' ? 'success' : body.result === 'NOT_BUILT' ? 'skipped' : 'failed',
          startedAt,
          finishedAt,
          buildNumber: body.number,
          buildUrl: rebase(body.url),
          ...(body.result !== 'SUCCESS' && body.result !== 'NOT_BUILT'
            ? { error: `Build result: ${body.result ?? 'unknown'}` }
            : {}),
        };
        this.lastReportedBuildNumber = body.number;
        return true;
      }

      return false;
    } catch (err) {
      this.logger.warn(`Could not check Jenkins' last build: ${(err as Error).message}`);
      return false;
    }
  }

  /**
   * Checks Jenkins' own queue for a pending item belonging to this job -
   * the blind spot reconcileWithJenkins alone has. A build accepted into
   * the queue is not yet "lastBuild" (no build number exists until an
   * executor picks it up), so lastBuild.building stays pointed at
   * whatever finished before it. Confirmed live: triggered a build
   * directly against Jenkins, then called triggerBuild() a moment later -
   * before Jenkins had assigned it a build number - and it went ahead and
   * submitted a second, genuinely separate queue item instead of
   * attaching to the first. disableConcurrentBuilds() serialised them so
   * nothing broke outright, but two full scans ran back to back where one
   * request had been made, exactly the "why": "Build #N is already in
   * progress" pattern this project's history already knew Jenkins produces
   * when a request's parameters differ from an already-queued item's own
   * (so it cannot be merged into it the way an identical one would be).
   */
  private async checkJenkinsQueue(): Promise<boolean> {
    try {
      const res = await this.fetchJenkins(`${JENKINS_URL}/queue/api/json`);
      if (!res.ok) {
        await this.drain(res);
        return false;
      }
      const body = (await res.json()) as { items?: { id: number; task?: { name?: string } }[] };
      const existing = body.items?.find((item) => item.task?.name === JOB_NAME);
      if (!existing) return false;

      const startedAt = new Date().toISOString();
      this.status = { state: 'queued', startedAt };
      this.pollQueueThenBuild(`${JENKINS_URL}/queue/item/${existing.id}/`, startedAt);
      return true;
    } catch (err) {
      this.logger.warn(`Could not check Jenkins' queue: ${(err as Error).message}`);
      return false;
    }
  }

  private auth(): string {
    const id = process.env.JENKINS_ADMIN_ID ?? 'admin';
    const password = process.env.JENKINS_ADMIN_PASSWORD ?? 'admin';
    return 'Basic ' + Buffer.from(`${id}:${password}`).toString('base64');
  }

  /**
   * A dedicated undici Agent with keep-alive disabled, so no pooled socket
   * to Jenkins can ever accumulate staleness in the first place.
   *
   * The earlier attempt at this fix set a `Connection: close` *header* on
   * Node's global fetch and looked right at the time (confirmed live, twice,
   * that it stopped the "fetch failed" recurrence in the moment) - but that
   * only controls what gets sent on the wire, not whether undici's own
   * global dispatcher still pools and reuses the underlying socket
   * internally. It resurfaced later exactly the same way: every poll to
   * Jenkins failing with a generic "fetch failed" for 20+ minutes straight
   * while a brand-new process making the identical call succeeded
   * instantly - proof the connection-reuse problem, not just the header,
   * was still there. `dispatcher` is undici's actual mechanism for this,
   * not a header some server or client is free to ignore.
   */
  private readonly agent = new Agent({ keepAliveTimeout: 1, keepAliveMaxTimeout: 1 });

  private fetchJenkins(url: string, init: RequestInit = {}): Promise<Response> {
    return undiciFetch(url, {
      ...init,
      headers: { Authorization: this.auth(), ...init.headers },
      signal: AbortSignal.timeout(POLL_TIMEOUT_MS),
      dispatcher: this.agent,
    });
  }

  /**
   * A response whose body is never read is not actually released - it stays
   * pinned rather than being returned to the pool (or, with keep-alive
   * disabled, properly closed), because the stream is still "pending" from
   * the connection's point of view. Confirmed as the real cause of the
   * "fetch failed" recurrence after the dispatcher fix above did not stop
   * it: several call sites here discard a response on an early return
   * (`if (!res.ok) return`) without ever reading its body, and this process
   * makes a request every 2-3 seconds for its entire lifetime - hours of
   * that leaking one connection at a time explains exactly the observed
   * pattern (fine when freshly started, failing every single request after
   * running a while, while a brand-new process always succeeds instantly).
   */
  private async drain(res: Response): Promise<void> {
    try {
      await res.body?.cancel();
    } catch {
      // best-effort - the point is to not leave it unread, not to require success
    }
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

    // Claimed synchronously, before any `await`, so a second call arriving
    // while everything below is still in flight - including the
    // reconcile check just after this - is caught by the exact same guard
    // above a rapid double-click always was, rather than only once this
    // call finishes. Overwritten with the real build's own info below if
    // reconcileWithJenkins finds this run should attach to one instead.
    const startedAt = new Date().toISOString();
    this.status = { state: 'queued', startedAt };

    // Closes a real race, not just a theoretical one: the periodic
    // idle-reconcile poll only checks Jenkins every 15s, so a build that
    // started independently (cron, or Jenkins' own UI) moments before this
    // exact click can still be genuinely running in Jenkins while
    // `this.status` was stale idle/success/failed a moment ago - confirmed
    // live, "Run scan" clickable in that narrow window right after such a
    // build started, queuing a redundant second one behind it. One fresh
    // check here, synchronously as part of handling the click itself,
    // closes it regardless of how the background poll happens to be timed.
    if (await this.reconcileWithJenkins()) {
      return this.status;
    }
    // reconcileWithJenkins only sees a build that already has an executor
    // - this catches the narrower but real window where one is merely
    // queued (see checkJenkinsQueue's own comment).
    if (await this.checkJenkinsQueue()) {
      return this.status;
    }

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
        await this.drain(res);
        throw new Error(`Jenkins returned ${res.status} triggering the build`);
      }
      const queueUrl = res.headers.get('Location');
      await this.drain(res); // only the Location header is needed; the body is never read
      if (!queueUrl) {
        // Not necessarily a failure - confirmed live. Jenkins returns 200
        // with no Location (instead of 201 + Location) when this request
        // gets merged into an *existing* blocked queue item rather than
        // creating a new one, which happens routinely with
        // disableConcurrentBuilds() once both the cron poll and manual
        // "Run scan" clicks can land while a build is already running: the
        // queue item's own causes showed three TimerTrigger entries plus
        // one UserIdCause all merged into one, "why": "Build #44 is already
        // in progress". Reconcile with what Jenkins is actually doing
        // before assuming the trigger failed.
        const attached = await this.reconcileWithJenkins();
        if (attached) {
          return this.status;
        }
        throw new Error('Jenkins did not return a queue item location, and no build appears to be running to attach to');
      }
      this.pollQueueThenBuild(rebase(queueUrl), startedAt);
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
      if (!res.ok) {
        await this.drain(res);
        return null;
      }
      const cookie = res.headers.get('set-cookie');
      if (!cookie) {
        await this.drain(res);
        return null;
      }
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
        if (!res.ok) {
          await this.drain(res);
          return;
        }
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
          const buildUrl = rebase(body.executable.url);
          this.status = {
            state: 'running',
            startedAt,
            buildNumber: body.executable.number,
            buildUrl,
          };
          this.pollBuild(body.executable.number, buildUrl, startedAt);
        }
      } catch (err) {
        this.logger.warn(`Queue poll failed: ${(err as Error).message} | cause: ${describeCause(err)}`);
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
    let stallLoggedAt = 0;
    // GitLeaks/Trivy/Checkov run as parallel branches of one 'Scans' stage
    // (see the Jenkinsfile), so more than one can genuinely be active at
    // once - accumulated within that stage rather than replaced on every
    // poll, so a fast scanner (Checkov, a few seconds) is not silently
    // dropped from the list the moment a slower one produces the next line.
    // SonarQube, however, now runs afterward as its own dedicated stage
    // (Tier 3: decoupled from the blocking parallel batch so the dashboard
    // isn't stuck waiting on it) - its `[Pipeline] { (SAST - SonarQube)`
    // marker carries no "Branch: " prefix, unlike a parallel branch's, and
    // that distinction (see `solo` in allStagesWithPositions) is what tells
    // this loop the previous batch has finished and should be cleared, not
    // accumulated into. Without this, every scanner that ever ran this
    // build stays "active" forever once SonarQube's stage starts (confirmed
    // live: all four chips showed "scanning now" simultaneously long after
    // GitLeaks/Trivy/Checkov had actually finished).
    const activeStages = new Set<string>();

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
            const stage = latestStage(chunk);
            for (const marker of allStagesWithPositions(chunk)) {
              if (marker.solo) activeStages.clear();
              activeStages.add(marker.name);
            }
            this.status = {
              ...this.status,
              stalled: false,
              activeStages: [...activeStages],
              ...(activity ? { currentActivity: activity } : {}),
              ...(stage ? { currentStage: stage } : {}),
            };
          }

          if (!moreData) {
            // The console is done, but only the structured endpoint carries
            // the actual pass/fail result.
            const statusRes = await this.fetchJenkins(`${buildUrl}api/json`);
            let body: { result: string | null };
            if (statusRes.ok) {
              body = (await statusRes.json()) as { result: string | null };
            } else {
              await this.drain(statusRes);
              body = { result: null };
            }
            this.stopPolling();
            this.status = {
              state: body.result === 'SUCCESS' ? 'success' : body.result === 'NOT_BUILT' ? 'skipped' : 'failed',
              startedAt,
              finishedAt: new Date().toISOString(),
              buildNumber,
              buildUrl,
              ...(body.result !== 'SUCCESS' && body.result !== 'NOT_BUILT'
                ? { error: `Build result: ${body.result ?? 'unknown'}` }
                : {}),
            };
            // Keeps reconcileWithJenkins's "flew by" branch from re-reporting
            // a build this service already tracked and finished itself.
            this.lastReportedBuildNumber = buildNumber;
            return;
          }
        } else {
          await this.drain(res);
        }
      } catch (err) {
        this.logger.warn(`Build console poll failed: ${(err as Error).message} | cause: ${describeCause(err)}`);
      }

      const silentFor = Date.now() - lastProgressAt;

      if (silentFor >= HARD_GIVEUP_MS) {
        this.stopPolling();
        const minutes = Math.round(HARD_GIVEUP_MS / 60_000);
        this.status = {
          state: 'failed',
          startedAt,
          finishedAt: new Date().toISOString(),
          buildNumber,
          buildUrl,
          error: `No new output from the build for over ${minutes} minute(s) - giving up. The build itself may still be running; check ${buildUrl} directly.`,
        };
        this.logger.error(`Gave up on build #${buildNumber}: no new console output for ${minutes}+ minutes`);
        return;
      }

      if (silentFor >= RUNNING_STALL_LIMIT_MS) {
        // Non-fatal: keep polling in the background. A build can go silent
        // for this long simply because a CPU-heavy scanner stage (observed:
        // GitLeaks walking a large repo's full git history) is starving
        // Jenkins itself of the ability to answer HTTP requests, not
        // because the build has actually stopped.
        this.status = { ...this.status, stalled: true };
        if (Date.now() - stallLoggedAt >= RUNNING_STALL_LIMIT_MS) {
          stallLoggedAt = Date.now();
          const minutes = Math.round(silentFor / 60_000);
          this.logger.warn(`Build #${buildNumber} has been silent for ${minutes}+ minute(s) - still watching, not giving up yet`);
        }
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

/**
 * Rewrite a Jenkins-supplied absolute URL (the `Location` header from
 * triggering a build, or `executable.url`/`lastBuild.url` from its JSON
 * API) onto our own known-reachable JENKINS_URL, keeping only the path.
 *
 * This is the actual root cause of the "fetch failed" incidents that kept
 * recurring through several earlier fix attempts (a stale-connection
 * header, a dispatcher with keep-alive disabled, draining unread response
 * bodies - all real improvements, none of them the actual bug). Jenkins
 * builds these URLs from its own configured root URL
 * (`unclassified.location.url` in casc.yaml, here `http://localhost:8080/`
 * - correct only from the host browser's point of view), not from the
 * address a given caller used to reach it. The crumb fetch and the initial
 * trigger POST always used our own correct JENKINS_URL directly and so
 * always worked; every later poll trusted Jenkins' self-reported URL
 * instead and so was, once a build left the queue, permanently trying to
 * connect to the api container's own localhost - confirmed live via
 * `cause: Error: connect ECONNREFUSED 127.0.0.1:8080`, not any kind of
 * connection staleness.
 */
function rebase(jenkinsUrl: string): string {
  try {
    const path = new URL(jenkinsUrl).pathname;
    return `${JENKINS_URL}${path}`;
  } catch {
    return jenkinsUrl;
  }
}

/** undici's "fetch failed" is a generic wrapper - the actual reason (ECONNRESET,
 * ECONNREFUSED, a DNS failure, ...) lives on `.cause` and was never being
 * logged, which is why the repeated live incidents of this error could only
 * ever be theorized about, not diagnosed directly. */
function describeCause(err: unknown): string {
  const cause = (err as { cause?: unknown })?.cause;
  if (!cause) return 'none';
  if (cause instanceof Error) {
    const code = (cause as NodeJS.ErrnoException).code;
    return `${cause.name}: ${cause.message}${code ? ` (${code})` : ''}`;
  }
  return String(cause);
}

/** Jenkins embeds invisible metadata for its own web UI (hyperlinks on a
 * build's stage/step markers) directly in the raw console byte stream,
 * wrapped in an ANSI "conceal" escape sequence - invisible in a real
 * terminal or Jenkins' own UI (which strips it before rendering), but
 * confirmed live to leak through verbatim as literal garbage
 * (`[8mha://///4A1C/AEGgMlM2y2Nxw...`) when picked up as plain text the
 * way this poll does. `ha:` is ConsoleNote's own fixed preamble, unique
 * enough to not risk matching any real scanner/shell output. */
const JENKINS_CONSOLE_NOTE = /\x1b?\[8mha:\S*(\x1b?\[0?m)?/g;

/** Real ANSI CSI escape sequences (colour codes, cursor moves, ...) that a
 * scanner's own coloured output can legitimately contain - stripped so a
 * one-line UI display never shows raw control-code text. */
const ANSI_ESCAPE = /\x1b\[[0-9;]*[a-zA-Z]/g;

function cleanConsoleLine(line: string): string {
  return line.replace(JENKINS_CONSOLE_NOTE, '').replace(ANSI_ESCAPE, '').trim();
}

/** The last genuinely human-readable line of a console chunk, with
 * Jenkins' timestamp prefix (from the `timestamps()` pipeline option) and
 * any invisible-in-a-real-terminal control data stripped, trimmed to a
 * reasonable length for a one-line UI display. Scans backward rather than
 * only ever looking at the true last line, since that line is sometimes
 * nothing but one of Jenkins' own ConsoleNote blobs once cleaned - in
 * which case the most recent real line before it is what a viewer
 * actually wants to see. */
function latestLine(chunk: string): string | null {
  const lines = chunk.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    const withoutTimestamp = lines[i].replace(/^\[\d{4}-\d{2}-\d{2}T[\d:.]+Z]\s*/, '');
    const cleaned = cleanConsoleLine(withoutTimestamp);
    if (cleaned) {
      return cleaned.length > 160 ? `${cleaned.slice(0, 160)}…` : cleaned;
    }
  }
  return null;
}

/** Known scanner names, both as declarative stage markers and as parallel
 * branch labels - matched against so an unrelated bracketed prefix (a shell
 * command echoing "[foo]", say) is never mistaken for one. */
const KNOWN_STAGES = [
  'SAST - SonarQube', 'Secrets - GitLeaks', 'Container - Trivy',
  'IaC - Checkov', 'Cloud - AWS monitor',
];

/** The most recently active scanner in this chunk. Two console formats carry
 * this: a declarative `[Pipeline] { (Stage Name)` marker when it runs as its
 * own stage, and a `[Stage Name] ...` line prefix when it runs as a branch
 * of a `parallel()` step instead (Jenkins tags every line of concurrent
 * branch output this way, since several branches interleave in one log).
 * The four scanners run as parallel branches so their reports don't have to
 * wait on each other, so both forms need handling - the last match of
 * either wins. */
function latestStage(chunk: string): string | null {
  const all = allStagesWithPositions(chunk);
  return all.length ? all[all.length - 1].name : null;
}

/**
 * Every stage/branch marker touched anywhere in this chunk, in the order
 * they appeared, tagged with whether each is a `solo` (dedicated, sequential
 * stage - e.g. `[Pipeline] { (SAST - SonarQube)`) or parallel-branch marker
 * (`[Pipeline] { (Branch: Name)` or the `[Name] ...` line-prefix form). A
 * caller accumulating "currently active" scanners needs this distinction:
 * branch markers genuinely overlap and should pile up together, but a solo
 * marker means a brand-new sequential stage has started and whatever ran
 * before it is done.
 */
function allStagesWithPositions(chunk: string): { index: number; name: string; solo: boolean }[] {
  // Jenkins' parallel() step emits its own `[Pipeline] { (Branch: Name) }`
  // marker for each branch alongside the `[Name] ...` line-prefix form -
  // confirmed live (`"currentStage":"Branch: IaC - Checkov"`). Stripping the
  // prefix here, not at every call site, is what lets a plain scanner name
  // match KNOWN_STAGES/STAGE_TO_SOURCE regardless of which of the two forms
  // produced it.
  // Anchored to end-of-line with a greedy `.+` (not `[^)]+`) specifically so
  // a stage name that itself contains parens - e.g. "SAST - SonarQube
  // (async)" - captures in full up to its own last `)`, rather than
  // stopping at the *first* `)` and losing everything from "(async" on.
  // Confirmed live: the naive `[^)]+` version silently truncated that exact
  // stage name, which meant it could never match STAGE_TO_SOURCE/
  // KNOWN_STAGES downstream no matter how those were spelled.
  const stageMarkers = [...chunk.matchAll(/^\[Pipeline]\s*\{\s*\((.+)\)$/gm)]
    .map((m) => {
      const raw = m[1];
      const isBranch = /^Branch:\s*/.test(raw);
      return { index: m.index ?? 0, name: raw.replace(/^Branch:\s*/, ''), solo: !isBranch };
    });
  const branchLines = [...chunk.matchAll(/^\[([^\]]+)]/gm)]
    .map((m) => ({ index: m.index ?? 0, name: m[1], solo: false }))
    .filter((m) => KNOWN_STAGES.includes(m.name));
  return [...stageMarkers, ...branchLines].sort((a, b) => a.index - b.index);
}
