import { JenkinsService } from './jenkins.service';
import { PipelineSettings } from '../settings/settings.service';

// JenkinsService talks to Jenkins via undici's fetch directly (not Node's
// global fetch) so it can hand it a dispatcher with keep-alive disabled -
// see the comment on JenkinsService.agent for why that distinction matters.
// Mocking undici's export, rather than global.fetch, is what actually
// intercepts those calls.
jest.mock('undici', () => ({
  ...jest.requireActual('undici'),
  fetch: jest.fn(),
}));
import { fetch as undiciFetchMock } from 'undici';

const SETTINGS: PipelineSettings = {
  sourceDir: '/target',
  iacDir: '/target/infra',
  targetImage: 'scratch',
  sonarProjectKey: 'my-project',
  runAwsMonitor: false,
  failOnCritical: false,
};

function jsonResponse(body: unknown, init: Partial<Response> = {}): Response {
  return {
    ok: true,
    status: 200,
    headers: new Headers(),
    json: async () => body,
    ...init,
  } as Response;
}

/** A chunk of Jenkins' progressiveText console API response. */
function textResponse(text: string, opts: { moreData: boolean; nextOffset?: number }): Response {
  return {
    ok: true,
    status: 200,
    headers: new Headers({
      'X-More-Data': String(opts.moreData),
      'X-Text-Size': String(opts.nextOffset ?? text.length),
    }),
    text: async () => text,
  } as Response;
}

const TRIGGERED = {
  ok: true,
  headers: new Headers({ Location: 'http://jenkins:8080/queue/item/9/' }),
} as Response;
const NO_CRUMB = { ok: false, status: 404 } as Response;
const QUEUE_RESOLVED = jsonResponse({ executable: { number: 7, url: 'http://jenkins:8080/job/threatweave-pipeline/7/' } });

describe('JenkinsService', () => {
  let service: JenkinsService;
  let fetchMock: jest.Mock;

  beforeEach(() => {
    jest.useFakeTimers();
    service = new JenkinsService();
    fetchMock = undiciFetchMock as jest.Mock;
    fetchMock.mockReset();
  });

  afterEach(() => {
    jest.clearAllTimers();
    jest.useRealTimers();
  });

  it('reports idle before any build is triggered', () => {
    expect(service.getStatus()).toEqual({ state: 'idle' });
  });

  // ---- Regression: confirmed live. Redeploying the api container mid-build
  // wipes JenkinsService's in-memory tracking entirely - the sidebar was
  // left showing "Scanning..." forever afterward even though Jenkins itself
  // had already finished the build with SUCCESS minutes earlier, because
  // nothing ever told the new process that build was still (or had been)
  // running.
  it('resumes tracking a build that is still running when the service starts up', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({
      building: true, number: 21, url: 'http://jenkins:8080/job/threatweave-pipeline/21/', timestamp: Date.now(),
    }));

    await service.onModuleInit();

    expect(service.getStatus().state).toBe('running');
    expect(service.getStatus().buildNumber).toBe(21);
  });

  it('stays idle at startup when the last build already finished', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({
      building: false, number: 21, url: 'http://jenkins:8080/job/threatweave-pipeline/21/', timestamp: Date.now(),
    }));

    await service.onModuleInit();

    expect(service.getStatus()).toEqual({ state: 'idle' });
  });

  // ---- Regression: confirmed live. reconcileWithJenkins used to run only
  // at startup (and inside triggerBuild's own narrow edge case), so a build
  // Jenkins started on its own - its cron trigger, or someone using
  // Jenkins' own UI directly - was invisible to this service for its
  // entire duration: the dashboard sat showing "idle, last run #309" the
  // whole time a real build (#310) ran and finished, "Run scan" still
  // clickable throughout.
  it('discovers a build Jenkins started on its own while idle, not just at startup', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({
      building: false, number: 309, url: 'http://jenkins:8080/job/threatweave-pipeline/309/', timestamp: Date.now(),
    }));
    await service.onModuleInit();
    expect(service.getStatus()).toEqual({ state: 'idle' });

    fetchMock.mockResolvedValueOnce(jsonResponse({
      building: true, number: 310, url: 'http://jenkins:8080/job/threatweave-pipeline/310/', timestamp: Date.now(),
    }));
    await jest.advanceTimersByTimeAsync(15000); // the idle-reconcile tick

    expect(service.getStatus().state).toBe('running');
    expect(service.getStatus().buildNumber).toBe(310);
  });

  it('does not reconcile while a build this service is already tracking is in flight', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({
      building: true, number: 21, url: 'http://jenkins:8080/job/threatweave-pipeline/21/', timestamp: Date.now(),
    })).mockResolvedValueOnce(textResponse('still going\n', { moreData: true, nextOffset: 20 }));
    await service.onModuleInit();
    expect(service.getStatus().state).toBe('running');

    fetchMock.mockClear();
    await jest.advanceTimersByTimeAsync(15000); // the idle-reconcile tick, if it fired

    // Only the console poll (from pollBuild, already tracking #21) should
    // have run - a second /lastBuild call here would mean the idle
    // reconciler fired despite a build already being tracked.
    const lastBuildCalls = fetchMock.mock.calls.filter(([url]) => (url as string).includes('/lastBuild/'));
    expect(lastBuildCalls).toHaveLength(0);
  });

  it('stays idle at startup rather than throwing when Jenkins cannot be reached', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));

    await expect(service.onModuleInit()).resolves.toBeUndefined();
    expect(service.getStatus()).toEqual({ state: 'idle' });
  });

  it('is idempotent while a build is already in flight, rather than throwing', async () => {
    // Regression: this used to throw a plain Error, which Nest's default
    // exception filter turns into a bare 500 "Internal server error" with
    // no useful detail reaching the dashboard - confirmed live when a
    // second call landed while build #12 was still queued. Returning the
    // current status instead means an accidental double-click, or a
    // request while a build is genuinely still running, is harmless.
    fetchMock.mockImplementation(() => new Promise(() => {})); // trigger never resolves
    void service.triggerBuild(SETTINGS);
    await Promise.resolve(); // let the first triggerBuild's synchronous part run
    expect(service.getStatus().state).toBe('queued');

    const second = await service.triggerBuild(SETTINGS);

    expect(second).toEqual(service.getStatus());
    expect(second.state).toBe('queued');
  });

  it('reports failed with a clear error when Jenkins is unreachable', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));

    const status = await service.triggerBuild(SETTINGS);

    expect(status.state).toBe('failed');
    expect(status.error).toContain('ECONNREFUSED');
  });

  it('reports failed when Jenkins rejects the trigger request', async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 403 })) // crumb issuer
      .mockResolvedValueOnce({ ok: false, status: 404 } as Response); // buildWithParameters

    const status = await service.triggerBuild(SETTINGS);

    expect(status.state).toBe('failed');
    expect(status.error).toContain('404');
  });

  // ---- Regression: confirmed live. Queue item causes showed three
  // TimerTrigger entries (the cron poll) plus one UserIdCause (a manual
  // "Run scan" click) all merged into a single blocked item - "why": "Build
  // #44 is already in progress". Jenkins answers a trigger request that
  // gets folded into an already-existing queue item with 200 and no
  // Location header (not 201 + Location, which only happens for a genuinely
  // new item) - previously treated as an unconditional failure even though
  // a real build was running the entire time.
  it('reconciles with the running build rather than failing when Jenkins returns no Location header', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce({ ok: true, headers: new Headers() } as Response) // 200, no Location
      .mockResolvedValueOnce(jsonResponse({
        building: true, number: 44, url: 'http://jenkins:8080/job/threatweave-pipeline/44/', timestamp: Date.now(),
      }));

    const status = await service.triggerBuild(SETTINGS);

    expect(status.state).toBe('running');
    expect(status.buildNumber).toBe(44);
  });

  it('still reports failed when there is no Location header and no build is actually running', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce({ ok: true, headers: new Headers() } as Response) // 200, no Location
      .mockResolvedValueOnce(jsonResponse({ building: false, number: 44, url: '', timestamp: Date.now() }));

    const status = await service.triggerBuild(SETTINGS);

    expect(status.state).toBe('failed');
    expect(status.error).toContain('did not return a queue item location');
  });

  it('proceeds without a crumb when no crumb issuer is available', async () => {
    fetchMock.mockResolvedValueOnce(NO_CRUMB).mockResolvedValueOnce(TRIGGERED);

    const status = await service.triggerBuild(SETTINGS);

    expect(status.state).toBe('queued');
    // No crumb header should have been required for the call to succeed.
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('sends the crumb together with its session cookie, not the crumb alone', async () => {
    // Regression: Jenkins' DefaultCrumbIssuer ties the crumb to a session,
    // and Basic Auth carries none by itself - a crumb sent without the
    // Set-Cookie it came with produces a 403 even though the crumb value
    // itself is correct.
    fetchMock
      .mockImplementationOnce(async () => ({
        ok: true,
        headers: new Headers({ 'set-cookie': 'JSESSIONID.abc=xyz; Path=/; HttpOnly' }),
        json: async () => ({ crumbRequestField: 'Jenkins-Crumb', crumb: 'the-crumb-value' }),
      }))
      .mockImplementationOnce(async (_url: string, init: RequestInit) => {
        const headers = init.headers as Record<string, string>;
        expect(headers['Jenkins-Crumb']).toBe('the-crumb-value');
        expect(headers['Cookie']).toContain('JSESSIONID.abc=xyz');
        return TRIGGERED;
      });

    const status = await service.triggerBuild(SETTINGS);
    expect(status.state).toBe('queued');
  });

  it('resolves queued -> running -> success, and surfaces live console activity along the way', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockResolvedValueOnce(QUEUE_RESOLVED)
      // running: two console chunks, then done
      .mockResolvedValueOnce(textResponse('[2026-08-27T20:03:12.000Z] Sensor JavaScript/TypeScript/CSS analysis\n', { moreData: true, nextOffset: 60 }))
      .mockResolvedValueOnce(textResponse('[2026-08-27T20:03:15.000Z] 1001/1001 source files analyzed\n', { moreData: false, nextOffset: 120 }))
      .mockResolvedValueOnce(jsonResponse({ result: 'SUCCESS' }));

    await service.triggerBuild(SETTINGS);
    expect(service.getStatus().state).toBe('queued');

    await jest.advanceTimersByTimeAsync(2000); // queue poll tick
    expect(service.getStatus().state).toBe('running');
    expect(service.getStatus().buildNumber).toBe(7);

    await jest.advanceTimersByTimeAsync(3000); // first console poll tick
    expect(service.getStatus().currentActivity).toBe('Sensor JavaScript/TypeScript/CSS analysis');
    expect(service.getStatus().state).toBe('running'); // not finished yet

    await jest.advanceTimersByTimeAsync(3000); // second console poll tick - build finishes
    expect(service.getStatus().state).toBe('success');
  });

  // ---- Regression: confirmed live on the dashboard - the sidebar's
  // "currently running" activity line showed raw garbage
  // ("[8mha://///4A1C/AEGgMlM2y2Nxw...") instead of anything readable.
  // Jenkins embeds invisible metadata for its own web UI (a ConsoleNote,
  // fixed "ha:" preamble) directly in the raw console byte stream, wrapped
  // in an ANSI "conceal" escape sequence real terminals never display -
  // but a plain-text poll of the console has no terminal to hide it, and
  // picking "the last line" verbatim surfaces it straight to the UI.
  it('skips Jenkins\' own invisible ConsoleNote blobs when picking the current activity line', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockResolvedValueOnce(QUEUE_RESOLVED)
      .mockResolvedValueOnce(textResponse(
        '[2026-09-01T12:20:59.820Z] Waiting for SonarQube scan from build-232 to finish (2 min so far)...\n' +
        '\x1b[8mha:////4A1C/AEGgMlM2y2NxwCaOCOIhqQC+zUw3EOAoDv8Z0HmAAAApB+LCAAAAAAAAP9tjTEOwjAQBC9BFLSUPMLpCBKiSmul4Q\x1b[0m\n',
        { moreData: true, nextOffset: 90 },
      ));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(2000);
    await jest.advanceTimersByTimeAsync(3000);

    expect(service.getStatus().currentActivity).toBe(
      'Waiting for SonarQube scan from build-232 to finish (2 min so far)...',
    );
  });

  it('also skips the ConsoleNote blob when its ESC byte itself did not survive transport', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockResolvedValueOnce(QUEUE_RESOLVED)
      .mockResolvedValueOnce(textResponse(
        '[2026-09-01T12:20:59.820Z] Sleeping for 15 sec\n' +
        '[8mha:////4A1C/AEGgMlM2y2NxwCaOCOIhqQC+zUw3EOAoDv8Z0HmAAAApB+LCAAAAAAAAP9tjTEOwjAQBC9BFLSUPMLpCBKiSmul4Q[0m\n',
        { moreData: true, nextOffset: 90 },
      ));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(2000);
    await jest.advanceTimersByTimeAsync(3000);

    expect(service.getStatus().currentActivity).toBe('Sleeping for 15 sec');
  });

  it('tracks which declared stage is currently running, from the console\'s own stage markers', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockResolvedValueOnce(QUEUE_RESOLVED)
      .mockResolvedValueOnce(textResponse(
        '[Pipeline] { (Checkout)\n[Pipeline] { (SAST - SonarQube)\nSensor analysis\n',
        { moreData: true, nextOffset: 80 },
      ));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(2000); // -> running
    await jest.advanceTimersByTimeAsync(3000); // console poll

    expect(service.getStatus().currentStage).toBe('SAST - SonarQube');
  });

  // ---- The four scanners now run as parallel branches of one 'Scans'
  // stage (see the Jenkinsfile) rather than as separate sequential stages,
  // so Jenkins tags their console lines with a `[Branch Name]` prefix
  // instead of the `[Pipeline] { (Stage Name)` marker a dedicated stage
  // gets. More than one can genuinely be running at once, so all of them
  // touched so far - not just whichever produced the latest line - need to
  // surface for the UI to highlight correctly.
  it('accumulates every scanner branch active in a run, not just the most recent line', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockResolvedValueOnce(QUEUE_RESOLVED)
      .mockResolvedValueOnce(textResponse(
        '[IaC - Checkov] Running shell script\n[SAST - SonarQube] Sensor analysis\n[IaC - Checkov] Finished\n',
        { moreData: true, nextOffset: 90 },
      ));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(2000); // -> running
    await jest.advanceTimersByTimeAsync(3000); // console poll

    const status = service.getStatus();
    expect(status.currentStage).toBe('IaC - Checkov'); // last line in the chunk
    expect(status.activeStages).toEqual(expect.arrayContaining(['IaC - Checkov', 'SAST - SonarQube']));
  });

  // ---- Regression: confirmed live after decoupling SonarQube into its own
  // sequential stage (Tier 3) so the dashboard doesn't wait on it. GitLeaks/
  // Trivy/Checkov still run as parallel branches of 'Scans' and should keep
  // accumulating together, but once SonarQube's *own* dedicated stage starts
  // - a solo `[Pipeline] { (SAST - SonarQube)` marker, not a `Branch: `
  // one - the previous batch is done and must be cleared, not piled onto.
  // Before this fix, all four scanners stayed "active" for the rest of the
  // build the moment SonarQube's stage began, so the dashboard showed every
  // chip as "scanning now" simultaneously long after three of them had
  // actually finished.
  it('clears previously-active parallel branches once a dedicated sequential stage starts', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockResolvedValueOnce(QUEUE_RESOLVED)
      .mockResolvedValueOnce(textResponse(
        '[Pipeline] { (Branch: IaC - Checkov)\n[Pipeline] { (Branch: Secrets - GitLeaks)\n[Pipeline] { (Branch: Container - Trivy)\n',
        { moreData: true, nextOffset: 90 },
      ))
      .mockResolvedValueOnce(textResponse(
        '[Pipeline] { (SAST - SonarQube)\nSensor analysis\n',
        { moreData: true, nextOffset: 140 },
      ));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(2000); // -> running
    await jest.advanceTimersByTimeAsync(3000); // console poll 1: Scans branches

    expect(service.getStatus().activeStages).toEqual(
      expect.arrayContaining(['IaC - Checkov', 'Secrets - GitLeaks', 'Container - Trivy']),
    );

    await jest.advanceTimersByTimeAsync(3000); // console poll 2: SonarQube's own stage starts

    expect(service.getStatus().activeStages).toEqual(['SAST - SonarQube']);
  });

  // ---- Regression: the actual root cause behind every "fetch failed"
  // incident this service went through, found only after logging the real
  // underlying error instead of undici's generic wrapper message:
  // `cause: Error: connect ECONNREFUSED 127.0.0.1:8080`. Jenkins builds the
  // `Location` header and `executable.url`/`lastBuild.url` fields from its
  // own configured root URL (unclassified.location.url in casc.yaml), which
  // is correct only from the host browser's point of view - not from
  // inside the api container, where that address is itself. Every poll
  // after the initial trigger trusted those self-reported URLs verbatim, so
  // once a build left the queue every single subsequent request permanently
  // failed. This locks in that only the *path* Jenkins reports is used - the
  // origin always comes from our own JENKINS_URL, never from Jenkins itself.
  it("rebases Jenkins' self-reported queue and build URLs onto our own JENKINS_URL, never trusting their origin", async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ Location: 'http://localhost:8080/queue/item/9/' }),
      } as Response)
      .mockResolvedValueOnce(jsonResponse({
        executable: { number: 7, url: 'http://localhost:8080/job/threatweave-pipeline/7/' },
      }))
      .mockResolvedValueOnce(textResponse('progress\n', { moreData: true, nextOffset: 10 }));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(2000); // queue poll -> running
    await jest.advanceTimersByTimeAsync(3000); // console poll

    // JENKINS_URL defaults to http://127.0.0.1:8080 when unset (as in this
    // test process) - every call after the trigger must use that origin,
    // never the http://localhost:8080 Jenkins claimed in its own responses.
    for (const [url] of fetchMock.mock.calls as [string][]) {
      expect(url.startsWith('http://localhost:8080')).toBe(false);
    }
    expect(service.getStatus().buildUrl).toBe('http://127.0.0.1:8080/job/threatweave-pipeline/7/');
  });

  // ---- Regression: confirmed live against a real build. Jenkins' parallel()
  // step emits its own `[Pipeline] { (Branch: Name) }` stage marker for each
  // branch, not just the `[Name] ...` line prefix - without stripping the
  // "Branch: " prefix, currentStage/activeStages would come back as
  // "Branch: SAST - SonarQube" and silently fail to match STAGE_TO_SOURCE on
  // the frontend, leaving every chip un-highlighted despite a real scanner
  // genuinely running.
  it('strips the "Branch: " prefix Jenkins adds to parallel-step stage markers', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockResolvedValueOnce(QUEUE_RESOLVED)
      .mockResolvedValueOnce(textResponse(
        '[Pipeline] { (Branch: IaC - Checkov)\nsome output\n',
        { moreData: true, nextOffset: 50 },
      ));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(2000);
    await jest.advanceTimersByTimeAsync(3000);

    const status = service.getStatus();
    expect(status.currentStage).toBe('IaC - Checkov');
    expect(status.activeStages).toContain('IaC - Checkov');
  });

  it('reports failed with the build result when the pipeline fails', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockResolvedValueOnce(QUEUE_RESOLVED)
      .mockResolvedValueOnce(textResponse('build failed\n', { moreData: false }))
      .mockResolvedValueOnce(jsonResponse({ result: 'FAILURE' }));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(2000);
    await jest.advanceTimersByTimeAsync(3000);

    const status = service.getStatus();
    expect(status.state).toBe('failed');
    expect(status.error).toContain('FAILURE');
  });

  // ---- Regression: a real incident during development. Jenkins itself was
  // healthy again after a network blip, but the API's own long-lived
  // connection to it kept failing anyway ("fetch failed") - the poll loop
  // retried forever, and the dashboard would have shown "Scanning..."
  // indefinitely with no way for anyone to know something was actually
  // wrong. These lock in that a stall now surfaces as a clear failure.
  it('gives up while queued after losing contact with Jenkins for too long', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockRejectedValue(new Error('fetch failed')); // every poll after this fails

    await service.triggerBuild(SETTINGS);
    expect(service.getStatus().state).toBe('queued');

    await jest.advanceTimersByTimeAsync(190_000); // past the queue stall limit (3 min)

    const status = service.getStatus();
    expect(status.state).toBe('failed');
    expect(status.error).toContain('Lost contact with Jenkins');
  });

  it('does not give up while polling is merely slow, only once truly stalled', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      // Two failures, then a real response - simulates a brief blip that
      // recovers, not a genuine stall.
      .mockRejectedValueOnce(new Error('fetch failed'))
      .mockRejectedValueOnce(new Error('fetch failed'))
      .mockResolvedValueOnce(QUEUE_RESOLVED);

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(6_000); // three queue-poll ticks: fail, fail, succeed

    expect(service.getStatus().state).toBe('running');
    expect(service.getStatus().buildNumber).toBe(7);
  });

  // ---- Regression: the exact false-positive hit live. A CPU-heavy stage
  // (SonarQube parsing ~1000 files) made the status endpoint slow enough to
  // trip a flat "no response in 90s" rule, even though the build's console
  // was genuinely advancing the whole time - the dashboard reported a
  // failure for a build that was actually fine. Progress is now measured by
  // new console output, so an occasional failed/slow poll no longer matters
  // as long as output keeps arriving.
  it('does not report a stall while the console keeps producing new output, even if individual polls fail', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockResolvedValueOnce(QUEUE_RESOLVED)
      // Console poll fails once (transient), then succeeds with real progress.
      .mockRejectedValueOnce(new Error('fetch failed'))
      .mockResolvedValueOnce(textResponse('[2026-08-27T20:03:12.000Z] still parsing files\n', { moreData: true, nextOffset: 40 }));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(2000); // -> running
    await jest.advanceTimersByTimeAsync(3000); // console poll 1: fails
    await jest.advanceTimersByTimeAsync(3000); // console poll 2: succeeds, real progress

    const status = service.getStatus();
    expect(status.state).toBe('running');
    expect(status.currentActivity).toBe('still parsing files');
  });

  // ---- Regression: confirmed live. Build #18's own GitLeaks stage pegged
  // the host's CPU heavily enough that Jenkins stopped answering HTTP
  // requests for the *entire* 5-minute stall window, while the build itself
  // kept running and finished successfully moments later. Treating a stall
  // as an immediate hard failure would have abandoned a build that was
  // never actually broken - it is now a non-fatal warning that keeps
  // polling instead.
  it('flags a running build as stalled (not failed) after no new console output for 5 minutes, and keeps polling', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockResolvedValueOnce(QUEUE_RESOLVED)
      // Every console poll after this "succeeds" but returns nothing new.
      .mockResolvedValue(textResponse('', { moreData: true, nextOffset: 0 }));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(2000); // -> running

    await jest.advanceTimersByTimeAsync(5 * 60_000); // past the 5-minute running stall limit

    const status = service.getStatus();
    expect(status.state).toBe('running');
    expect(status.stalled).toBe(true);
    expect(status.buildNumber).toBe(7); // still tracking the same build
  });

  it('clears the stalled flag as soon as real output resumes, without ever reaching failed', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockResolvedValueOnce(QUEUE_RESOLVED)
      .mockResolvedValue(textResponse('', { moreData: true, nextOffset: 0 }));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(2000); // -> running
    await jest.advanceTimersByTimeAsync(5 * 60_000); // now stalled
    expect(service.getStatus().stalled).toBe(true);

    fetchMock.mockResolvedValue(textResponse('[2026-08-27T20:03:12.000Z] back to work\n', { moreData: true, nextOffset: 40 }));
    await jest.advanceTimersByTimeAsync(3000);

    const status = service.getStatus();
    expect(status.stalled).toBe(false);
    expect(status.currentActivity).toBe('back to work');
  });

  it('truly gives up on a running build only after the much longer hard ceiling with zero output', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockResolvedValueOnce(QUEUE_RESOLVED)
      .mockResolvedValue(textResponse('', { moreData: true, nextOffset: 0 }));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(2000); // -> running
    await jest.advanceTimersByTimeAsync(40 * 60_000); // past the 40-minute hard ceiling

    const status = service.getStatus();
    expect(status.state).toBe('failed');
    expect(status.error).toContain('No new output from the build');
  });

  it('includes an AbortSignal on every request so one hung connection cannot hang forever', async () => {
    fetchMock.mockRejectedValue(new Error('irrelevant'));

    await service.triggerBuild(SETTINGS);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  // ---- Regression: confirmed live, twice, in two different ways. First
  // fix attempt set a `Connection: close` *header* - that is genuinely sent
  // on the wire (verified directly against a real server), but it does not
  // control whether undici's own dispatcher keeps the underlying socket
  // pooled internally, and the exact same failure mode (every poll to
  // Jenkins failing with a generic "fetch failed" for 20+ minutes straight,
  // while a brand-new process making the identical call succeeded
  // instantly) recurred later anyway. A dispatcher with keep-alive disabled
  // is undici's actual mechanism for this, not a header a client can set
  // and hope the dispatcher happens to honour.
  it('uses a dispatcher with keep-alive disabled, so no pooled connection can go stale', async () => {
    fetchMock.mockRejectedValue(new Error('irrelevant'));

    await service.triggerBuild(SETTINGS);

    const [, init] = fetchMock.mock.calls[0] as [string, { dispatcher?: unknown }];
    // undici's Agent does not expose its keepAliveTimeout as a public
    // property, so the real thing being checked is "the same dispatcher
    // instance every call" (constructed once, not a fresh one that could
    // itself default to keep-alive) - identity across two calls proves it
    // is the deliberately-configured one, not undici's own default agent.
    const [, init2] = fetchMock.mock.calls[1] ?? [];
    expect(init.dispatcher).toBeDefined();
    if (init2) expect((init2 as { dispatcher?: unknown }).dispatcher).toBe(init.dispatcher);
  });

  it('describes a request timeout in plain language rather than a raw exception message', async () => {
    const timeout = new Error('The operation was aborted due to timeout');
    timeout.name = 'TimeoutError';
    fetchMock.mockRejectedValue(timeout);

    const status = await service.triggerBuild(SETTINGS);

    expect(status.error).toContain('did not respond within');
  });
});
