import { JenkinsService } from './jenkins.service';
import { PipelineSettings } from '../settings/settings.service';

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
    fetchMock = jest.fn();
    global.fetch = fetchMock as never;
  });

  afterEach(() => {
    jest.clearAllTimers();
    jest.useRealTimers();
  });

  it('reports idle before any build is triggered', () => {
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

  it('gives up on a running build only after genuinely no new console output for the full stall window', async () => {
    fetchMock
      .mockResolvedValueOnce(NO_CRUMB)
      .mockResolvedValueOnce(TRIGGERED)
      .mockResolvedValueOnce(QUEUE_RESOLVED)
      // Every console poll after this "succeeds" but returns nothing new -
      // simulates a build that is truly stuck, not just slow to answer.
      .mockResolvedValue(textResponse('', { moreData: true, nextOffset: 0 }));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(2000); // -> running

    await jest.advanceTimersByTimeAsync(5 * 60_000); // past the 5-minute running stall limit

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

  // ---- Regression: confirmed live, twice. This long-running process's
  // pooled connection to Jenkins went stale (generic "fetch failed" on every
  // subsequent request) while a brand-new process making the identical call
  // succeeded immediately - the timeout/stall-detection above only made that
  // visible, it didn't stop it recurring. Never reusing a connection is the
  // actual fix.
  it('never reuses a pooled connection, so a stale one cannot accumulate', async () => {
    fetchMock.mockRejectedValue(new Error('irrelevant'));

    await service.triggerBuild(SETTINGS);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)['Connection']).toBe('close');
  });

  it('describes a request timeout in plain language rather than a raw exception message', async () => {
    const timeout = new Error('The operation was aborted due to timeout');
    timeout.name = 'TimeoutError';
    fetchMock.mockRejectedValue(timeout);

    const status = await service.triggerBuild(SETTINGS);

    expect(status.error).toContain('did not respond within');
  });
});
