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

  it('refuses to trigger a second build while one is already in flight', async () => {
    // No crumb issuer, trigger response never resolves within this test -
    // just needs triggerBuild() to have set state to "queued" first.
    fetchMock.mockImplementation(() => new Promise(() => {}));
    void service.triggerBuild(SETTINGS);
    await Promise.resolve(); // let the first triggerBuild's synchronous part run

    await expect(service.triggerBuild(SETTINGS)).rejects.toThrow('already in progress');
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
    fetchMock
      .mockResolvedValueOnce({ ok: false, status: 404 } as Response) // crumbIssuer 404s
      .mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ Location: 'http://jenkins:8080/queue/item/9/' }),
      } as Response);

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
        return { ok: true, headers: new Headers({ Location: 'http://jenkins:8080/queue/item/9/' }) };
      });

    const status = await service.triggerBuild(SETTINGS);
    expect(status.state).toBe('queued');
  });

  it('resolves queued -> running -> success as Jenkins reports it', async () => {
    fetchMock
      .mockResolvedValueOnce({ ok: false, status: 404 } as Response) // no crumb issuer
      .mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ Location: 'http://jenkins:8080/queue/item/9/' }),
      } as Response) // triggered
      .mockResolvedValueOnce(jsonResponse({ executable: { number: 7, url: 'http://jenkins:8080/job/threatweave-pipeline/7/' } })) // queue resolves
      .mockResolvedValueOnce(jsonResponse({ building: false, result: 'SUCCESS' })); // build finished

    await service.triggerBuild(SETTINGS);
    expect(service.getStatus().state).toBe('queued');

    await jest.advanceTimersByTimeAsync(2000); // queue poll tick
    expect(service.getStatus().state).toBe('running');
    expect(service.getStatus().buildNumber).toBe(7);

    await jest.advanceTimersByTimeAsync(3000); // build poll tick
    expect(service.getStatus().state).toBe('success');
  });

  it('reports failed with the build result when the pipeline fails', async () => {
    fetchMock
      .mockResolvedValueOnce({ ok: false, status: 404 } as Response)
      .mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ Location: 'http://jenkins:8080/queue/item/9/' }),
      } as Response)
      .mockResolvedValueOnce(jsonResponse({ executable: { number: 7, url: 'http://jenkins:8080/job/threatweave-pipeline/7/' } }))
      .mockResolvedValueOnce(jsonResponse({ building: false, result: 'FAILURE' }));

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
  it('gives up and reports a clear failure after losing contact with Jenkins for too long', async () => {
    fetchMock
      .mockResolvedValueOnce({ ok: false, status: 404 } as Response) // no crumb
      .mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ Location: 'http://jenkins:8080/queue/item/9/' }),
      } as Response) // triggered, now queued
      .mockRejectedValue(new Error('fetch failed')); // every poll after this fails

    await service.triggerBuild(SETTINGS);
    expect(service.getStatus().state).toBe('queued');

    await jest.advanceTimersByTimeAsync(95_000); // past the stall limit

    const status = service.getStatus();
    expect(status.state).toBe('failed');
    expect(status.error).toContain('Lost contact with Jenkins');
  });

  it('does not give up while polling is merely slow, only once truly stalled', async () => {
    fetchMock
      .mockResolvedValueOnce({ ok: false, status: 404 } as Response)
      .mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ Location: 'http://jenkins:8080/queue/item/9/' }),
      } as Response)
      // Two failures, then a real response - simulates a brief blip that
      // recovers, not a genuine stall.
      .mockRejectedValueOnce(new Error('fetch failed'))
      .mockRejectedValueOnce(new Error('fetch failed'))
      .mockResolvedValueOnce(jsonResponse({ executable: { number: 7, url: 'http://jenkins:8080/job/threatweave-pipeline/7/' } }));

    await service.triggerBuild(SETTINGS);
    await jest.advanceTimersByTimeAsync(6_000); // three queue-poll ticks: fail, fail, succeed

    expect(service.getStatus().state).toBe('running');
    expect(service.getStatus().buildNumber).toBe(7);
  });

  it('includes an AbortSignal on every request so one hung connection cannot hang forever', async () => {
    fetchMock.mockRejectedValue(new Error('irrelevant'));

    await service.triggerBuild(SETTINGS);

    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('describes a request timeout in plain language rather than a raw exception message', async () => {
    const timeout = new Error('The operation was aborted due to timeout');
    timeout.name = 'TimeoutError';
    fetchMock.mockRejectedValue(timeout);

    const status = await service.triggerBuild(SETTINGS);

    expect(status.error).toContain('did not respond within');
  });
});
