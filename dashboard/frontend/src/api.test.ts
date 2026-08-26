import { describe, it, expect, vi, afterEach } from 'vitest';
import { api } from './api';

function mockFetchOnce(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
}

describe('api', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('getFindings calls GET /api/findings and returns the parsed body', async () => {
    const payload = { run_id: 'run-1', health_score: 15 };
    const fetchMock = mockFetchOnce(200, payload);
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const result = await api.getFindings();

    expect(fetchMock).toHaveBeenCalledWith('/api/findings', expect.objectContaining({
      headers: { 'Content-Type': 'application/json' },
    }));
    expect(result).toEqual(payload);
  });

  it('updateSettings sends a PUT with a JSON body', async () => {
    const fetchMock = mockFetchOnce(200, { awsRegion: 'eu-west-1' });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await api.updateSettings({ awsRegion: 'eu-west-1' });

    expect(fetchMock).toHaveBeenCalledWith('/api/settings', expect.objectContaining({
      method: 'PUT',
      body: JSON.stringify({ awsRegion: 'eu-west-1' }),
    }));
  });

  it('revokeSuppression sends a DELETE to the id-scoped path', async () => {
    const fetchMock = mockFetchOnce(200, { id: 'sup-1', active: false });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await api.revokeSuppression('sup-1');

    expect(fetchMock).toHaveBeenCalledWith('/api/suppressions/sup-1', expect.objectContaining({
      method: 'DELETE',
    }));
  });

  it('throws with the server message when the response is not ok and has a message field', async () => {
    globalThis.fetch = mockFetchOnce(400, { message: 'A suppression needs a reason' }) as unknown as typeof fetch;

    await expect(api.createSuppression({ reason: '' })).rejects.toThrow('A suppression needs a reason');
  });

  it('joins an array message field into one string', async () => {
    globalThis.fetch = mockFetchOnce(400, { message: ['reason required', 'condition required'] }) as unknown as typeof fetch;

    await expect(api.createSuppression({ reason: '' })).rejects.toThrow('reason required, condition required');
  });

  it('falls back to an HTTP-status message when the error body has no message field', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => { throw new Error('not json'); },
    }) as unknown as typeof fetch;

    await expect(api.getFindings()).rejects.toThrow('HTTP 500');
  });

  it('runAwsScan sends the optional region in the body', async () => {
    const fetchMock = mockFetchOnce(200, { ok: true, log: [] });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await api.runAwsScan('ap-southeast-1');

    expect(fetchMock).toHaveBeenCalledWith('/api/aws/scan', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ region: 'ap-southeast-1' }),
    }));
  });
});
