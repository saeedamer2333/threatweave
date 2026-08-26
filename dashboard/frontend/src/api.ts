import type { AiopsOutput, Suppression } from './types';

/**
 * Calls go to the NestJS API through the dev-server proxy (see vite.config.ts),
 * so the same relative URLs work when the built frontend is served alongside
 * the API in production.
 */
const BASE = '/api';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.message) detail = Array.isArray(body.message) ? body.message.join(', ') : body.message;
    } catch {
      /* response had no JSON body */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export interface AwsStatus {
  connected: boolean;
  account?: string;
  arn?: string;
  region?: string;
  message?: string;
}

export interface ScanStatus {
  state: 'idle' | 'running' | 'success' | 'failed';
  startedAt?: string;
  finishedAt?: string;
  durationMs?: number;
  log: string[];
  error?: string;
}

export interface NewSuppression {
  reason: string;
  created_by?: string;
  source?: string;
  rule_id?: string;
  cve_id?: string;
  type?: string;
  severity?: string;
  resource_pattern?: string;
  title_pattern?: string;
}

export interface AppSettings {
  awsRegion: string;
  checks: { ec2: boolean; sg: boolean; s3: boolean; iam: boolean };
  scanIntervalMinutes: number;
}

export const api = {
  getFindings: () => request<AiopsOutput>('/findings'),
  getSettings: () => request<AppSettings>('/settings'),
  updateSettings: (body: Partial<AppSettings>) =>
    request<AppSettings>('/settings', { method: 'PUT', body: JSON.stringify(body) }),
  getSuppressions: () => request<Suppression[]>('/suppressions'),
  createSuppression: (body: NewSuppression) =>
    request<Suppression>('/suppressions', { method: 'POST', body: JSON.stringify(body) }),
  revokeSuppression: (id: string) =>
    request<Suppression>(`/suppressions/${id}`, { method: 'DELETE' }),
  startScan: () => request<ScanStatus>('/scan', { method: 'POST' }),
  getScanStatus: () => request<ScanStatus>('/scan/status'),
  getAwsStatus: () => request<AwsStatus>('/aws/status'),
  runAwsScan: (region?: string) =>
    request<{ ok: boolean; log: string[] }>('/aws/scan', {
      method: 'POST',
      body: JSON.stringify({ region }),
    }),
};
