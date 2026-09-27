import type { AiopsOutput, Suppression } from './types';

/**
 * Calls go to the NestJS API through the dev-server proxy (see vite.config.ts),
 * so the same relative URLs work when the built frontend is served alongside
 * the API in production.
 */
const BASE = '/api';

/** Carries the HTTP status alongside the message, so callers can tell "the
 * API is reachable but says there's nothing yet" (404, e.g. no scan has run)
 * apart from a genuine connectivity failure - those need very different UI
 * treatment, and a plain Error threw both away identically. */
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

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
    throw new ApiError(detail, res.status);
  }
  return res.json() as Promise<T>;
}

export interface AwsStatus {
  connected: boolean;
  account?: string;
  arn?: string;
  region?: string;
  message?: string;
  /** "deployment" means the failure has nothing to do with AWS credentials
   * (a missing script, a broken path) - showing the generic "run aws
   * configure" guidance in that case would point at the wrong fix. Absent
   * or "credentials"/"unknown" means the generic guidance still applies. */
  messageKind?: 'deployment' | 'credentials' | 'unknown';
  /** Beyond "credentials are valid": can they actually read anything?
   * sts:GetCallerIdentity needs no IAM permission at all, so `connected`
   * alone cannot tell "valid but zero policies attached" from "fully
   * working" - this can. */
  permissions?: { ec2: boolean; s3: boolean; iam: boolean };
  hasFullAccess?: boolean;
  /** 'manual' while keys typed on the Settings page are in use (held in the
   * API's memory for this session only); 'default' for Boto3's own chain. */
  credentialSource?: 'manual' | 'default';
}

export interface ManualAwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  region?: string;
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

export interface PipelineSettings {
  sourceDir: string;
  iacDir: string;
  targetImage: string;
  sonarProjectKey: string;
  runAwsMonitor: boolean;
  failOnCritical: boolean;
}

/** Where a pipeline target's value came from. */
export type TargetOrigin = 'saved' | 'install' | 'detected' | 'none';

export interface AppSettings {
  awsRegion: string;
  checks: { ec2: boolean; sg: boolean; s3: boolean; iam: boolean };
  scanIntervalMinutes: number;
  pipeline: PipelineSettings;
  /** Read-only, from the API: where each target value came from. */
  pipelineOrigin?: Partial<Record<'sourceDir' | 'iacDir' | 'targetImage' | 'sonarProjectKey', TargetOrigin>>;
}

/** Result of checking a typed path before it is scanned. */
export interface PathCheck {
  ok: boolean;
  level: 'ok' | 'warn' | 'error' | 'info';
  message: string;
}

export interface DetectedTarget {
  sourceDir: string;
  projectName?: string;
  hasDockerfile: boolean;
  /** The best IaC folder, for Checkov - absent when none found. */
  iacDir?: string;
  /** Every folder with Terraform, CDK or CloudFormation files, best first. */
  iacCandidates?: { path: string; kind: 'terraform' | 'cdk' | 'cloudformation'; files: number }[];
}

export interface SonarQubeStatus {
  /** false outside the all-in-one image (split docker-compose deployment,
   * or SONARQUBE_AUTOSTART=false) - there is nothing local to warn about. */
  relevant: boolean;
  healthy: boolean;
  crashReason?: 'oom' | 'other';
  /** SonarQube never came up this boot, so SAST is off until a restart. */
  didNotStart?: 'timeout' | 'token';
  message?: string;
}

/** The async SonarQube scan the Jenkinsfile launches detached
 * (checkPendingSonarScan/kickOffSonarScan) can genuinely be scanning with
 * no Jenkins build around to report it - the whole reason it runs
 * detached in the first place. This reads its real, current state
 * directly rather than only ever showing it as part of a build's own
 * progress. */
export interface AsyncSonarScanStatus {
  scanning: boolean;
  /** 'running': the scanner container is still actively working.
   * 'finished-pending-harvest': it already exited: a later run's own
   * catch-up will pick up its results, nothing further to wait on. */
  phase?: 'running' | 'finished-pending-harvest';
  runId?: string;
  ageMinutes?: number;
}

export interface PipelineStatus {
  /** 'skipped' is a routine auto-skip (no new commits since the last
   * scan), not an error - kept distinct from 'failed' so it never renders
   * as one. */
  state: 'idle' | 'queued' | 'running' | 'success' | 'skipped' | 'failed';
  buildNumber?: number;
  buildUrl?: string;
  startedAt?: string;
  finishedAt?: string;
  error?: string;
  currentActivity?: string;
  stalled?: boolean;
  currentStage?: string;
  activeStages?: string[];
}

export const api = {
  getFindings: () => request<AiopsOutput>('/findings'),
  getSettings: () => request<AppSettings>('/settings'),
  updateSettings: (body: Partial<AppSettings>) =>
    request<AppSettings>('/settings', { method: 'PUT', body: JSON.stringify(body) }),
  detectTarget: () => request<DetectedTarget>('/settings/detect-target'),
  checkPath: (kind: 'iac' | 'source' | 'image', path: string) =>
    request<PathCheck>(`/settings/check-path?kind=${kind}&path=${encodeURIComponent(path)}`),
  getSonarQubeStatus: () => request<SonarQubeStatus>('/settings/sonarqube-status'),
  getAsyncSonarScanStatus: () => request<AsyncSonarScanStatus>('/settings/sonarqube-scan-status'),
  getSuppressions: () => request<Suppression[]>('/suppressions'),
  createSuppression: (body: NewSuppression) =>
    request<Suppression>('/suppressions', { method: 'POST', body: JSON.stringify(body) }),
  revokeSuppression: (id: string) =>
    request<Suppression>(`/suppressions/${id}`, { method: 'DELETE' }),
  startScan: () => request<ScanStatus>('/scan', { method: 'POST' }),
  getScanStatus: () => request<ScanStatus>('/scan/status'),
  runPipeline: () => request<PipelineStatus>('/pipeline/run', { method: 'POST' }),
  getPipelineStatus: () => request<PipelineStatus>('/pipeline/status'),
  getAwsStatus: () => request<AwsStatus>('/aws/status'),
  connectAws: (creds: ManualAwsCredentials) =>
    request<AwsStatus>('/aws/credentials', { method: 'POST', body: JSON.stringify(creds) }),
  disconnectAws: () => request<AwsStatus>('/aws/credentials', { method: 'DELETE' }),
  runAwsScan: (region?: string) =>
    request<{ ok: boolean; log: string[] }>('/aws/scan', {
      method: 'POST',
      body: JSON.stringify({ region }),
    }),
};
