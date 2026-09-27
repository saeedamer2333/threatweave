import { Injectable, Logger } from '@nestjs/common';
import { readFile, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import { execFile } from 'child_process';
import { join } from 'path';
import * as http from 'http';
import { PATHS } from '../config/paths';

export interface PipelineSettings {
  /** Source tree for GitLeaks/SonarQube. Paths under /target resolve to
   * TARGET_PATH on the host; paths under /workspace resolve to ThreatWeave
   * itself - see the Jenkinsfile's toHostPath(). */
  sourceDir: string;
  /** Infrastructure-as-code directory for Checkov. */
  iacDir: string;
  /** Container image for Trivy to scan. */
  targetImage: string;
  /** SonarQube project key for the SAST stage. */
  sonarProjectKey: string;
  /** Include live AWS cloud governance checks in the run. */
  runAwsMonitor: boolean;
  /** Fail the build when the resulting health score is critical. */
  failOnCritical: boolean;
}

/** Where a pipeline target's current value came from, for Settings labels. */
export type TargetOrigin = 'saved' | 'install' | 'detected' | 'none';

export interface AppSettings {
  /** AWS region the cloud monitor scans. Empty means use the profile default. */
  awsRegion: string;
  /** Which cloud checks to run. */
  checks: { ec2: boolean; sg: boolean; s3: boolean; iam: boolean };
  /** Minutes between automatic cloud scans; 0 disables the schedule. */
  scanIntervalMinutes: number;
  /** What "Run scan" actually scans - mirrors the Jenkins job's own
   * parameter defaults (casc.yaml), so nothing changes for an existing
   * install until someone edits these. */
  pipeline: PipelineSettings;
  /** Read-only: where each target value came from. Not saved. */
  pipelineOrigin?: Partial<Record<TargetKey, TargetOrigin>>;
}

type TargetKey = 'sourceDir' | 'iacDir' | 'targetImage' | 'sonarProjectKey';

/** Each pipeline target and the environment variable that seeds it. */
const TARGET_ENV: Record<TargetKey, string> = {
  sourceDir: 'SCAN_SOURCE_DIR',
  iacDir: 'SCAN_IAC_DIR',
  targetImage: 'SCAN_IMAGE',
  sonarProjectKey: 'SCAN_SONAR_KEY',
};

/**
 * What "Run scan" scans before the user has chosen anything: read from the
 * environment and empty otherwise. SCAN_* values come either from the user
 * (.env, or `-e` on docker run) or, in the all-in-one image, from startup
 * detection of the mounted project (target_detect.py, which lists the ones it
 * filled in SCAN_DETECTED). An empty target is skipped by the pipeline rather
 * than pointed at a demo. Must stay in step with jenkins/casc.yaml.
 */
function pipelineDefaults(): PipelineSettings {
  const env = (name: string) => (process.env[name] ?? '').trim();
  return {
    sourceDir: env('SCAN_SOURCE_DIR'),
    iacDir: env('SCAN_IAC_DIR'),
    targetImage: env('SCAN_IMAGE'),
    sonarProjectKey: env('SCAN_SONAR_KEY'),
    runAwsMonitor: true,
    failOnCritical: false,
  };
}

function defaults(): AppSettings {
  return {
    awsRegion: '',
    checks: { ec2: true, sg: true, s3: true, iam: true },
    scanIntervalMinutes: 30,
    pipeline: pipelineDefaults(),
  };
}

const SETTINGS_FILE =
  process.env.SETTINGS_FILE ?? join(PATHS.findingsDir, 'settings.json');

/** What the saved file holds: settings, plus which pipeline keys the user
 * actually chose (so detected or install-time values are not frozen into
 * the file the first time any other setting is saved). */
interface SavedSettings extends Partial<AppSettings> {
  pipelineUserSet?: string[];
}

export interface DetectedTarget {
  sourceDir: string;
  projectName?: string;
  hasDockerfile: boolean;
  /** The best IaC folder, for Checkov - absent when none found. */
  iacDir?: string;
  /** Every folder with Terraform/CDK/CloudFormation, best first. */
  iacCandidates: { path: string; kind: 'terraform' | 'cdk' | 'cloudformation'; files: number }[];
}

export interface PathCheck {
  ok: boolean;
  level: 'ok' | 'warn' | 'error' | 'info';
  message: string;
}

@Injectable()
export class SettingsService {
  private readonly logger = new Logger(SettingsService.name);

  private async readSaved(): Promise<SavedSettings | null> {
    if (!existsSync(SETTINGS_FILE)) return null;
    try {
      return JSON.parse(await readFile(SETTINGS_FILE, 'utf-8')) as SavedSettings;
    } catch (err) {
      this.logger.warn(`Could not read settings, using defaults: ${err}`);
      return null;
    }
  }

  /** Pipeline keys the user chose. A file written before this was tracked
   * counts every saved pipeline key as the user's choice. */
  private userSetKeys(saved: SavedSettings | null): Set<string> {
    if (!saved) return new Set();
    return new Set(saved.pipelineUserSet ?? Object.keys(saved.pipeline ?? {}));
  }

  /** Settings as the rest of the app sees them: defaults, then the saved
   * file on top, plus where each target value came from. */
  private compose(saved: SavedSettings | null): AppSettings {
    const DEFAULTS = defaults();
    const { pipelineUserSet: _ignored, pipelineOrigin: _stale, ...rest } = saved ?? {};
    // Merge so a settings file written by an older version still loads.
    const merged: AppSettings = saved
      ? {
          ...DEFAULTS,
          ...rest,
          checks: { ...DEFAULTS.checks, ...(saved.checks ?? {}) },
          pipeline: { ...DEFAULTS.pipeline, ...(saved.pipeline ?? {}) },
        }
      : DEFAULTS;

    const userSet = this.userSetKeys(saved);
    const detected = new Set((process.env.SCAN_DETECTED ?? '').split(',').map((v) => v.trim()).filter(Boolean));
    const origin: Partial<Record<TargetKey, TargetOrigin>> = {};
    for (const key of Object.keys(TARGET_ENV) as TargetKey[]) {
      const envName = TARGET_ENV[key];
      if (userSet.has(key)) origin[key] = 'saved';
      else if ((process.env[envName] ?? '').trim()) origin[key] = detected.has(envName) ? 'detected' : 'install';
      else origin[key] = 'none';
    }
    return { ...merged, pipelineOrigin: origin };
  }

  async get(): Promise<AppSettings> {
    return this.compose(await this.readSaved());
  }

  async update(patch: Partial<AppSettings>): Promise<AppSettings> {
    const saved = await this.readSaved();
    const current = this.compose(saved);
    const userSet = this.userSetKeys(saved);
    for (const key of Object.keys(patch.pipeline ?? {})) userSet.add(key);

    const pipeline = { ...current.pipeline, ...(patch.pipeline ?? {}) };
    // Only the user's own pipeline choices are written down; everything else
    // keeps following the environment/detection on the next start.
    const storedPipeline = Object.fromEntries(
      Object.entries(pipeline).filter(([key]) => userSet.has(key)),
    );
    const { pipelineOrigin: _o, ...currentRest } = current;
    const { pipelineOrigin: _p, ...patchRest } = patch;
    const next: SavedSettings = {
      ...currentRest,
      ...patchRest,
      checks: { ...current.checks, ...(patch.checks ?? {}) },
      pipeline: storedPipeline as unknown as PipelineSettings,
      pipelineUserSet: [...userSet],
    };
    await writeFile(SETTINGS_FILE, JSON.stringify(next, null, 2), 'utf-8');
    return this.compose(next);
  }

  /** The --checks value for the AWS monitor, e.g. "ec2,sg,s3". */
  async enabledChecks(): Promise<string> {
    const { checks } = await this.get();
    return Object.entries(checks)
      .filter(([, on]) => on)
      .map(([name]) => name)
      .join(',');
  }

  /** Runs aiops_engine/target_detect.py - the same detection the all-in-one
   * image runs at startup - and parses its JSON answer. */
  private runDetect(args: string[]): Promise<unknown> {
    return new Promise((resolve, reject) => {
      execFile(
        PATHS.python,
        [join(PATHS.engineDir, 'target_detect.py'), ...args],
        { timeout: 20_000, maxBuffer: 1024 * 1024 },
        (err, stdout) => {
          if (err) return reject(err);
          try {
            resolve(JSON.parse(String(stdout)));
          } catch (parseErr) {
            reject(parseErr);
          }
        },
      );
    });
  }

  /**
   * Inspects whatever is actually mounted at PATHS.target and suggests real
   * Pipeline target values from it, including every IaC folder found (so a
   * project that keeps Terraform or CDK somewhere unusual can still pick it).
   * A suggestion only: never overwrites a value the user saved.
   */
  async detectTarget(): Promise<DetectedTarget> {
    try {
      return (await this.runDetect(['targets', '--root', PATHS.target])) as DetectedTarget;
    } catch (err) {
      this.logger.warn(`Target detection failed: ${err}`);
      return { sourceDir: '', hasDockerfile: false, iacCandidates: [] };
    }
  }

  /** Checks a path typed in Settings before a scan finds out it was wrong. */
  async checkPath(kind: string, path: string): Promise<PathCheck> {
    if (kind !== 'iac' && kind !== 'source') {
      return { ok: false, level: 'error', message: 'kind must be "iac" or "source".' };
    }
    try {
      return (await this.runDetect(['check', '--kind', kind, '--path', path ?? ''])) as PathCheck;
    } catch (err) {
      this.logger.warn(`Path check failed: ${err}`);
      return { ok: true, level: 'info', message: 'Could not check this path right now.' };
    }
  }

  /**
   * Only meaningful inside the all-in-one image (where this API and the
   * bundled SonarQube share one container) - reports whether SonarQube is
   * actually healthy, and if not, whether the cause looks like it ran out
   * of memory, so the dashboard can explain the real problem and both real
   * fixes (raise the host's memory, or turn SonarQube off) instead of
   * leaving a build failure as the only visible symptom.
   *
   * Reuses jenkins-entrypoint.sh's own `.sonar-env` marker rather than a
   * separate mechanism: an empty marker means SonarQube was never asked to
   * start (SONARQUBE_AUTOSTART=false) or hasn't finished its first boot yet
   * - neither is a problem worth a warning. A marker with a real
   * SONAR_HOST_URL means autoconfig itself already confirmed SonarQube was
   * up at least once; if it is unreachable *now*, that is a genuine
   * regression worth surfacing, not a normal startup state.
   */
  async checkSonarQubeStatus(): Promise<{
    relevant: boolean;
    healthy: boolean;
    crashReason?: 'oom' | 'other';
    message?: string;
  }> {
    if (process.env.SONARQUBE_AUTOSTART !== 'true' || !existsSync('/opt/sonarqube')) {
      return { relevant: false, healthy: false };
    }

    const markerFile = '/var/jenkins_home/.sonar-env';
    if (!existsSync(markerFile)) {
      return { relevant: false, healthy: false }; // still booting for the first time
    }
    const marker = await readFile(markerFile, 'utf-8').catch(() => '');
    if (!/^SONAR_HOST_URL=/m.test(marker)) {
      return { relevant: false, healthy: false }; // autoconfig ran but never confirmed SonarQube up
    }

    try {
      const res = await fetch('http://localhost:9000/api/system/status', { signal: AbortSignal.timeout(3000) });
      const body = (await res.json()) as { status?: string };
      if (body.status === 'UP' || body.status === 'STARTING') {
        return { relevant: true, healthy: true };
      }
    } catch {
      // unreachable - fall through to log inspection below
    }

    const logFiles = [
      '/opt/sonarqube/logs/es.log',
      '/opt/sonarqube/logs/sonar.log',
      '/opt/sonarqube/logs/ce.log',
      '/opt/sonarqube/logs/web.log',
    ];
    for (const file of logFiles) {
      if (!existsSync(file)) continue;
      try {
        const content = await readFile(file, 'utf-8');
        if (/OutOfMemoryError/i.test(content.slice(-20000))) {
          return {
            relevant: true,
            healthy: false,
            crashReason: 'oom',
            message: 'SonarQube ran out of memory and stopped.',
          };
        }
      } catch (err) {
        this.logger.warn(`Could not read ${file} while checking SonarQube health: ${err}`);
      }
    }

    return {
      relevant: true,
      healthy: false,
      crashReason: 'other',
      message: 'SonarQube was running but is not responding now.',
    };
  }

  /**
   * Reports whether the async SonarQube scan the Jenkinsfile launches
   * (checkPendingSonarScan/kickOffSonarScan) is genuinely running right
   * now - not just "was launched at some point", which the marker file
   * alone can't distinguish from "already finished, waiting for a build to
   * pick it up" or "the container is long gone". Between builds - the
   * whole reason this scan runs detached in the first place - there is
   * often no Jenkins build around at all to report this, so it has to be
   * read directly from the same source Jenkins itself checks: the
   * container's own live state, over the Docker Engine API.
   */
  async checkAsyncSonarScan(): Promise<{
    scanning: boolean;
    phase?: 'running' | 'finished-pending-harvest';
    runId?: string;
    ageMinutes?: number;
  }> {
    const markerFile = join(PATHS.findingsDir, '.sonar-pending.json');
    if (!existsSync(markerFile)) return { scanning: false };

    let pending: { container?: string; run_id?: string; started_at_epoch_ms?: number };
    try {
      pending = JSON.parse(await readFile(markerFile, 'utf-8'));
    } catch (err) {
      this.logger.warn(`Could not parse ${markerFile}: ${err}`);
      return { scanning: false };
    }
    if (!pending.container) return { scanning: false };

    const ageMinutes = pending.started_at_epoch_ms
      ? Math.floor((Date.now() - pending.started_at_epoch_ms) / 60000)
      : undefined;

    try {
      const { status, body } = await this.dockerGet(`/containers/${pending.container}/json`);
      if (status === 404) return { scanning: false }; // stale marker - container already reaped
      const running = (body as { State?: { Running?: boolean } })?.State?.Running === true;
      return { scanning: true, phase: running ? 'running' : 'finished-pending-harvest', runId: pending.run_id, ageMinutes };
    } catch (err) {
      // Docker socket not reachable (e.g. this deployment doesn't mount
      // it) - not an error state worth surfacing, just nothing to report.
      this.logger.warn(`Could not query Docker for the async SonarQube scan's state: ${err}`);
      return { scanning: false };
    }
  }

  /** A minimal GET against the Docker Engine API over its Unix socket - no
   * docker CLI or client library needed just to read one container's
   * state. */
  private dockerGet(path: string): Promise<{ status: number; body: unknown }> {
    return new Promise((resolve, reject) => {
      const req = http.request(
        { socketPath: '/var/run/docker.sock', path, method: 'GET', timeout: 3000 },
        (res) => {
          let data = '';
          res.on('data', (chunk) => (data += chunk));
          res.on('end', () => {
            try {
              resolve({ status: res.statusCode ?? 0, body: data ? JSON.parse(data) : null });
            } catch (err) {
              reject(err instanceof Error ? err : new Error(String(err)));
            }
          });
        },
      );
      req.on('error', reject);
      req.on('timeout', () => req.destroy(new Error('Docker socket request timed out')));
      req.end();
    });
  }
}
