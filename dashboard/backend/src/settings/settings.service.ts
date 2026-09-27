import { Injectable, Logger } from '@nestjs/common';
import { readFile, writeFile } from 'fs/promises';
import { existsSync, readdirSync } from 'fs';
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
}

/**
 * What "Run scan" scans before the user has chosen anything: read from the
 * environment (SCAN_* in .env, or `-e` on docker run) and empty otherwise.
 * A fresh install scans nothing it was not told to, and an empty target is
 * skipped by the pipeline rather than pointed at a demo. Must stay in step
 * with the Jenkins job's own defaults in jenkins/casc.yaml.
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

/** Folders where a project's Terraform usually lives, checked in order. */
const IAC_CANDIDATES = ['infra', 'terraform', 'iac', 'infrastructure', 'deploy', '.'];

function hasTerraform(dir: string): boolean {
  try {
    const entries = readdirSync(dir);
    return Array.isArray(entries) && entries.some((f) => String(f).endsWith('.tf'));
  } catch {
    return false;
  }
}

const SETTINGS_FILE =
  process.env.SETTINGS_FILE ?? join(PATHS.findingsDir, 'settings.json');

@Injectable()
export class SettingsService {
  private readonly logger = new Logger(SettingsService.name);

  async get(): Promise<AppSettings> {
    const DEFAULTS = defaults();
    if (!existsSync(SETTINGS_FILE)) return DEFAULTS;
    try {
      const raw = await readFile(SETTINGS_FILE, 'utf-8');
      const saved = JSON.parse(raw) as Partial<AppSettings>;
      // Merge so a settings file written by an older version still loads.
      return {
        ...DEFAULTS,
        ...saved,
        checks: { ...DEFAULTS.checks, ...(saved.checks ?? {}) },
        pipeline: { ...DEFAULTS.pipeline, ...(saved.pipeline ?? {}) },
      };
    } catch (err) {
      this.logger.warn(`Could not read settings, using defaults: ${err}`);
      return DEFAULTS;
    }
  }

  async update(patch: Partial<AppSettings>): Promise<AppSettings> {
    const current = await this.get();
    const next: AppSettings = {
      ...current,
      ...patch,
      checks: { ...current.checks, ...(patch.checks ?? {}) },
      pipeline: { ...current.pipeline, ...(patch.pipeline ?? {}) },
    };
    await writeFile(SETTINGS_FILE, JSON.stringify(next, null, 2), 'utf-8');
    return next;
  }

  /** The --checks value for the AWS monitor, e.g. "ec2,sg,s3". */
  async enabledChecks(): Promise<string> {
    const { checks } = await this.get();
    return Object.entries(checks)
      .filter(([, on]) => on)
      .map(([name]) => name)
      .join(',');
  }

  /**
   * Inspects whatever is actually mounted at PATHS.target and suggests real
   * Pipeline target values from it, rather than leaving the fields pinned to
   * the demo forever. This is a *suggestion* the frontend offers the user to
   * apply, not something that silently overwrites saved settings - what
   * "Run scan" actually does should always be something the user explicitly
   * chose, per PipelineSettings' own contract.
   */
  async detectTarget(): Promise<{
    sourceDir: string;
    projectName?: string;
    hasDockerfile: boolean;
    /** A folder with Terraform files, for Checkov - absent when none found. */
    iacDir?: string;
  }> {
    const root = PATHS.target;
    // Nothing mounted (an empty /target): there is no project to suggest.
    let mounted = false;
    try {
      const entries = readdirSync(root);
      mounted = Array.isArray(entries) && entries.length > 0;
    } catch {
      mounted = false;
    }
    if (!mounted) {
      return { sourceDir: '', hasDockerfile: false };
    }
    // The bundled demo nests its real content one level down
    // (demo-app/juice-shop/); a project mounted directly at /target has no
    // such subfolder, so its own root is what should be scanned.
    const sourceDir = existsSync(join(root, 'juice-shop'))
      ? join(root, 'juice-shop')
      : root;

    let projectName: string | undefined;
    try {
      const pkgPath = join(sourceDir, 'package.json');
      if (existsSync(pkgPath)) {
        const pkg = JSON.parse(await readFile(pkgPath, 'utf-8'));
        if (typeof pkg.name === 'string' && pkg.name.trim()) {
          // SonarQube project keys only allow letters, numbers, '-', '_',
          // '.', ':' - an npm scoped name like "@org/pkg" would otherwise
          // be rejected outright by the SAST stage.
          projectName = pkg.name.trim().replace(/[^a-zA-Z0-9._-]/g, '-');
        }
      }
    } catch (err) {
      this.logger.warn(`Could not read package.json for target detection: ${err}`);
    }

    const iacFolder = IAC_CANDIDATES.map((d) => (d === '.' ? sourceDir : join(sourceDir, d)))
      .find((d) => hasTerraform(d));

    return {
      sourceDir,
      projectName,
      hasDockerfile: existsSync(join(sourceDir, 'Dockerfile')),
      ...(iacFolder ? { iacDir: iacFolder } : {}),
    };
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
