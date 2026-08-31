import { Injectable, Logger } from '@nestjs/common';
import { readFile, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
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

const PIPELINE_DEFAULTS: PipelineSettings = {
  sourceDir: '/target/juice-shop',
  iacDir: '/workspace/infra',
  targetImage: 'bkimminich/juice-shop:latest',
  sonarProjectKey: 'threatweave-demo',
  runAwsMonitor: true,
  failOnCritical: false,
};

const DEFAULTS: AppSettings = {
  awsRegion: '',
  checks: { ec2: true, sg: true, s3: true, iam: true },
  scanIntervalMinutes: 30,
  pipeline: PIPELINE_DEFAULTS,
};

const SETTINGS_FILE =
  process.env.SETTINGS_FILE ?? join(PATHS.findingsDir, 'settings.json');

@Injectable()
export class SettingsService {
  private readonly logger = new Logger(SettingsService.name);

  async get(): Promise<AppSettings> {
    if (!existsSync(SETTINGS_FILE)) return DEFAULTS;
    try {
      const raw = await readFile(SETTINGS_FILE, 'utf-8');
      const saved = JSON.parse(raw) as Partial<AppSettings>;
      // Merge so a settings file written by an older version still loads.
      return {
        ...DEFAULTS,
        ...saved,
        checks: { ...DEFAULTS.checks, ...(saved.checks ?? {}) },
        pipeline: { ...PIPELINE_DEFAULTS, ...(saved.pipeline ?? {}) },
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
  }> {
    const root = PATHS.target;
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

    return {
      sourceDir,
      projectName,
      hasDockerfile: existsSync(join(sourceDir, 'Dockerfile')),
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
}
