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
}
