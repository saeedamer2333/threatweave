import { ConflictException, Injectable, Logger } from '@nestjs/common';
import { spawn } from 'child_process';
import { join } from 'path';
import { PATHS } from '../config/paths';

export type RunState = 'idle' | 'running' | 'success' | 'failed';

/**
 * AWS keys typed into the Settings page, for a machine where nobody has run
 * `aws configure`. Held in this process's memory only - never written to
 * disk, never logged, never returned by any endpoint - and gone when the API
 * restarts or the user disconnects. The preferred route is still the default
 * Boto3 chain (an IAM role, environment, or ~/.aws/credentials).
 */
export interface ManualAwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  region?: string;
}

const ACCESS_KEY_ID = /^(AKIA|ASIA)[A-Z0-9]{16}$/;
const SECRET_ACCESS_KEY = /^[A-Za-z0-9/+=]{40}$/;
const REGION = /^[a-z]{2}(-gov)?-[a-z]+-\d$/;

/** Returns a user-facing problem with the submitted keys, or null if the
 * shape is valid. Shape only - whether AWS accepts them is checked live. */
export function validateManualAwsCredentials(c: Partial<ManualAwsCredentials>): string | null {
  const id = (c.accessKeyId ?? '').trim();
  const secret = (c.secretAccessKey ?? '').trim();
  if (!ACCESS_KEY_ID.test(id)) {
    return 'Access key ID should be 20 characters starting with AKIA (or ASIA for temporary keys).';
  }
  if (!SECRET_ACCESS_KEY.test(secret)) {
    return 'Secret access key should be exactly 40 characters.';
  }
  if (id.startsWith('ASIA') && !(c.sessionToken ?? '').trim()) {
    return 'Temporary keys (starting with ASIA) also need their session token.';
  }
  if (c.region && !REGION.test(c.region.trim())) {
    return 'Region should look like ap-southeast-1.';
  }
  return null;
}

export interface RunStatus {
  state: RunState;
  startedAt?: string;
  finishedAt?: string;
  durationMs?: number;
  log: string[];
  error?: string;
}

@Injectable()
export class EngineService {
  private readonly logger = new Logger(EngineService.name);

  /**
   * Only one run at a time. The engine writes aiops-output.json, so two
   * concurrent runs would race on the same file.
   */
  private status: RunStatus = { state: 'idle', log: [] };

  private manualAws?: ManualAwsCredentials;

  hasManualAwsCredentials(): boolean {
    return this.manualAws !== undefined;
  }

  /**
   * Try the given keys; keep them only if AWS accepts them. On rejection
   * the previous state (manual keys or the default chain) is restored, so a
   * typo never disconnects a working setup.
   */
  async connectManualAws(creds: ManualAwsCredentials) {
    const previous = this.manualAws;
    this.manualAws = {
      accessKeyId: creds.accessKeyId.trim(),
      secretAccessKey: creds.secretAccessKey.trim(),
      ...(creds.sessionToken?.trim() ? { sessionToken: creds.sessionToken.trim() } : {}),
      ...(creds.region?.trim() ? { region: creds.region.trim() } : {}),
    };
    const status = await this.getAwsStatus();
    if (!status.connected) {
      this.manualAws = previous;
    }
    return status;
  }

  async disconnectManualAws() {
    this.manualAws = undefined;
    return this.getAwsStatus();
  }

  /**
   * Environment for the Python AWS scripts. With manual keys set, they are
   * passed as the standard AWS_* variables, which Boto3 checks before
   * ~/.aws/credentials; AWS_PROFILE is dropped because an explicit profile
   * would make Boto3 skip the environment keys.
   */
  private awsEnv(): NodeJS.ProcessEnv | undefined {
    if (!this.manualAws) return undefined;
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.AWS_PROFILE;
    delete env.AWS_DEFAULT_PROFILE;
    env.AWS_ACCESS_KEY_ID = this.manualAws.accessKeyId;
    env.AWS_SECRET_ACCESS_KEY = this.manualAws.secretAccessKey;
    if (this.manualAws.sessionToken) env.AWS_SESSION_TOKEN = this.manualAws.sessionToken;
    else delete env.AWS_SESSION_TOKEN;
    if (this.manualAws.region) env.AWS_DEFAULT_REGION = this.manualAws.region;
    return env;
  }

  getStatus(): RunStatus {
    return this.status;
  }

  /** Start an engine run in the background; returns immediately. */
  startScan(): RunStatus {
    if (this.status.state === 'running') {
      throw new ConflictException('A scan is already running');
    }

    const startedAt = new Date();
    this.status = { state: 'running', startedAt: startedAt.toISOString(), log: [] };

    // engine.py's own defaults are the bundled *sample* fixtures, meant for
    // running the engine standalone with no real scan having happened yet.
    // Without these explicit paths, "Run scan" would silently re-score the
    // demo data instead of the real findings/scan-inputs/, overwriting a
    // genuine run's results with sample output and giving no indication
    // anything had gone wrong.
    this.run(PATHS.python, [
      'engine.py',
      '--input', join(PATHS.findingsDir, 'scan-inputs'),
      '--output', PATHS.aiopsOutput,
      '--history', PATHS.history,
      '--first-seen', PATHS.firstSeen,
    ], PATHS.engineDir)
      .then(() => {
        const finished = new Date();
        this.status = {
          ...this.status,
          state: 'success',
          finishedAt: finished.toISOString(),
          durationMs: finished.getTime() - startedAt.getTime(),
        };
      })
      .catch((err: Error) => {
        const finished = new Date();
        this.status = {
          ...this.status,
          state: 'failed',
          finishedAt: finished.toISOString(),
          durationMs: finished.getTime() - startedAt.getTime(),
          error: err.message,
        };
        this.logger.error(`Engine run failed: ${err.message}`);
      });

    return this.status;
  }

  /**
   * Run the AWS monitor with the configured region and enabled checks.
   *
   * `--output` is not optional here despite monitor.py having its own
   * default - that default is `findings/aws-findings.json`, one directory
   * above `findings/scan-inputs/`, which is where the aggregator (and
   * every other scanner's report) actually lives. Confirmed live: without
   * this, every manual "Run cloud scan" ever wrote its result to a
   * location the engine never reads, no matter how many times "run a full
   * scan to fold the results in" was followed afterward - a stale
   * findings/aws-findings.json from an old test sat there while
   * findings/scan-inputs/aws-findings.json simply never existed.
   */
  async runAwsMonitor(
    region?: string,
    checks?: string,
  ): Promise<{ ok: boolean; log: string[] }> {
    const args = [PATHS.awsMonitor, '--output', join(PATHS.findingsDir, 'scan-inputs', 'aws-findings.json')];
    if (region) args.push('--region', region);
    if (checks) args.push('--checks', checks);
    try {
      const log = await this.run(PATHS.python, args, PATHS.projectRoot, this.awsEnv());
      return { ok: true, log };
    } catch (err) {
      return { ok: false, log: [(err as Error).message] };
    }
  }

  /**
   * Whether Boto3 can resolve credentials, for which account, and - beyond
   * just "credentials parse" - whether they can actually read anything.
   * `sts:GetCallerIdentity` alone needs no IAM permission at all, so relying
   * on it exclusively would show "Connected" for a real account even with
   * zero attached policies, while every actual check in monitor.py silently
   * failed with AccessDenied. status_check.py probes the same services
   * monitor.py's checks use. Used by the Settings page so the user sees
   * real connection *and* permission state without typing anything.
   */
  async getAwsStatus(): Promise<{
    connected: boolean;
    account?: string;
    arn?: string;
    region?: string;
    message?: string;
    /** Distinguishes "the deployment itself is broken" (a missing script, a
     * bad path - nothing the user watching the dashboard can fix by
     * configuring AWS) from "credentials genuinely aren't set up yet" -
     * without this, the generic "run aws configure" guidance shows even
     * when the real problem has nothing to do with credentials, which reads
     * as unclear/wrong advice rather than an actual explanation. */
    messageKind?: 'deployment' | 'credentials' | 'unknown';
    permissions?: { ec2: boolean; s3: boolean; iam: boolean };
    hasFullAccess?: boolean;
    /** 'manual' when the keys typed on the Settings page are in use,
     * 'default' for Boto3's normal chain (role, environment, ~/.aws). */
    credentialSource: 'manual' | 'default';
  }> {
    const credentialSource = this.manualAws ? 'manual' : 'default';
    try {
      const out = await this.run(PATHS.python, [PATHS.awsStatusCheck], PATHS.projectRoot, this.awsEnv());
      const line = out.reverse().find((l) => l.trim().startsWith('{'));
      return line
        ? { ...JSON.parse(line), credentialSource }
        : { connected: false, message: 'No response', messageKind: 'unknown', credentialSource };
    } catch (err) {
      const raw = (err as Error).message;
      if (/No such file or directory|ENOENT|cannot find the (file|path)/i.test(raw)) {
        return {
          connected: false,
          messageKind: 'deployment',
          message:
            'The AWS status-check script is missing from this deployment. This is a container ' +
            `configuration problem, not something fixable by setting up AWS credentials. (${raw})`,
          credentialSource,
        };
      }
      return { connected: false, messageKind: 'unknown', message: raw, credentialSource };
    }
  }

  /** Spawn a process, stream its output into the status log, resolve on exit 0. */
  private run(cmd: string, args: string[], cwd: string, env?: NodeJS.ProcessEnv): Promise<string[]> {
    return new Promise((resolve, reject) => {
      const lines: string[] = [];
      const child = spawn(cmd, args, env ? { cwd, shell: false, env } : { cwd, shell: false });

      const capture = (chunk: Buffer) => {
        const text = chunk.toString('utf-8');
        for (const line of text.split(/\r?\n/)) {
          if (!line.trim()) continue;
          lines.push(line);
          if (this.status.state === 'running') {
            this.status.log.push(line);
          }
        }
      };

      child.stdout.on('data', capture);
      child.stderr.on('data', capture);

      child.on('error', (err) => reject(err));
      child.on('close', (code) => {
        if (code === 0) resolve(lines);
        else reject(new Error(`${cmd} exited with code ${code}: ${lines.slice(-3).join(' | ')}`));
      });
    });
  }
}
