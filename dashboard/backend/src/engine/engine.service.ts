import { ConflictException, Injectable, Logger } from '@nestjs/common';
import { spawn } from 'child_process';
import { join } from 'path';
import { PATHS } from '../config/paths';

export type RunState = 'idle' | 'running' | 'success' | 'failed';

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
      const log = await this.run(PATHS.python, args, PATHS.projectRoot);
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
  }> {
    try {
      const out = await this.run(PATHS.python, [PATHS.awsStatusCheck], PATHS.projectRoot);
      const line = out.reverse().find((l) => l.trim().startsWith('{'));
      return line ? JSON.parse(line) : { connected: false, message: 'No response', messageKind: 'unknown' };
    } catch (err) {
      const raw = (err as Error).message;
      if (/No such file or directory|ENOENT|cannot find the (file|path)/i.test(raw)) {
        return {
          connected: false,
          messageKind: 'deployment',
          message:
            'The AWS status-check script is missing from this deployment. This is a container ' +
            `configuration problem, not something fixable by setting up AWS credentials. (${raw})`,
        };
      }
      return { connected: false, messageKind: 'unknown', message: raw };
    }
  }

  /** Spawn a process, stream its output into the status log, resolve on exit 0. */
  private run(cmd: string, args: string[], cwd: string): Promise<string[]> {
    return new Promise((resolve, reject) => {
      const lines: string[] = [];
      const child = spawn(cmd, args, { cwd, shell: false });

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
