import { ConflictException, Injectable, Logger } from '@nestjs/common';
import { spawn } from 'child_process';
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

    this.run(PATHS.python, ['engine.py'], PATHS.engineDir)
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

  /** Run the AWS monitor with the configured region and enabled checks. */
  async runAwsMonitor(
    region?: string,
    checks?: string,
  ): Promise<{ ok: boolean; log: string[] }> {
    const args = [PATHS.awsMonitor];
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
   * Whether Boto3 can resolve credentials, and for which account. Used by the
   * Settings page so the user sees connection state without typing anything.
   */
  async getAwsStatus(): Promise<{
    connected: boolean;
    account?: string;
    arn?: string;
    region?: string;
    message?: string;
  }> {
    const script = [
      'import json',
      'try:',
      '    import boto3',
      '    s = boto3.Session()',
      '    i = s.client("sts").get_caller_identity()',
      '    print(json.dumps({"connected": True, "account": i["Account"],',
      '                      "arn": i["Arn"], "region": s.region_name}))',
      'except Exception as e:',
      '    print(json.dumps({"connected": False, "message": str(e)[:200]}))',
    ].join('\n');

    try {
      const out = await this.run(PATHS.python, ['-c', script], PATHS.projectRoot);
      const line = out.reverse().find((l) => l.trim().startsWith('{'));
      return line ? JSON.parse(line) : { connected: false, message: 'No response' };
    } catch (err) {
      return { connected: false, message: (err as Error).message };
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
