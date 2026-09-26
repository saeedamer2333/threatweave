jest.mock('child_process');
jest.mock('../config/paths', () => ({
  PATHS: {
    python: 'python3',
    engineDir: '/fake/aiops_engine',
    findingsDir: '/fake/findings',
    aiopsOutput: '/fake/findings/aiops-output.json',
    history: '/fake/findings/history.json',
    firstSeen: '/fake/findings/first_seen.json',
    projectRoot: '/fake',
    awsMonitor: '/fake/aws_monitor/monitor.py',
    awsStatusCheck: '/fake/aws_monitor/status_check.py',
  },
}));

import { spawn } from 'child_process';
import { EventEmitter } from 'events';
import { join } from 'path';
import { EngineService, validateManualAwsCredentials } from './engine.service';

const mockSpawn = spawn as jest.MockedFunction<typeof spawn>;

function fakeChild() {
  const child = new EventEmitter() as EventEmitter & { stdout: EventEmitter; stderr: EventEmitter };
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  return child;
}

describe('EngineService', () => {
  let service: EngineService;

  beforeEach(() => {
    service = new EngineService();
    jest.resetAllMocks();
  });

  describe('startScan', () => {
    it('passes explicit --input/--output/--history/--first-seen so it re-scores the real scan-inputs, not the bundled sample fixtures', () => {
      // Regression: engine.py's own argparse defaults point at
      // aiops_engine/sample_inputs/ - the demo fixtures - so calling it with
      // no arguments (as this used to) silently re-scores sample data
      // instead of a real run's findings/scan-inputs/, overwriting real
      // results with sample output with no indication anything was wrong.
      const child = fakeChild();
      mockSpawn.mockReturnValue(child as never);

      service.startScan();

      expect(mockSpawn).toHaveBeenCalledWith(
        'python3',
        [
          'engine.py',
          '--input', join('/fake/findings', 'scan-inputs'),
          '--output', '/fake/findings/aiops-output.json',
          '--history', '/fake/findings/history.json',
          '--first-seen', '/fake/findings/first_seen.json',
        ],
        expect.objectContaining({ cwd: '/fake/aiops_engine' }),
      );
    });

    it('refuses to start a second scan while one is already running', () => {
      mockSpawn.mockReturnValue(fakeChild() as never);
      service.startScan();

      expect(() => service.startScan()).toThrow('A scan is already running');
    });

    it('reports success once the process exits cleanly', () => {
      const child = fakeChild();
      mockSpawn.mockReturnValue(child as never);

      service.startScan();
      child.emit('close', 0);

      return new Promise((resolve) => setImmediate(() => {
        expect(service.getStatus().state).toBe('success');
        resolve(undefined);
      }));
    });

    it('reports failed with the exit code and recent output when the process exits non-zero', () => {
      const child = fakeChild();
      mockSpawn.mockReturnValue(child as never);

      service.startScan();
      child.stdout.emit('data', Buffer.from('some progress line\n'));
      child.emit('close', 1);

      return new Promise((resolve) => setImmediate(() => {
        const status = service.getStatus();
        expect(status.state).toBe('failed');
        expect(status.error).toContain('exited with code 1');
        resolve(undefined);
      }));
    });
  });

  describe('runAwsMonitor', () => {
    // ---- Regression: confirmed live. monitor.py's own --output default is
    // findings/aws-findings.json, one directory above
    // findings/scan-inputs/ - where the aggregator, and every other
    // scanner's report, actually lives. Without passing --output
    // explicitly, every manual "Run cloud scan" wrote its result to a file
    // the engine never reads, no matter how many times a follow-up rescan
    // ran afterward.
    it('passes an explicit --output pointing into scan-inputs/, not monitor.py\'s own default', async () => {
      const child = fakeChild();
      mockSpawn.mockReturnValue(child as never);

      const promise = service.runAwsMonitor();
      child.emit('close', 0);
      await promise;

      expect(mockSpawn).toHaveBeenCalledWith(
        'python3',
        ['/fake/aws_monitor/monitor.py', '--output', join('/fake/findings', 'scan-inputs', 'aws-findings.json')],
        expect.objectContaining({ cwd: '/fake' }),
      );
    });

    it('still appends region and checks when given, after the output path', async () => {
      const child = fakeChild();
      mockSpawn.mockReturnValue(child as never);

      const promise = service.runAwsMonitor('eu-west-1', 'ec2,s3');
      child.emit('close', 0);
      await promise;

      expect(mockSpawn).toHaveBeenCalledWith(
        'python3',
        [
          '/fake/aws_monitor/monitor.py', '--output', join('/fake/findings', 'scan-inputs', 'aws-findings.json'),
          '--region', 'eu-west-1', '--checks', 'ec2,s3',
        ],
        expect.objectContaining({ cwd: '/fake' }),
      );
    });
  });

  describe('getAwsStatus', () => {
    it('runs status_check.py and returns its parsed JSON, including the permission breakdown', async () => {
      const child = fakeChild();
      mockSpawn.mockReturnValue(child as never);

      const promise = service.getAwsStatus();
      child.stdout.emit('data', Buffer.from(JSON.stringify({
        connected: true, account: '111122223333', arn: 'arn:aws:iam::111122223333:user/test',
        region: 'us-east-1', permissions: { ec2: true, s3: false, iam: true }, hasFullAccess: false,
      }) + '\n'));
      child.emit('close', 0);

      const result = await promise;

      expect(mockSpawn).toHaveBeenCalledWith(
        'python3', ['/fake/aws_monitor/status_check.py'], expect.objectContaining({ cwd: '/fake' }),
      );
      expect(result.connected).toBe(true);
      expect(result.hasFullAccess).toBe(false);
      expect(result.permissions).toEqual({ ec2: true, s3: false, iam: true });
    });

    it('reports not connected, rather than throwing, when the script itself fails to run', async () => {
      const child = fakeChild();
      mockSpawn.mockReturnValue(child as never);

      const promise = service.getAwsStatus();
      child.emit('close', 1);

      const result = await promise;

      expect(result.connected).toBe(false);
      expect(result.message).toContain('exited with code 1');
    });
  });

  describe('manual AWS credentials', () => {
    const KEYS = { accessKeyId: 'AKIAABCDEFGHIJKLMNOP', secretAccessKey: 'a'.repeat(40) };

    /** Answer the next spawned status check with the given JSON. */
    function answerStatus(json: object) {
      const child = fakeChild();
      mockSpawn.mockReturnValueOnce(child as never);
      setImmediate(() => {
        child.stdout.emit('data', Buffer.from(JSON.stringify(json) + '\n'));
        child.emit('close', 0);
      });
    }

    function lastSpawnEnv(): NodeJS.ProcessEnv | undefined {
      const calls = mockSpawn.mock.calls;
      return (calls[calls.length - 1][2] as { env?: NodeJS.ProcessEnv }).env;
    }

    it('validates the key shapes before anything is sent to AWS', () => {
      expect(validateManualAwsCredentials(KEYS)).toBeNull();
      expect(validateManualAwsCredentials({ ...KEYS, accessKeyId: 'not-a-key' })).toMatch(/Access key ID/);
      expect(validateManualAwsCredentials({ ...KEYS, secretAccessKey: 'short' })).toMatch(/40 characters/);
      expect(validateManualAwsCredentials({ ...KEYS, accessKeyId: 'ASIAABCDEFGHIJKLMNOP' })).toMatch(/session token/);
      expect(validateManualAwsCredentials({ ...KEYS, region: 'Singapore' })).toMatch(/Region/);
    });

    it('uses the default credential chain (no env override) until keys are entered', async () => {
      answerStatus({ connected: true, account: '1', permissions: { ec2: true, s3: true, iam: true }, hasFullAccess: true });
      const result = await service.getAwsStatus();

      expect(lastSpawnEnv()).toBeUndefined();
      expect(result.credentialSource).toBe('default');
    });

    it('passes accepted keys to the AWS scripts as environment variables, dropping AWS_PROFILE', async () => {
      process.env.AWS_PROFILE = 'someone-else';
      try {
        answerStatus({ connected: true, account: '1', permissions: { ec2: true, s3: true, iam: true }, hasFullAccess: true });
        const result = await service.connectManualAws({ ...KEYS, region: 'ap-southeast-1' });

        const env = lastSpawnEnv();
        expect(env?.AWS_ACCESS_KEY_ID).toBe(KEYS.accessKeyId);
        expect(env?.AWS_SECRET_ACCESS_KEY).toBe(KEYS.secretAccessKey);
        expect(env?.AWS_DEFAULT_REGION).toBe('ap-southeast-1');
        expect(env?.AWS_PROFILE).toBeUndefined();
        expect(result.credentialSource).toBe('manual');
        expect(service.hasManualAwsCredentials()).toBe(true);

        // ...and the cloud scan uses them too
        const child = fakeChild();
        mockSpawn.mockReturnValueOnce(child as never);
        const scan = service.runAwsMonitor();
        child.emit('close', 0);
        await scan;
        expect(lastSpawnEnv()?.AWS_ACCESS_KEY_ID).toBe(KEYS.accessKeyId);
      } finally {
        delete process.env.AWS_PROFILE;
      }
    });

    it('does not keep keys that AWS rejects', async () => {
      answerStatus({ connected: false, message: 'InvalidClientTokenId' });
      const result = await service.connectManualAws(KEYS);

      expect(result.connected).toBe(false);
      expect(service.hasManualAwsCredentials()).toBe(false);
    });

    it('never returns the secret in the status response', async () => {
      answerStatus({ connected: true, account: '1', permissions: { ec2: true, s3: true, iam: true }, hasFullAccess: true });
      const result = await service.connectManualAws(KEYS);

      expect(JSON.stringify(result)).not.toContain(KEYS.secretAccessKey);
    });

    it('forgets the keys on disconnect and returns to the default chain', async () => {
      answerStatus({ connected: true, account: '1', permissions: { ec2: true, s3: true, iam: true }, hasFullAccess: true });
      await service.connectManualAws(KEYS);

      answerStatus({ connected: false, message: 'Unable to locate credentials' });
      const result = await service.disconnectManualAws();

      expect(service.hasManualAwsCredentials()).toBe(false);
      expect(lastSpawnEnv()).toBeUndefined();
      expect(result.credentialSource).toBe('default');
    });
  });
});
