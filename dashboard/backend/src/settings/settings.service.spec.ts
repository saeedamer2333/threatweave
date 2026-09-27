jest.mock('fs/promises');
jest.mock('fs');
jest.mock('http');
jest.mock('child_process');
jest.mock('../config/paths', () => ({
  PATHS: { findingsDir: '/fake/findings', target: '/fake/target', engineDir: '/fake/engine', python: 'python3' },
}));

import { readFile, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import * as http from 'http';
import { execFile } from 'child_process';
import type { IncomingMessage, ClientRequest } from 'http';
import { SettingsService } from './settings.service';

const mockHttpRequest = http.request as jest.MockedFunction<typeof http.request>;

/** Simulates the Docker Engine API's response to a `dockerGet` call - a
 * real `http.request` callback receives an IncomingMessage that emits
 * 'data'/'end', not something a Promise-based mock can stand in for
 * directly. */
function mockDockerResponse(statusCode: number, body: unknown) {
  mockHttpRequest.mockImplementation(((_opts: unknown, callback: (res: Partial<IncomingMessage>) => void) => {
    const listeners: Record<string, (arg?: unknown) => void> = {};
    const res: Partial<IncomingMessage> = {
      statusCode,
      on: ((event: string, handler: (arg?: unknown) => void) => {
        listeners[event] = handler;
        return res as IncomingMessage;
      }) as IncomingMessage['on'],
    };
    callback(res);
    listeners.data?.(Buffer.from(JSON.stringify(body)));
    listeners.end?.();
    return { on: jest.fn(), end: jest.fn(), destroy: jest.fn() } as unknown as ClientRequest;
  }) as typeof http.request);
}

function mockDockerSocketError(message: string) {
  mockHttpRequest.mockImplementation(((_opts: unknown, _callback: unknown) => {
    const listeners: Record<string, (arg?: unknown) => void> = {};
    const req = {
      on: ((event: string, handler: (arg?: unknown) => void) => {
        listeners[event] = handler;
        return req;
      }) as unknown,
      end: jest.fn(() => listeners.error?.(new Error(message))),
      destroy: jest.fn(),
    };
    return req as unknown as ClientRequest;
  }) as typeof http.request);
}

const SETTINGS_PATH = join('/fake/findings', 'settings.json');

const mockReadFile = readFile as jest.MockedFunction<typeof readFile>;
const mockWriteFile = writeFile as jest.MockedFunction<typeof writeFile>;
const mockExistsSync = existsSync as jest.MockedFunction<typeof existsSync>;
const mockExecFile = execFile as unknown as jest.Mock;

describe('SettingsService', () => {
  let service: SettingsService;

  beforeEach(() => {
    service = new SettingsService();
    jest.resetAllMocks();
  });

  describe('get', () => {
    // A fresh install must not scan anything it was not told to - in
    // particular not the Juice Shop demo this project was developed against.
    it('returns empty scan targets by default, so a fresh install scans nothing it was not told to', async () => {
      mockExistsSync.mockReturnValue(false);
      const settings = await service.get();
      expect(settings).toEqual({
        awsRegion: '',
        checks: { ec2: true, sg: true, s3: true, iam: true },
        scanIntervalMinutes: 30,
        pipeline: {
          sourceDir: '',
          iacDir: '',
          targetImage: '',
          sonarProjectKey: '',
          runAwsMonitor: true,
          failOnCritical: false,
        },
        pipelineOrigin: { sourceDir: 'none', iacDir: 'none', targetImage: 'none', sonarProjectKey: 'none' },
      });
    });

    it('takes default scan targets from SCAN_* environment variables when set', async () => {
      const saved = { ...process.env };
      Object.assign(process.env, {
        SCAN_SOURCE_DIR: '/target', SCAN_IAC_DIR: '/target/infra',
        SCAN_IMAGE: 'me/app:1.0', SCAN_SONAR_KEY: 'my-app',
      });
      try {
        mockExistsSync.mockReturnValue(false);
        const { pipeline } = await service.get();
        expect(pipeline).toEqual(expect.objectContaining({
          sourceDir: '/target', iacDir: '/target/infra', targetImage: 'me/app:1.0', sonarProjectKey: 'my-app',
        }));
      } finally {
        process.env = saved;
      }
    });

    it('keeps a saved choice over the environment defaults', async () => {
      const saved = { ...process.env };
      process.env.SCAN_SOURCE_DIR = '/target';
      try {
        mockExistsSync.mockReturnValue(true);
        mockReadFile.mockResolvedValue(JSON.stringify({ pipeline: { sourceDir: '/target/juice-shop' } }) as never);
        const { pipeline } = await service.get();
        expect(pipeline.sourceDir).toBe('/target/juice-shop');
      } finally {
        process.env = saved;
      }
    });

    it('merges an older settings file missing the pipeline block entirely', async () => {
      mockExistsSync.mockReturnValue(true);
      // Simulates a settings.json written before pipeline settings existed.
      mockReadFile.mockResolvedValue(JSON.stringify({ awsRegion: 'eu-west-1' }) as never);

      const settings = await service.get();
      expect(settings.pipeline.sourceDir).toBe('');
      expect(settings.pipeline.targetImage).toBe('');
      expect(settings.pipeline.runAwsMonitor).toBe(true);
    });

    it('merges a saved settings file over the defaults', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({ awsRegion: 'eu-west-1' }) as never);

      const settings = await service.get();
      expect(settings.awsRegion).toBe('eu-west-1');
      expect(settings.scanIntervalMinutes).toBe(30);       // default still applied
    });

    it('merges an older settings file missing newer check keys', async () => {
      mockExistsSync.mockReturnValue(true);
      // Simulates a settings.json written before the IAM check existed.
      mockReadFile.mockResolvedValue(JSON.stringify({
        checks: { ec2: false, sg: true, s3: true },
      }) as never);

      const settings = await service.get();
      expect(settings.checks).toEqual({ ec2: false, sg: true, s3: true, iam: true });
    });

    it('falls back to defaults when the settings file is corrupt', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue('{not valid json' as never);

      const settings = await service.get();
      expect(settings.awsRegion).toBe('');
    });
  });

  describe('update', () => {
    it('applies a partial patch without touching unrelated fields', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({
        awsRegion: 'us-east-1',
        checks: { ec2: true, sg: true, s3: true, iam: true },
        scanIntervalMinutes: 15,
      }) as never);
      mockWriteFile.mockResolvedValue(undefined as never);

      const result = await service.update({ awsRegion: 'ap-southeast-1' });

      expect(result.awsRegion).toBe('ap-southeast-1');
      expect(result.scanIntervalMinutes).toBe(15);          // untouched by the patch
    });

    it('merges the nested checks object rather than replacing it wholesale', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({
        awsRegion: '', checks: { ec2: true, sg: true, s3: true, iam: true }, scanIntervalMinutes: 30,
      }) as never);
      mockWriteFile.mockResolvedValue(undefined as never);

      // This is the exact bug a naive single-level spread would introduce:
      // patching only s3 must not silently drop ec2/sg/iam.
      const result = await service.update({ checks: { s3: false } as never });

      expect(result.checks).toEqual({ ec2: true, sg: true, s3: false, iam: true });
    });

    it('merges the nested pipeline object rather than replacing it wholesale', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({
        pipeline: {
          sourceDir: '/target/juice-shop', iacDir: '/workspace/infra',
          targetImage: 'bkimminich/juice-shop:latest', sonarProjectKey: 'threatweave-demo',
          runAwsMonitor: true, failOnCritical: false,
        },
      }) as never);
      mockWriteFile.mockResolvedValue(undefined as never);

      const result = await service.update({ pipeline: { sourceDir: '/target/my-app' } as never });

      expect(result.pipeline.sourceDir).toBe('/target/my-app');
      expect(result.pipeline.targetImage).toBe('bkimminich/juice-shop:latest'); // untouched
    });

    it('persists the merged result to disk', async () => {
      mockExistsSync.mockReturnValue(false);
      mockWriteFile.mockResolvedValue(undefined as never);

      await service.update({ awsRegion: 'eu-central-1' });

      expect(mockWriteFile).toHaveBeenCalledWith(
        SETTINGS_PATH,
        expect.stringContaining('eu-central-1'),
        'utf-8',
      );
    });
  });

  describe('enabledChecks', () => {
    it('returns a comma-separated list of the checks currently on', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({
        checks: { ec2: true, sg: false, s3: true, iam: false },
      }) as never);

      expect(await service.enabledChecks()).toBe('ec2,s3');
    });

    it('returns an empty string when every check is disabled', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({
        checks: { ec2: false, sg: false, s3: false, iam: false },
      }) as never);

      expect(await service.enabledChecks()).toBe('');
    });
  });

  describe('detectTarget', () => {
    // Detection itself lives in aiops_engine/target_detect.py (tested there),
    // shared with the all-in-one image's startup - these cover the API's use of it.
    function pythonAnswers(stdout: string, err: Error | null = null) {
      mockExecFile.mockImplementation(((_cmd: string, _args: string[], _opts: unknown, cb: (e: Error | null, out: string) => void) => {
        cb(err, stdout);
        return {} as never;
      }) as never);
    }

    it('runs the shared Python detection against the mounted project', async () => {
      pythonAnswers(JSON.stringify({
        sourceDir: '/fake/target', projectName: 'accesshub', hasDockerfile: false,
        iacDir: '/fake/target/infra/cdk.out',
        iacCandidates: [{ path: '/fake/target/infra/cdk.out', kind: 'cdk', files: 3 }],
      }));

      const result = await service.detectTarget();

      const [cmd, args] = mockExecFile.mock.calls[0] as unknown as [string, string[]];
      expect(cmd).toBe('python3');
      expect(args).toEqual([join('/fake/engine', 'target_detect.py'), 'targets', '--root', '/fake/target']);
      expect(result.projectName).toBe('accesshub');
      expect(result.iacCandidates[0].kind).toBe('cdk');
    });

    it('suggests nothing, rather than failing the page, when detection itself fails', async () => {
      pythonAnswers('', new Error('python3 not found'));

      const result = await service.detectTarget();

      expect(result).toEqual({ sourceDir: '', hasDockerfile: false, iacCandidates: [] });
    });
  });

  describe('checkPath', () => {
    function pythonAnswers(stdout: string) {
      mockExecFile.mockImplementation(((_cmd: string, _args: string[], _opts: unknown, cb: (e: Error | null, out: string) => void) => {
        cb(null, stdout);
        return {} as never;
      }) as never);
    }

    it('passes the kind and typed path to the shared check', async () => {
      pythonAnswers(JSON.stringify({ ok: false, level: 'error', message: '/target/deply does not exist.' }));

      const result = await service.checkPath('iac', '/target/deply');

      const [, args] = mockExecFile.mock.calls[0] as unknown as [string, string[]];
      expect(args.slice(1)).toEqual(['check', '--kind', 'iac', '--path', '/target/deply']);
      expect(result.level).toBe('error');
    });

    it('rejects an unknown kind without running anything', async () => {
      const result = await service.checkPath('rm -rf', '/target');

      expect(result.ok).toBe(false);
      expect(mockExecFile).not.toHaveBeenCalled();
    });
  });

  describe('pipelineOrigin', () => {
    const saved = { ...process.env };
    afterEach(() => { process.env = { ...saved }; });

    it('labels values filled by startup detection, given at install, and left empty', async () => {
      Object.assign(process.env, {
        SCAN_SOURCE_DIR: '/target', SCAN_IAC_DIR: '/target/infra/cdk.out', SCAN_SONAR_KEY: 'accesshub',
        SCAN_DETECTED: 'SCAN_SOURCE_DIR,SCAN_IAC_DIR',
      });
      delete process.env.SCAN_IMAGE;
      mockExistsSync.mockReturnValue(false);

      const { pipelineOrigin } = await service.get();

      expect(pipelineOrigin).toEqual({
        sourceDir: 'detected', iacDir: 'detected', sonarProjectKey: 'install', targetImage: 'none',
      });
    });

    it('labels a field the user saved in Settings, and only that field', async () => {
      process.env.SCAN_SOURCE_DIR = '/target';
      process.env.SCAN_DETECTED = 'SCAN_SOURCE_DIR';
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({
        pipeline: { iacDir: '/target/deploy' }, pipelineUserSet: ['iacDir'],
      }) as never);

      const result = await service.get();

      expect(result.pipeline.iacDir).toBe('/target/deploy');
      expect(result.pipelineOrigin?.iacDir).toBe('saved');
      expect(result.pipelineOrigin?.sourceDir).toBe('detected');
    });

    it('saves only the fields the user changed, so detected values keep following detection', async () => {
      process.env.SCAN_SOURCE_DIR = '/target';
      process.env.SCAN_IAC_DIR = '/target/infra/cdk.out';
      process.env.SCAN_DETECTED = 'SCAN_SOURCE_DIR,SCAN_IAC_DIR';
      mockExistsSync.mockReturnValue(false);
      mockWriteFile.mockResolvedValue(undefined as never);

      const result = await service.update({ pipeline: { targetImage: 'accesshub:latest' } as never });

      const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
      expect(written.pipeline).toEqual({ targetImage: 'accesshub:latest' });
      expect(written.pipelineUserSet).toEqual(['targetImage']);
      expect(result.pipeline.iacDir).toBe('/target/infra/cdk.out');
      expect(result.pipelineOrigin?.targetImage).toBe('saved');
      expect(result.pipelineOrigin?.iacDir).toBe('detected');
    });

    it('treats every saved pipeline value in an older settings file as the user\'s choice', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({ pipeline: { sourceDir: '/target/juice-shop' } }) as never);

      const { pipelineOrigin } = await service.get();

      expect(pipelineOrigin?.sourceDir).toBe('saved');
    });
  });

  describe('checkSonarQubeStatus', () => {
    const originalEnv = process.env.SONARQUBE_AUTOSTART;
    const originalFetch = global.fetch;

    afterEach(() => {
      process.env.SONARQUBE_AUTOSTART = originalEnv;
      global.fetch = originalFetch;
    });

    it('is not relevant when SONARQUBE_AUTOSTART is not true (e.g. split docker-compose deployment)', async () => {
      process.env.SONARQUBE_AUTOSTART = 'false';
      mockExistsSync.mockReturnValue(true);

      const result = await service.checkSonarQubeStatus();

      expect(result).toEqual({ relevant: false, healthy: false });
    });

    it('is not relevant when this is not the all-in-one image (/opt/sonarqube absent)', async () => {
      process.env.SONARQUBE_AUTOSTART = 'true';
      mockExistsSync.mockReturnValue(false);

      const result = await service.checkSonarQubeStatus();

      expect(result).toEqual({ relevant: false, healthy: false });
    });

    it('is not relevant while still on its first boot (no marker file yet)', async () => {
      process.env.SONARQUBE_AUTOSTART = 'true';
      mockExistsSync.mockImplementation((p) => (p as string) === '/opt/sonarqube');

      const result = await service.checkSonarQubeStatus();

      expect(result).toEqual({ relevant: false, healthy: false });
    });

    it('is not relevant when the marker was written empty (autoconfig never confirmed SonarQube up)', async () => {
      process.env.SONARQUBE_AUTOSTART = 'true';
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue('' as never);

      const result = await service.checkSonarQubeStatus();

      expect(result).toEqual({ relevant: false, healthy: false });
    });

    it('reports healthy when SonarQube responds UP after having been confirmed up once', async () => {
      process.env.SONARQUBE_AUTOSTART = 'true';
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue('SONAR_HOST_URL=http://localhost:9000\nSONAR_TOKEN=squ_x' as never);
      global.fetch = jest.fn().mockResolvedValue({
        json: async () => ({ status: 'UP' }),
      } as never);

      const result = await service.checkSonarQubeStatus();

      expect(result).toEqual({ relevant: true, healthy: true });
    });

    it('reports an OOM crash when unreachable and the logs show OutOfMemoryError', async () => {
      process.env.SONARQUBE_AUTOSTART = 'true';
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockImplementation(async (p) => {
        const path = p as string;
        if (path.endsWith('.sonar-env')) return 'SONAR_HOST_URL=http://localhost:9000\nSONAR_TOKEN=squ_x';
        if (path.endsWith('es.log')) return 'some line\njava.lang.OutOfMemoryError: Java heap space\n';
        return '';
      });
      global.fetch = jest.fn().mockRejectedValue(new Error('connect ECONNREFUSED'));

      const result = await service.checkSonarQubeStatus();

      expect(result).toEqual({
        relevant: true,
        healthy: false,
        crashReason: 'oom',
        message: 'SonarQube ran out of memory and stopped.',
      });
    });

    it('reports an unknown-cause failure when unreachable with no OOM signature in the logs', async () => {
      process.env.SONARQUBE_AUTOSTART = 'true';
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockImplementation(async (p) => {
        const path = p as string;
        if (path.endsWith('.sonar-env')) return 'SONAR_HOST_URL=http://localhost:9000\nSONAR_TOKEN=squ_x';
        return 'nothing unusual here\n';
      });
      global.fetch = jest.fn().mockRejectedValue(new Error('connect ECONNREFUSED'));

      const result = await service.checkSonarQubeStatus();

      expect(result).toEqual({
        relevant: true,
        healthy: false,
        crashReason: 'other',
        message: 'SonarQube was running but is not responding now.',
      });
    });
  });

  describe('checkAsyncSonarScan', () => {
    it('reports not scanning when no scan has ever been launched (no marker file)', async () => {
      mockExistsSync.mockReturnValue(false);

      const result = await service.checkAsyncSonarScan();

      expect(result).toEqual({ scanning: false });
    });

    it('reports not scanning when the marker file is unparsable', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue('not json' as never);

      const result = await service.checkAsyncSonarScan();

      expect(result).toEqual({ scanning: false });
    });

    it('reports genuinely running when the container is still going', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({
        container: 'sonar-scan-pending',
        run_id: 'build-232',
        started_at_epoch_ms: Date.now() - 3 * 60_000,
      }) as never);
      mockDockerResponse(200, { State: { Running: true } });

      const result = await service.checkAsyncSonarScan();

      expect(result).toEqual({ scanning: true, phase: 'running', runId: 'build-232', ageMinutes: 3 });
    });

    it('distinguishes "finished, waiting for a build to harvest it" from genuinely running', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({
        container: 'sonar-scan-pending',
        run_id: 'build-232',
        started_at_epoch_ms: Date.now() - 6 * 60_000,
      }) as never);
      mockDockerResponse(200, { State: { Running: false } });

      const result = await service.checkAsyncSonarScan();

      expect(result).toEqual({ scanning: true, phase: 'finished-pending-harvest', runId: 'build-232', ageMinutes: 6 });
    });

    it('reports not scanning when the marker points at a container that no longer exists (stale marker)', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({ container: 'sonar-scan-pending', run_id: 'build-1' }) as never);
      mockDockerResponse(404, { message: 'No such container' });

      const result = await service.checkAsyncSonarScan();

      expect(result).toEqual({ scanning: false });
    });

    it('reports not scanning rather than throwing when the Docker socket is unreachable', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({ container: 'sonar-scan-pending', run_id: 'build-1' }) as never);
      mockDockerSocketError('connect ENOENT /var/run/docker.sock');

      const result = await service.checkAsyncSonarScan();

      expect(result).toEqual({ scanning: false });
    });
  });
});
