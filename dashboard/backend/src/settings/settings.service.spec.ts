jest.mock('fs/promises');
jest.mock('fs');
jest.mock('../config/paths', () => ({
  PATHS: { findingsDir: '/fake/findings', target: '/fake/target' },
}));

import { readFile, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { SettingsService } from './settings.service';

const SETTINGS_PATH = join('/fake/findings', 'settings.json');

const mockReadFile = readFile as jest.MockedFunction<typeof readFile>;
const mockWriteFile = writeFile as jest.MockedFunction<typeof writeFile>;
const mockExistsSync = existsSync as jest.MockedFunction<typeof existsSync>;

describe('SettingsService', () => {
  let service: SettingsService;

  beforeEach(() => {
    service = new SettingsService();
    jest.resetAllMocks();
  });

  describe('get', () => {
    it('returns built-in defaults when no settings file exists', async () => {
      mockExistsSync.mockReturnValue(false);
      const settings = await service.get();
      expect(settings).toEqual({
        awsRegion: '',
        checks: { ec2: true, sg: true, s3: true, iam: true },
        scanIntervalMinutes: 30,
        pipeline: {
          sourceDir: '/target/juice-shop',
          iacDir: '/workspace/infra',
          targetImage: 'bkimminich/juice-shop:latest',
          sonarProjectKey: 'threatweave-demo',
          runAwsMonitor: true,
          failOnCritical: false,
        },
      });
    });

    it('merges an older settings file missing the pipeline block entirely', async () => {
      mockExistsSync.mockReturnValue(true);
      // Simulates a settings.json written before pipeline settings existed.
      mockReadFile.mockResolvedValue(JSON.stringify({ awsRegion: 'eu-west-1' }) as never);

      const settings = await service.get();
      expect(settings.pipeline.sourceDir).toBe('/target/juice-shop');
      expect(settings.pipeline.targetImage).toBe('bkimminich/juice-shop:latest');
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
    it('suggests /target itself when there is no nested juice-shop demo folder', async () => {
      mockExistsSync.mockReturnValue(false);

      const result = await service.detectTarget();

      expect(result.sourceDir).toBe('/fake/target');
      expect(result.hasDockerfile).toBe(false);
      expect(result.projectName).toBeUndefined();
    });

    it('suggests /target/juice-shop when the bundled demo layout is detected', async () => {
      mockExistsSync.mockImplementation((p) => (p as string).endsWith('juice-shop'));

      const result = await service.detectTarget();

      expect(result.sourceDir).toBe(join('/fake/target', 'juice-shop'));
    });

    it("suggests a project key from the mounted project's package.json name", async () => {
      mockExistsSync.mockImplementation((p) => (p as string).endsWith('package.json'));
      mockReadFile.mockResolvedValue(JSON.stringify({ name: 'accesshub' }) as never);

      const result = await service.detectTarget();

      expect(result.projectName).toBe('accesshub');
    });

    it('sanitises a scoped npm package name into a valid SonarQube project key', async () => {
      mockExistsSync.mockImplementation((p) => (p as string).endsWith('package.json'));
      mockReadFile.mockResolvedValue(JSON.stringify({ name: '@my-org/my-app' }) as never);

      const result = await service.detectTarget();

      expect(result.projectName).toBe('-my-org-my-app');
    });

    it('reports no project name when there is no readable package.json', async () => {
      mockExistsSync.mockReturnValue(false);

      const result = await service.detectTarget();

      expect(result.projectName).toBeUndefined();
    });

    it('reports hasDockerfile true only when the target actually has one', async () => {
      mockExistsSync.mockImplementation((p) => (p as string).endsWith('Dockerfile'));

      const result = await service.detectTarget();

      expect(result.hasDockerfile).toBe(true);
    });

    it('does not throw when package.json exists but is not valid JSON', async () => {
      mockExistsSync.mockImplementation((p) => (p as string).endsWith('package.json'));
      mockReadFile.mockResolvedValue('{not valid json' as never);

      const result = await service.detectTarget();

      expect(result.projectName).toBeUndefined();
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
});
