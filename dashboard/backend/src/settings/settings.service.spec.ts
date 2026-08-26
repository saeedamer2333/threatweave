jest.mock('fs/promises');
jest.mock('fs');
jest.mock('../config/paths', () => ({
  PATHS: { findingsDir: '/fake/findings' },
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
      });
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
});
