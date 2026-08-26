import { NotFoundException } from '@nestjs/common';

jest.mock('fs/promises');
jest.mock('fs');
jest.mock('../config/paths', () => ({
  PATHS: { aiopsOutput: '/fake/aiops-output.json', history: '/fake/history.json' },
}));

import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { FindingsService } from './findings.service';

const mockReadFile = readFile as jest.MockedFunction<typeof readFile>;
const mockExistsSync = existsSync as jest.MockedFunction<typeof existsSync>;

const SAMPLE_OUTPUT = {
  run_id: 'run-9', generated_at: '2026-08-24T16:03:53Z', health_score: 15,
  summary: { raw_findings: 629, after_dedup: 132 },
  clusters: [{ cluster_id: 'cluster-1', title: 'Internet-exposed asset', finding_ids: ['f-1'] }],
  findings: [{ id: 'f-1', title: 'Vulnerable dependency', severity: 'CRITICAL' }],
};

describe('FindingsService', () => {
  let service: FindingsService;

  beforeEach(() => {
    service = new FindingsService();
    jest.resetAllMocks();
  });

  describe('getLatest', () => {
    it('throws NotFoundException when no scan has ever run', async () => {
      mockExistsSync.mockReturnValue(false);
      await expect(service.getLatest()).rejects.toThrow(NotFoundException);
    });

    it('returns the parsed aiops-output.json when it exists', async () => {
      mockExistsSync.mockImplementation((p) => String(p) === '/fake/aiops-output.json');
      mockReadFile.mockResolvedValue(JSON.stringify(SAMPLE_OUTPUT) as never);

      const result = await service.getLatest();
      expect(result.run_id).toBe('run-9');
      expect(result.health_score).toBe(15);
    });

    it('merges history into the output when history exists', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockImplementation((path) => {
        if (String(path) === '/fake/aiops-output.json') {
          return Promise.resolve(JSON.stringify(SAMPLE_OUTPUT)) as never;
        }
        return Promise.resolve(JSON.stringify({ runs: [{ run_id: 'run-8', health_score: 23 }] })) as never;
      });

      const result = await service.getLatest();
      expect(result.history).toEqual([{ run_id: 'run-8', health_score: 23 }]);
    });

    it('omits history when the history file does not exist', async () => {
      mockExistsSync.mockImplementation((p) => String(p) === '/fake/aiops-output.json');
      mockReadFile.mockResolvedValue(JSON.stringify(SAMPLE_OUTPUT) as never);

      const result = await service.getLatest();
      expect(result.history).toBeUndefined();
    });
  });

  describe('getHistory', () => {
    it('returns an empty array when history.json does not exist, not an error', async () => {
      mockExistsSync.mockReturnValue(false);
      expect(await service.getHistory()).toEqual([]);
    });

    it('supports both a bare array and a {runs: [...]} shape', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify([{ run_id: 'a' }]) as never);
      expect(await service.getHistory()).toEqual([{ run_id: 'a' }]);

      mockReadFile.mockResolvedValue(JSON.stringify({ runs: [{ run_id: 'b' }] }) as never);
      expect(await service.getHistory()).toEqual([{ run_id: 'b' }]);
    });

    it('returns an empty array rather than throwing when the file is corrupt', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue('{not valid json' as never);
      expect(await service.getHistory()).toEqual([]);
    });
  });

  describe('getFinding', () => {
    it('returns the finding matching the given id', async () => {
      mockExistsSync.mockImplementation((p) => String(p) === '/fake/aiops-output.json');
      mockReadFile.mockResolvedValue(JSON.stringify(SAMPLE_OUTPUT) as never);

      const finding = await service.getFinding('f-1');
      expect(finding.title).toBe('Vulnerable dependency');
    });

    it('throws NotFoundException for an id that does not exist in the latest run', async () => {
      mockExistsSync.mockImplementation((p) => String(p) === '/fake/aiops-output.json');
      mockReadFile.mockResolvedValue(JSON.stringify(SAMPLE_OUTPUT) as never);

      await expect(service.getFinding('f-missing')).rejects.toThrow(NotFoundException);
    });
  });

  describe('getClusters', () => {
    it('returns the clusters array from the latest run', async () => {
      mockExistsSync.mockImplementation((p) => String(p) === '/fake/aiops-output.json');
      mockReadFile.mockResolvedValue(JSON.stringify(SAMPLE_OUTPUT) as never);

      const clusters = await service.getClusters();
      expect(clusters).toHaveLength(1);
      expect(clusters[0].cluster_id).toBe('cluster-1');
    });
  });
});
