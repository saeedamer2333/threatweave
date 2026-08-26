import { BadRequestException, NotFoundException } from '@nestjs/common';
import { SuppressionsService } from './suppressions.service';

jest.mock('fs/promises');
jest.mock('fs');
jest.mock('../config/paths', () => ({
  PATHS: { suppressionRules: '/fake/suppression_rules.json' },
}));

import { readFile, writeFile } from 'fs/promises';
import { existsSync } from 'fs';

const mockReadFile = readFile as jest.MockedFunction<typeof readFile>;
const mockWriteFile = writeFile as jest.MockedFunction<typeof writeFile>;
const mockExistsSync = existsSync as jest.MockedFunction<typeof existsSync>;

describe('SuppressionsService', () => {
  let service: SuppressionsService;

  beforeEach(() => {
    service = new SuppressionsService();
    jest.resetAllMocks();
  });

  describe('list', () => {
    it('returns an empty array when the rules file does not exist', async () => {
      mockExistsSync.mockReturnValue(false);
      expect(await service.list()).toEqual([]);
    });

    it('returns only active rules by default', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({
        rules: [
          { id: 'sup-1', active: true, reason: 'a' },
          { id: 'sup-2', active: false, reason: 'b' },
        ],
      }) as never);

      const result = await service.list();
      expect(result.map((r) => r.id)).toEqual(['sup-1']);
    });

    it('includes revoked rules when includeRevoked is true', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({
        rules: [
          { id: 'sup-1', active: true, reason: 'a' },
          { id: 'sup-2', active: false, reason: 'b' },
        ],
      }) as never);

      const result = await service.list(true);
      expect(result.map((r) => r.id)).toEqual(['sup-1', 'sup-2']);
    });
  });

  describe('create', () => {
    it('rejects a rule with no reason', async () => {
      await expect(service.create({ source: 'gitleaks' })).rejects.toThrow(BadRequestException);
    });

    it('rejects a rule with a reason but no matching condition', async () => {
      await expect(service.create({ reason: 'no conditions' })).rejects.toThrow(
        'A suppression needs at least one matching condition',
      );
    });

    it('creates a rule with a generated id, timestamp and active=true', async () => {
      mockExistsSync.mockReturnValue(false);
      mockWriteFile.mockResolvedValue(undefined as never);

      const rule = await service.create({ reason: 'test fixtures', source: 'gitleaks' });

      expect(rule.id).toMatch(/^sup-[0-9a-f]{8}$/);
      expect(rule.active).toBe(true);
      expect(rule.source).toBe('gitleaks');
      expect(rule.created_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
      expect(mockWriteFile).toHaveBeenCalledWith(
        '/fake/suppression_rules.json',
        expect.stringContaining('"gitleaks"'),
        'utf-8',
      );
    });

    it('defaults created_by to "dashboard" when not supplied', async () => {
      mockExistsSync.mockReturnValue(false);
      mockWriteFile.mockResolvedValue(undefined as never);

      const rule = await service.create({ reason: 'x', cve_id: 'CVE-2021-1' });
      expect(rule.created_by).toBe('dashboard');
    });

    it('appends to existing rules rather than overwriting them', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({
        rules: [{ id: 'sup-old', active: true, reason: 'existing' }],
      }) as never);
      mockWriteFile.mockResolvedValue(undefined as never);

      await service.create({ reason: 'new rule', type: 'SECRET' });

      const written = JSON.parse((mockWriteFile.mock.calls[0][1] as string));
      expect(written.rules).toHaveLength(2);
      expect(written.rules[0].id).toBe('sup-old');
    });
  });

  describe('revoke', () => {
    it('marks the matching rule inactive rather than deleting it', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({
        rules: [{ id: 'sup-1', active: true, reason: 'a' }],
      }) as never);
      mockWriteFile.mockResolvedValue(undefined as never);

      const result = await service.revoke('sup-1');

      expect(result.active).toBe(false);
      const written = JSON.parse((mockWriteFile.mock.calls[0][1] as string));
      expect(written.rules).toHaveLength(1);       // still present, not removed
      expect(written.rules[0].active).toBe(false);
    });

    it('throws NotFoundException for an unknown id', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({ rules: [] }) as never);

      await expect(service.revoke('sup-missing')).rejects.toThrow(NotFoundException);
    });
  });

  describe('restore', () => {
    it('marks a revoked rule active again', async () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFile.mockResolvedValue(JSON.stringify({
        rules: [{ id: 'sup-1', active: false, reason: 'a' }],
      }) as never);
      mockWriteFile.mockResolvedValue(undefined as never);

      const result = await service.restore('sup-1');
      expect(result.active).toBe(true);
    });
  });
});
