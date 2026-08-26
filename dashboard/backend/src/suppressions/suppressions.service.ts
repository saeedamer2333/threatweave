import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { readFile, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import { randomUUID } from 'crypto';
import { PATHS } from '../config/paths';

export interface SuppressionRule {
  id: string;
  created_at: string;
  created_by: string;
  reason: string;
  active: boolean;
  source?: string;
  rule_id?: string;
  cve_id?: string;
  type?: string;
  severity?: string;
  resource_pattern?: string;
  title_pattern?: string;
}

/** Conditions a rule may constrain. At least one is required. */
const CONDITION_KEYS = [
  'source',
  'rule_id',
  'cve_id',
  'type',
  'severity',
  'resource_pattern',
  'title_pattern',
] as const;

@Injectable()
export class SuppressionsService {
  private async readAll(): Promise<SuppressionRule[]> {
    if (!existsSync(PATHS.suppressionRules)) return [];
    const raw = await readFile(PATHS.suppressionRules, 'utf-8');
    const parsed = JSON.parse(raw);
    return parsed.rules ?? [];
  }

  private async writeAll(rules: SuppressionRule[]): Promise<void> {
    await writeFile(
      PATHS.suppressionRules,
      JSON.stringify({ rules }, null, 2),
      'utf-8',
    );
  }

  async list(includeRevoked = false): Promise<SuppressionRule[]> {
    const rules = await this.readAll();
    return includeRevoked ? rules : rules.filter((r) => r.active !== false);
  }

  /**
   * Create a rule. Written in the same shape the Python suppressor reads, so
   * the next engine run picks it up with no further wiring.
   */
  async create(input: Partial<SuppressionRule>): Promise<SuppressionRule> {
    if (!input.reason?.trim()) {
      throw new BadRequestException('A suppression needs a reason');
    }

    const conditions: Partial<SuppressionRule> = {};
    for (const key of CONDITION_KEYS) {
      const value = input[key];
      if (value) conditions[key] = value as never;
    }
    if (!Object.keys(conditions).length) {
      // Without this guard a rule would match every finding.
      throw new BadRequestException(
        'A suppression needs at least one matching condition',
      );
    }

    const rule: SuppressionRule = {
      id: `sup-${randomUUID().replace(/-/g, '').slice(0, 8)}`,
      created_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      created_by: input.created_by?.trim() || 'dashboard',
      reason: input.reason.trim(),
      active: true,
      ...conditions,
    };

    const rules = await this.readAll();
    rules.push(rule);
    await this.writeAll(rules);
    return rule;
  }

  /** Revoke rather than delete, so the decision stays auditable. */
  async revoke(id: string): Promise<SuppressionRule> {
    const rules = await this.readAll();
    const rule = rules.find((r) => r.id === id);
    if (!rule) throw new NotFoundException(`No suppression rule ${id}`);
    rule.active = false;
    await this.writeAll(rules);
    return rule;
  }

  async restore(id: string): Promise<SuppressionRule> {
    const rules = await this.readAll();
    const rule = rules.find((r) => r.id === id);
    if (!rule) throw new NotFoundException(`No suppression rule ${id}`);
    rule.active = true;
    await this.writeAll(rules);
    return rule;
  }
}
