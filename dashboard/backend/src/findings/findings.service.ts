import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { PATHS } from '../config/paths';

export interface AiopsOutput {
  run_id: string;
  generated_at: string;
  health_score: number;
  summary: Record<string, number>;
  suppressions?: unknown[];
  clusters: any[];
  findings: any[];
  history?: any[];
}

@Injectable()
export class FindingsService {
  private readonly logger = new Logger(FindingsService.name);

  /** Latest engine output, with history merged in when available. */
  async getLatest(): Promise<AiopsOutput> {
    if (!existsSync(PATHS.aiopsOutput)) {
      throw new NotFoundException(
        'No scan results yet. Run a scan to generate findings.',
      );
    }

    const raw = await readFile(PATHS.aiopsOutput, 'utf-8');
    const output = JSON.parse(raw) as AiopsOutput;

    const history = await this.getHistory();
    if (history.length) {
      output.history = history;
    }
    return output;
  }

  /** Health-score trend across previous runs. Absent file is not an error. */
  async getHistory(): Promise<any[]> {
    if (!existsSync(PATHS.history)) return [];
    try {
      const raw = await readFile(PATHS.history, 'utf-8');
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : (parsed.runs ?? []);
    } catch (err) {
      this.logger.warn(`Could not read history: ${err}`);
      return [];
    }
  }

  /** A single finding by id, for the detail view. */
  async getFinding(id: string) {
    const output = await this.getLatest();
    const finding = output.findings.find((f) => f.id === id);
    if (!finding) {
      throw new NotFoundException(`Finding ${id} not found`);
    }
    return finding;
  }

  async getClusters() {
    const output = await this.getLatest();
    return output.clusters;
  }
}
