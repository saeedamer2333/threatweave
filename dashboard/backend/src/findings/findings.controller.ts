import { Controller, Get, Param } from '@nestjs/common';
import { FindingsService } from './findings.service';

@Controller('findings')
export class FindingsController {
  constructor(private readonly findings: FindingsService) {}

  /** Full engine output: summary, clusters, findings, history. */
  @Get()
  getLatest() {
    return this.findings.getLatest();
  }

  @Get('clusters')
  getClusters() {
    return this.findings.getClusters();
  }

  @Get('history')
  getHistory() {
    return this.findings.getHistory();
  }

  @Get(':id')
  getOne(@Param('id') id: string) {
    return this.findings.getFinding(id);
  }
}
