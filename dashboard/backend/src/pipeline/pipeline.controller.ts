import { Controller, Get, Post } from '@nestjs/common';
import { JenkinsService } from './jenkins.service';
import { SettingsService } from '../settings/settings.service';

@Controller('pipeline')
export class PipelineController {
  constructor(
    private readonly jenkins: JenkinsService,
    private readonly settings: SettingsService,
  ) {}

  /** Trigger the real Jenkins pipeline (scanners -> engine) using the
   * saved pipeline settings. Returns immediately; poll GET /pipeline/status. */
  @Post('run')
  async run() {
    const saved = await this.settings.get();
    return this.jenkins.triggerBuild(saved.pipeline);
  }

  @Get('status')
  status() {
    return this.jenkins.getStatus();
  }
}
