import { Body, Controller, Get, Put, Query } from '@nestjs/common';
import { AppSettings, SettingsService } from './settings.service';

@Controller('settings')
export class SettingsController {
  constructor(private readonly settings: SettingsService) {}

  @Get()
  get() {
    return this.settings.get();
  }

  @Get('detect-target')
  detectTarget() {
    return this.settings.detectTarget();
  }

  /** Confirms a typed path: ?kind=iac|source&path=/target/... */
  @Get('check-path')
  checkPath(@Query('kind') kind: string, @Query('path') path: string) {
    return this.settings.checkPath(kind, path);
  }

  @Get('sonarqube-status')
  checkSonarQubeStatus() {
    return this.settings.checkSonarQubeStatus();
  }

  @Get('sonarqube-scan-status')
  checkAsyncSonarScan() {
    return this.settings.checkAsyncSonarScan();
  }

  @Put()
  update(@Body() body: Partial<AppSettings>) {
    return this.settings.update(body);
  }
}
