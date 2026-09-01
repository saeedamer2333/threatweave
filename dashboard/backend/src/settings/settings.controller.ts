import { Body, Controller, Get, Put } from '@nestjs/common';
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
