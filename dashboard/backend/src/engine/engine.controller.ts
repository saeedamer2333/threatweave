import { Body, Controller, Get, Post } from '@nestjs/common';
import { EngineService } from './engine.service';
import { SettingsService } from '../settings/settings.service';

@Controller()
export class EngineController {
  constructor(
    private readonly engine: EngineService,
    private readonly settings: SettingsService,
  ) {}

  /** Kick off an engine run. Returns immediately; poll /scan/status. */
  @Post('scan')
  startScan() {
    return this.engine.startScan();
  }

  @Get('scan/status')
  scanStatus() {
    return this.engine.getStatus();
  }

  /** Settings page: is AWS reachable, and as which identity. */
  @Get('aws/status')
  awsStatus() {
    return this.engine.getAwsStatus();
  }

  /** Run the cloud checks now, honouring the saved region and check toggles. */
  @Post('aws/scan')
  async awsScan(@Body() body: { region?: string }) {
    const saved = await this.settings.get();
    const region = body?.region || saved.awsRegion || undefined;
    const checks = await this.settings.enabledChecks();
    return this.engine.runAwsMonitor(region, checks || undefined);
  }
}
