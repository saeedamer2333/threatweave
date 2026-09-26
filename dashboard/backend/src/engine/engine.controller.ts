import { BadRequestException, Body, Controller, Delete, Get, Post } from '@nestjs/common';
import { EngineService, ManualAwsCredentials, validateManualAwsCredentials } from './engine.service';
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

  /**
   * Use keys typed on the Settings page for this session. Kept only if AWS
   * accepts them; the response is the resulting connection status (never
   * the keys themselves).
   */
  @Post('aws/credentials')
  async connectAws(@Body() body: Partial<ManualAwsCredentials>) {
    const problem = validateManualAwsCredentials(body ?? {});
    if (problem) throw new BadRequestException(problem);
    const status = await this.engine.connectManualAws(body as ManualAwsCredentials);
    if (!status.connected) {
      throw new BadRequestException(`AWS rejected these keys: ${status.message ?? 'unknown error'}`);
    }
    return status;
  }

  /** Forget the session keys and fall back to the default credential chain. */
  @Delete('aws/credentials')
  disconnectAws() {
    return this.engine.disconnectManualAws();
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
