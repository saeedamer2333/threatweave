import { Injectable, Logger, OnModuleDestroy, OnModuleInit, Optional } from '@nestjs/common';
import { EngineService } from './engine.service';
import { SettingsService } from '../settings/settings.service';
import { JenkinsService } from '../pipeline/jenkins.service';

/** How often to check whether an interval AWS scan is due. Deliberately
 * much finer-grained than any realistic scanIntervalMinutes value (the
 * Settings page's own minimum is far above a minute) - this just needs to
 * notice "it's time" reasonably promptly, not match the interval itself. */
const CHECK_MS = 60_000;

/**
 * Runs AWS cloud governance checks on their own schedule, independent of
 * the code-scanning pipeline entirely.
 *
 * Before this existed, `scanIntervalMinutes` was a real, editable Settings
 * field with nothing behind it - AWS monitoring only ever ran as a side
 * effect of a real (non-skipped) pipeline run, or a one-off manual "Run
 * cloud scan" click. That is a genuine coverage gap this project's own
 * stated purpose depends on closing: cloud misconfigurations (an opened
 * security group, a bucket made public) happen directly in AWS, with no
 * code change involved at all, so a pipeline that only re-checks AWS when
 * the *target's source code* changes can miss real drift indefinitely.
 *
 * Each tick that finds an interval scan due: runs the AWS monitor with the
 * saved region/checks (the same call the manual button makes, so it
 * benefits from the same --output fix), then folds the result into the
 * dashboard with the same fast local re-score already used elsewhere
 * (suppression changes) rather than requiring a full pipeline run just to
 * see it reflected.
 */
@Injectable()
export class AwsScheduleService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(AwsScheduleService.name);
  private timer?: ReturnType<typeof setInterval>;
  private lastRunAt = 0;
  /** Highest successful pipeline build already refreshed with session keys. */
  private lastRefreshedBuild?: number;

  constructor(
    private readonly engine: EngineService,
    private readonly settings: SettingsService,
    @Optional() private readonly jenkins?: JenkinsService,
  ) {}

  onModuleInit(): void {
    // Counted from startup, not from epoch 0 - otherwise the very first
    // check after every restart (including every redeploy during
    // development) would find a run immediately "due" and fire right
    // away, rather than genuinely waiting out one full interval first.
    this.lastRunAt = Date.now();
    this.timer = setInterval(() => void this.tick(), CHECK_MS);
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  /**
   * Keys typed on the Settings page live only in this API process, so the
   * AWS monitor inside a Jenkins run cannot use them - and Checkout clears
   * the previous aws-findings.json. When session keys are active and a new
   * pipeline build has succeeded, re-run the cloud checks here with those
   * keys and fold them in, so the run's AWS results are not lost.
   */
  private async refreshAfterPipeline(): Promise<boolean> {
    if (!this.jenkins || !this.engine.hasManualAwsCredentials()) return false;
    const status = this.jenkins.getStatus();
    if (status.state !== 'success' || status.buildNumber === undefined) return false;
    if (this.lastRefreshedBuild !== undefined && status.buildNumber <= this.lastRefreshedBuild) return false;
    if (this.engine.getStatus().state === 'running') return false;

    this.lastRefreshedBuild = status.buildNumber;
    const { awsRegion } = await this.settings.get();
    const checks = await this.settings.enabledChecks();
    const result = await this.engine.runAwsMonitor(awsRegion || undefined, checks || undefined);
    if (!result.ok) {
      this.logger.warn(`AWS refresh after build #${status.buildNumber} failed: ${result.log.join(' | ')}`);
      return false;
    }
    this.engine.startScan();
    return true;
  }

  private async tick(): Promise<void> {
    try {
      if (await this.refreshAfterPipeline()) {
        this.lastRunAt = Date.now();
        return;
      }
      const { scanIntervalMinutes, awsRegion } = await this.settings.get();
      // 0 (or anything non-positive) disables the schedule, as already
      // documented on the field itself.
      if (!(scanIntervalMinutes > 0)) return;

      const dueAt = this.lastRunAt + scanIntervalMinutes * 60_000;
      if (Date.now() < dueAt) return;

      // A scan already in flight (someone's own manual click, or the
      // pipeline's local re-score) takes priority - this cycle is skipped
      // rather than queued, and picked up again next tick instead of
      // racing the in-progress one for the same output files.
      if (this.engine.getStatus().state === 'running') return;

      this.lastRunAt = Date.now();
      const checks = await this.settings.enabledChecks();
      const result = await this.engine.runAwsMonitor(awsRegion || undefined, checks || undefined);
      if (!result.ok) {
        this.logger.warn(`Scheduled AWS scan failed: ${result.log.join(' | ')}`);
        return;
      }
      this.engine.startScan();
    } catch (err) {
      this.logger.warn(`Scheduled AWS scan tick failed: ${(err as Error).message}`);
    }
  }
}
