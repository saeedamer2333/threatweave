import { AwsScheduleService } from './aws-schedule.service';
import { EngineService } from './engine.service';
import { SettingsService } from '../settings/settings.service';

function fakeSettings(overrides: Partial<{ scanIntervalMinutes: number; awsRegion: string }> = {}) {
  return {
    awsRegion: '',
    checks: { ec2: true, sg: true, s3: true, iam: true },
    scanIntervalMinutes: 30,
    pipeline: {} as never,
    ...overrides,
  };
}

describe('AwsScheduleService', () => {
  let service: AwsScheduleService;
  let engine: { getStatus: jest.Mock; runAwsMonitor: jest.Mock; startScan: jest.Mock };
  let settings: { get: jest.Mock; enabledChecks: jest.Mock };

  beforeEach(() => {
    jest.useFakeTimers();
    engine = {
      getStatus: jest.fn().mockReturnValue({ state: 'idle', log: [] }),
      runAwsMonitor: jest.fn().mockResolvedValue({ ok: true, log: [] }),
      startScan: jest.fn(),
    };
    settings = {
      get: jest.fn().mockResolvedValue(fakeSettings()),
      enabledChecks: jest.fn().mockResolvedValue('ec2,sg,s3,iam'),
    };
    service = new AwsScheduleService(engine as unknown as EngineService, settings as unknown as SettingsService);
  });

  afterEach(() => {
    service.onModuleDestroy();
    jest.clearAllTimers();
    jest.useRealTimers();
  });

  it('does nothing on the very first tick - a run is only due once a full interval has elapsed', async () => {
    service.onModuleInit();
    await jest.advanceTimersByTimeAsync(60_000);

    expect(engine.runAwsMonitor).not.toHaveBeenCalled();
  });

  // ---- Regression: confirmed live - scanIntervalMinutes was a real,
  // editable Settings field with nothing behind it at all. This locks in
  // that 0 (its documented "disabled" value) genuinely disables the
  // schedule rather than being silently ignored.
  it('never runs when scanIntervalMinutes is 0 (disabled)', async () => {
    settings.get.mockResolvedValue(fakeSettings({ scanIntervalMinutes: 0 }));
    service.onModuleInit();

    await jest.advanceTimersByTimeAsync(60 * 60_000); // a full hour of ticks

    expect(engine.runAwsMonitor).not.toHaveBeenCalled();
  });

  it('runs the AWS monitor and folds results in once the configured interval has elapsed', async () => {
    settings.get.mockResolvedValue(fakeSettings({ scanIntervalMinutes: 1, awsRegion: 'eu-west-1' }));
    service.onModuleInit();

    await jest.advanceTimersByTimeAsync(60_000); // first tick: not due yet (lastRunAt starts at 0, but "due" is relative to it)
    await jest.advanceTimersByTimeAsync(60_000); // interval has now elapsed

    expect(engine.runAwsMonitor).toHaveBeenCalledWith('eu-west-1', 'ec2,sg,s3,iam');
    expect(engine.startScan).toHaveBeenCalled();
  });

  it('skips a due cycle rather than racing an already-in-progress scan', async () => {
    engine.getStatus.mockReturnValue({ state: 'running', log: [] });
    settings.get.mockResolvedValue(fakeSettings({ scanIntervalMinutes: 1 }));
    service.onModuleInit();

    await jest.advanceTimersByTimeAsync(120_000);

    expect(engine.runAwsMonitor).not.toHaveBeenCalled();
  });

  it('does not fold results in when the AWS monitor call itself fails', async () => {
    engine.runAwsMonitor.mockResolvedValue({ ok: false, log: ['boom'] });
    settings.get.mockResolvedValue(fakeSettings({ scanIntervalMinutes: 1 }));
    service.onModuleInit();

    await jest.advanceTimersByTimeAsync(120_000);

    expect(engine.runAwsMonitor).toHaveBeenCalled();
    expect(engine.startScan).not.toHaveBeenCalled();
  });

  it('stops ticking once destroyed', async () => {
    settings.get.mockResolvedValue(fakeSettings({ scanIntervalMinutes: 1 }));
    service.onModuleInit();
    service.onModuleDestroy();

    await jest.advanceTimersByTimeAsync(10 * 60_000);

    expect(engine.runAwsMonitor).not.toHaveBeenCalled();
  });
});
