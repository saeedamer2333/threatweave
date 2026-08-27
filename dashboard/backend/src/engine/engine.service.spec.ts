jest.mock('child_process');
jest.mock('../config/paths', () => ({
  PATHS: {
    python: 'python3',
    engineDir: '/fake/aiops_engine',
    findingsDir: '/fake/findings',
    aiopsOutput: '/fake/findings/aiops-output.json',
    history: '/fake/findings/history.json',
    projectRoot: '/fake',
    awsMonitor: '/fake/aws_monitor/monitor.py',
  },
}));

import { spawn } from 'child_process';
import { EventEmitter } from 'events';
import { join } from 'path';
import { EngineService } from './engine.service';

const mockSpawn = spawn as jest.MockedFunction<typeof spawn>;

function fakeChild() {
  const child = new EventEmitter() as EventEmitter & { stdout: EventEmitter; stderr: EventEmitter };
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  return child;
}

describe('EngineService', () => {
  let service: EngineService;

  beforeEach(() => {
    service = new EngineService();
    jest.resetAllMocks();
  });

  describe('startScan', () => {
    it('passes explicit --input/--output/--history so it re-scores the real scan-inputs, not the bundled sample fixtures', () => {
      // Regression: engine.py's own argparse defaults point at
      // aiops_engine/sample_inputs/ - the demo fixtures - so calling it with
      // no arguments (as this used to) silently re-scores sample data
      // instead of a real run's findings/scan-inputs/, overwriting real
      // results with sample output with no indication anything was wrong.
      const child = fakeChild();
      mockSpawn.mockReturnValue(child as never);

      service.startScan();

      expect(mockSpawn).toHaveBeenCalledWith(
        'python3',
        [
          'engine.py',
          '--input', join('/fake/findings', 'scan-inputs'),
          '--output', '/fake/findings/aiops-output.json',
          '--history', '/fake/findings/history.json',
        ],
        expect.objectContaining({ cwd: '/fake/aiops_engine' }),
      );
    });

    it('refuses to start a second scan while one is already running', () => {
      mockSpawn.mockReturnValue(fakeChild() as never);
      service.startScan();

      expect(() => service.startScan()).toThrow('A scan is already running');
    });

    it('reports success once the process exits cleanly', () => {
      const child = fakeChild();
      mockSpawn.mockReturnValue(child as never);

      service.startScan();
      child.emit('close', 0);

      return new Promise((resolve) => setImmediate(() => {
        expect(service.getStatus().state).toBe('success');
        resolve(undefined);
      }));
    });

    it('reports failed with the exit code and recent output when the process exits non-zero', () => {
      const child = fakeChild();
      mockSpawn.mockReturnValue(child as never);

      service.startScan();
      child.stdout.emit('data', Buffer.from('some progress line\n'));
      child.emit('close', 1);

      return new Promise((resolve) => setImmediate(() => {
        const status = service.getStatus();
        expect(status.state).toBe('failed');
        expect(status.error).toContain('exited with code 1');
        resolve(undefined);
      }));
    });
  });
});
