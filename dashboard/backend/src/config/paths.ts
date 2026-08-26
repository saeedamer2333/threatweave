import { join, resolve } from 'path';

/**
 * All filesystem locations the API touches.
 *
 * The backend lives at implementation/dashboard/backend, so the project root
 * is three levels up. Every path can be overridden with an environment
 * variable so the same build runs from a container, where the findings
 * directory is a mounted volume rather than a sibling folder.
 */
const PROJECT_ROOT = resolve(__dirname, '..', '..', '..', '..');

export const PATHS = {
  projectRoot: PROJECT_ROOT,

  /** Directory the engine writes its output to. */
  findingsDir: process.env.FINDINGS_DIR ?? join(PROJECT_ROOT, 'findings'),

  /** The engine's combined output consumed by the dashboard. */
  aiopsOutput:
    process.env.AIOPS_OUTPUT ??
    join(PROJECT_ROOT, 'findings', 'aiops-output.json'),

  /** Rolling history of previous runs. */
  history:
    process.env.HISTORY_FILE ?? join(PROJECT_ROOT, 'findings', 'history.json'),

  /** The AIOps engine package. */
  engineDir: process.env.ENGINE_DIR ?? join(PROJECT_ROOT, 'aiops_engine'),

  /** Analyst suppression rules, read and written by both engine and API. */
  suppressionRules:
    process.env.SUPPRESSION_RULES ??
    join(PROJECT_ROOT, 'aiops_engine', 'suppression_rules.json'),

  /** AWS monitor entry point. */
  awsMonitor:
    process.env.AWS_MONITOR ??
    join(PROJECT_ROOT, 'aws_monitor', 'monitor.py'),

  /** Python interpreter to use when invoking the engine. */
  python: process.env.PYTHON_BIN ?? 'python',
};
