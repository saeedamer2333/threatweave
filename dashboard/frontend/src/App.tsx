import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from 'react';
import type { AiopsOutput, Finding, Cluster, HistoryPoint, Suppression, SourceStatus } from './types';
import { api, ApiError, type PathCheck, type PipelineStatus, type NewSuppression, type AwsStatus, type AppSettings, type DetectedTarget, type SonarQubeStatus, type AsyncSonarScanStatus } from './api';
import { healthLabel, dirGlob, filterFindings, formatElapsed, describeAwsAuthMethod, evidenceText, formatScoreValue, confidenceExplanation, isRealDescription, describeFindingAge, READONLY_POLICY_JSON, isAwsMonitorRunning, originLabel, iacKindLabel } from './lib';
import './App.css';

type View = 'overview' | 'findings' | 'clusters' | 'history' | 'settings';

/**
 * Suppression rules only take effect the next time the engine actually
 * runs (`suppressor.py` reads them at that point) - creating or revoking
 * one just writes to `suppression_rules.json` and returns, so a finding
 * that was just dismissed keeps showing until something re-scores. Rather
 * than make every analyst learn that and go click "Run scan" themselves
 * (which now triggers the full ~10 minute Jenkins pipeline, not what this
 * needs), this fires the fast local re-score - `POST /scan`, the same
 * `engine.py` pass over whatever reports already exist in scan-inputs/,
 * seconds not minutes - right after the write, so "Dismiss"/"Restore"
 * actually feel immediate. Best-effort: if a real pipeline scan happens to
 * be running at the same moment (rare - a narrow window, and reading a
 * mid-write scan-inputs/ is not worse than what a normal run already
 * tolerates from a slow scanner), this silently no-ops rather than
 * surfacing a second error on top of whatever the caller already reports.
 */
async function rescoreAfterSuppressionChange(): Promise<void> {
  try {
    await api.startScan();
    for (let i = 0; i < 30; i++) {
      await new Promise((r) => setTimeout(r, 500));
      const s = await api.getScanStatus();
      if (s.state === 'success' || s.state === 'failed') return;
    }
  } catch {
    // Best-effort - see the function comment above.
  }
}

/** Placeholder shown in place of real scan output before any scan has ever
 * completed - so the dashboard's actual structure (nav, Settings, zeroed-out
 * stat cards) renders immediately instead of the entire page being replaced
 * by a wall of text. Settings in particular has nothing to do with scan
 * results at all (AWS status, pipeline target, suppression rules), so there
 * is no real reason it should be unreachable just because no scan has run
 * yet. `sources`/`history` stay undefined rather than `[]` so their own
 * "nothing to show" guards (`data.sources &&`, `data.history?.length > 1`)
 * skip rendering those specific blocks entirely instead of rendering an
 * empty version of them. */
const EMPTY_OUTPUT: AiopsOutput = {
  run_id: '', generated_at: '', health_score: 0,
  summary: { raw_findings: 0, after_dedup: 0, reduction_pct: 0, clusters: 0, critical: 0, high: 0, medium: 0, low: 0, suppressed: 0 },
  clusters: [], findings: [], suppressions: [],
};

const NAV: { id: View; label: string; icon: string }[] = [
  { id: 'overview', label: 'Overview', icon: 'M3 12l9-9 9 9M5 10v10h5v-6h4v6h5V10' },
  { id: 'findings', label: 'Findings', icon: 'M4 6h16M4 12h16M4 18h10' },
  { id: 'clusters', label: 'Attack Paths', icon: 'M5 5a2 2 0 110 4 2 2 0 010-4zm14 10a2 2 0 110 4 2 2 0 010-4zM7 7l10 10' },
  { id: 'history', label: 'History', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
  { id: 'settings', label: 'Settings', icon: 'M12 15a3 3 0 100-6 3 3 0 000 6zM19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09A1.65 1.65 0 008 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06A1.65 1.65 0 004.6 15a1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06A1.65 1.65 0 009 4.6a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06A1.65 1.65 0 0019.4 9c.14.63.68 1.1 1.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z' },
];

export default function App() {
  const [data, setData] = useState<AiopsOutput | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [view, setView] = useState<View>('overview');
  const [scan, setScan] = useState<PipelineStatus | null>(null);

  const noScanYet = error instanceof ApiError && error.status === 404;
  const effectiveData = data ?? (noScanYet ? EMPTY_OUTPUT : null);

  const load = useCallback(() => {
    api.getFindings()
      .then((d) => { setData(d); setError(null); })
      .catch((e: Error) => setError(e));
  }, []);

  useEffect(() => { load(); }, [load]);

  // "Run scan" triggers the real Jenkins pipeline (scanners -> engine), not
  // just a re-score of old data - queued and running both need polling,
  // since a build can sit queued for a moment before an executor picks it up.
  // 'starting' covers the gap between the click and triggerBuild()'s response
  // landing (a crumb fetch + a POST to Jenkins, which can itself take a
  // couple of seconds) - without it the button just sits there looking
  // unclicked until that round trip resolves.
  const [starting, setStarting] = useState(false);
  const scanInFlight = starting || scan?.state === 'queued' || scan?.state === 'running';

  // Every scan this session watches finish gets its own dismissible banner,
  // stacked oldest-first - not one shared slot where a later event (most
  // commonly the cron auto-poll skipping because nothing changed) silently
  // overwrites an unread success banner from a scan the analyst triggered
  // moments earlier. Confirmed live: without this, a manual "Run scan"
  // success banner was replaced by the very next auto-skip banner before
  // anyone had a chance to read it. Each stays up until its own x is
  // clicked, same as ScanFailureBanner - none auto-dismiss.
  const [scanToasts, setScanToasts] = useState<ToastEntry[]>([]);
  const pushToast = useCallback((entry: ScanToastInfo & { id: string }) => {
    setScanToasts((prev) => (prev.some((t) => t.id === entry.id) ? prev : [...prev, entry]));
  }, []);
  const dismissToast = useCallback((id: string) => {
    setScanToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  useEffect(() => {
    if (!scanInFlight) return;
    // Captured once, when this effect starts (i.e. right as the scan
    // begins) - the "before" snapshot a finished scan's own results get
    // compared against below, so the toast can say what actually changed
    // this run (new attack paths, more/fewer findings) rather than just
    // repeating this run's raw totals with nothing to judge them against.
    const before = data;
    const timer = setInterval(async () => {
      try {
        const status = await api.getPipelineStatus();
        setScan(status);
        if (status.state === 'failed') load();
        if (status.state === 'success') {
          // Fetched directly (not via `load()`, which is fire-and-forget)
          // so the toast can be built from the exact same response that
          // becomes the new `data` - no risk of racing a second, separate
          // findings fetch and reading back a different run's numbers.
          try {
            const fresh = await api.getFindings();
            setData(fresh);
            setError(null);
            pushToast({
              id: `success-${status.buildNumber ?? fresh.run_id}`,
              state: 'success',
              buildNumber: status.buildNumber,
              totalFindings: fresh.summary.after_dedup,
              critical: fresh.summary.critical,
              high: fresh.summary.high,
              healthScore: fresh.health_score,
              healthDelta: before ? fresh.health_score - before.health_score : null,
              newClusters: before ? fresh.clusters.length - before.clusters.length : fresh.clusters.length,
              totalClusters: fresh.clusters.length,
            });
          } catch (e) {
            setError(e as Error);
          }
        }
        if (status.state === 'skipped') {
          load();
          pushToast({ id: `skipped-${status.buildNumber}`, state: 'skipped', buildNumber: status.buildNumber });
        }
      } catch {
        // A single failed poll (e.g. the api container restarting) is not a
        // reason to give up forever - that used to stop this interval
        // permanently, leaving the sidebar stuck on "Scanning..." counting
        // up indefinitely with no further checks ever happening again. Just
        // skip this tick and let the next one retry.
      }
    }, 2000);
    return () => clearInterval(timer);
    // `data` deliberately excluded - `before` above is meant to freeze at
    // whatever `data` held when the scan started, not follow later updates
    // (there are none until this same effect's own setData call anyway).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanInFlight, load, pushToast]);

  // Discovers a build this dashboard did not itself start - Jenkins' own
  // cron trigger, or a build kicked off directly in Jenkins' UI - which
  // the fast poll above can never notice on its own, since it only runs
  // once `scanInFlight` is already true. Confirmed live: a cron-triggered
  // build ran to completion while the dashboard sat on "idle, last run
  // #309" the entire time, "Run scan" still clickable, with no poll of any
  // kind checking whether that was still accurate. Slower than the fast
  // poll since idle is the common case; once this finds a build genuinely
  // in flight, setting `scan` flips `scanInFlight` true and the fast poll
  // above takes over from there.
  useEffect(() => {
    if (scanInFlight) return;
    let cancelled = false;
    const check = async () => {
      try {
        const status = await api.getPipelineStatus();
        if (!cancelled && (status.state === 'queued' || status.state === 'running')) setScan(status);
      } catch {
        // Best-effort, same reasoning as the fast poll above.
      }
    };
    // Checked immediately, not only after the first interval tick - a
    // freshly-loaded page (or one that just finished its own scan) should
    // not have to wait up to 15s to notice a build that was already
    // running before it loaded.
    void check();
    const timer = setInterval(check, 15000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [scanInFlight]);

  // Separate from `error` (which is about *fetching findings* and, for a
  // real failure, blocks the whole page) - a failed trigger here means
  // Jenkins itself couldn't be reached or rejected the request, which has
  // nothing to do with whatever findings are already on screen. Reusing
  // `error` used to blank out the entire dashboard just because clicking
  // "Run scan" failed, hiding results the user was still looking at.
  const [scanError, setScanError] = useState<string | null>(null);

  const runScan = async () => {
    setStarting(true);
    setScanError(null);
    try {
      setScan(await api.runPipeline());
    } catch (e) {
      setScanError((e as Error).message);
    } finally {
      setStarting(false);
    }
  };

  // A ticking clock for "how long has this taken so far", independent of
  // the 2s status poll - shows real elapsed time rather than jumping only
  // when a poll happens to land.
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!scanInFlight) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [scanInFlight]);

  const elapsedLabel = scanInFlight && scan?.startedAt
    ? formatElapsed(now - new Date(scan.startedAt).getTime())
    : null;

  // The async SonarQube scan the pipeline launches detached can genuinely
  // be working with no Jenkins build around to report it via `scan` above
  // - that gap is real (confirmed live: idle pipeline state, scan
  // container still running) and is what this polls for independently,
  // rather than only ever showing SonarQube's progress as part of a
  // build's own activity.
  const [asyncSonarScan, setAsyncSonarScan] = useState<AsyncSonarScanStatus | null>(null);
  useEffect(() => {
    const poll = () => api.getAsyncSonarScanStatus().then(setAsyncSonarScan).catch(() => {});
    poll();
    const timer = setInterval(poll, 20000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="logo">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2l8 3v6c0 5-3.5 8-8 11-4.5-3-8-6-8-11V5l8-3z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>
          <div className="brand-text">
            <span className="brand-name">ThreatWeave</span>
            <span className="brand-sub">AIOps Prioritisation</span>
          </div>
        </div>

        <nav className="nav">
          {NAV.map((n) => (
            <button key={n.id} className={`nav-item ${view === n.id ? 'active' : ''}`} onClick={() => setView(n.id)}>
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d={n.icon} />
              </svg>
              {n.label}
            </button>
          ))}
        </nav>

        <div className="side-foot">
          <button className="scan-btn" onClick={runScan} disabled={scanInFlight}>
            {scanInFlight ? (
              <><span className="spinner" /> {starting ? 'Starting…' : scan?.state === 'queued' ? 'Queued…' : 'Scanning…'} {elapsedLabel && <span className="scan-elapsed">{elapsedLabel}</span>}</>
            ) : (
              <>
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 12a9 9 0 11-3-6.7M21 3v6h-6" />
                </svg>
                Run scan
              </>
            )}
          </button>
          {scanInFlight && scan?.currentActivity && (
            <span className="scan-activity" title={scan.currentActivity}>{scan.currentActivity}</span>
          )}
          {scan?.state === 'failed' && <span className="scan-err">Scan failed</span>}
          {scanError && <span className="scan-err" title={scanError}>Could not start scan: {scanError}</span>}
          {scan?.buildNumber && <span className="run-chip">Build #{scan.buildNumber}</span>}
          {data && <span className="run-chip">Run {data.run_id}</span>}
        </div>
      </aside>

      <main className="main">
        {/* A 404 from /findings means the API is reachable and working fine -
            it's just telling us no scan has run in this deployment yet. That
            is a normal, expected first-run state, not a failure - the rest
            of the dashboard (Settings above all, which has nothing to do
            with scan results) should stay fully usable, not be replaced by
            a wall of text. So this renders as a dismissable-feeling banner
            above the real page, not instead of it. */}
        {noScanYet && (
          <div className="welcome-banner">
            <div className="welcome-text">
              <strong>No scan results yet</strong>
              <span>Choose what to scan in Settings → Pipeline target (your project folder, Terraform folder and container image), then run a scan.</span>
            </div>
            <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
              <button className="btn-ghost" onClick={() => setView('settings')}>Open Settings</button>
              <button className="btn-primary" onClick={runScan} disabled={scanInFlight}>Run scan</button>
            </div>
          </div>
        )}
        {/* A genuine connectivity failure (API container down, wrong port,
            etc.) is different from the above - nothing on the page can be
            trusted without a working API, so this one does block the page. */}
        {error && !noScanYet && (
          <div className="state">
            <p>Could not reach the API: {error.message}</p>
            <span className="empty-sub">Is the NestJS backend running on port 4000?</span>
          </div>
        )}
        {!error && !data && <div className="state">Loading findings…</div>}
        {scanToasts.map((toast) => (
          <ScanCompleteToast key={toast.id} toast={toast} onDismiss={() => dismissToast(toast.id)} />
        ))}
        {scan?.state === 'failed' && (
          <ScanFailureBanner scan={scan} onDismiss={() => setScan(null)} />
        )}
        {scanInFlight && scan?.stalled && (
          <ScanStalledBanner scan={scan} />
        )}
        {effectiveData && (
          <Content
            view={view}
            data={effectiveData}
            onGoto={setView}
            onReload={load}
            scan={scanInFlight ? scan : null}
            elapsedLabel={elapsedLabel}
            asyncSonarScan={asyncSonarScan}
          />
        )}
      </main>
    </div>
  );
}

/** What the toast needs to say something concrete, not just "it worked" -
 * built from the freshly-fetched findings response plus whatever `data`
 * held right before this scan started, so `healthDelta`/`newClusters` are
 * real before/after deltas rather than just this run's raw totals. `null`
 * deltas (first scan ever, nothing to compare against) render as plain
 * totals instead of a +/- change - see ScanCompleteToast. */
type ScanToastInfo =
  | { state: 'skipped'; buildNumber?: number }
  | {
      state: 'success'; buildNumber?: number;
      totalFindings: number; critical: number; high: number;
      healthScore: number; healthDelta: number | null;
      newClusters: number; totalClusters: number;
    };

/** One stacked banner - `id` is stable per build (`success-<buildNumber>` /
 * `skipped-<buildNumber>`) so an overlapping poll tick that detects the
 * same finished build twice (a real, if narrow, race - see the interval
 * comment above) de-dupes against pushToast's existing-id check instead of
 * stacking two identical banners for one build. */
type ToastEntry = ScanToastInfo & { id: string };

/* ---------- Scan finished: an inline banner (same family as
   ScanFailureBanner/welcome-banner below), not a floating toast - it stays
   on screen until the analyst dismisses it with the x, rather than
   auto-clearing after a few seconds and risking being missed entirely if
   nobody was looking at that exact moment. */
function ScanCompleteToast({ toast, onDismiss }: { toast: ScanToastInfo; onDismiss: () => void }) {
  const success = toast.state === 'success';
  return (
    <div className={`scan-toast ${success ? 'scan-toast-ok' : 'scan-toast-skip'}`} role="status">
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
        {success ? <path d="M20 6L9 17l-5-5" /> : <path d="M12 8v5M12 16.5v.01M10.3 3.9L2.5 18a1.5 1.5 0 001.3 2.2h16.4a1.5 1.5 0 001.3-2.2L13.7 3.9a1.5 1.5 0 00-2.6 0z" />}
      </svg>
      <div className="scan-toast-body">
        <strong>
          {success ? 'Scan completed successfully' : 'Scan skipped'}
          {toast.buildNumber ? <span className="scan-toast-build"> · Build #{toast.buildNumber}</span> : ''}
        </strong>
        {success ? (
          <>
            <span>
              {toast.totalFindings} finding{toast.totalFindings === 1 ? '' : 's'}
              {' '}({toast.critical} critical, {toast.high} high) · Health {toast.healthScore}
              {toast.healthDelta !== null && toast.healthDelta !== 0 && (
                <span className={toast.healthDelta > 0 ? 'scan-toast-up' : 'scan-toast-down'}>
                  {' '}({toast.healthDelta > 0 ? '+' : ''}{toast.healthDelta})
                </span>
              )}
            </span>
            <span>
              {toast.newClusters > 0
                ? <span className="scan-toast-warn">{toast.newClusters} new attack path{toast.newClusters === 1 ? '' : 's'} found</span>
                : toast.totalClusters > 0
                  ? `${toast.totalClusters} attack path${toast.totalClusters === 1 ? '' : 's'} correlated, none new this run`
                  : 'No attack paths correlated this run.'}
            </span>
          </>
        ) : (
          <span>No new commits since the last scan - nothing to do.</span>
        )}
      </div>
      <button className="scan-toast-close" onClick={onDismiss} aria-label="Dismiss">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M18 6L6 18M6 6l12 12" />
        </svg>
      </button>
    </div>
  );
}

/* ---------- Scan failure: the real reason, not just "Scan failed" ---------- */
function ScanFailureBanner({ scan, onDismiss }: { scan: PipelineStatus; onDismiss: () => void }) {
  // A stall timeout is a distinct case worth explaining differently: the
  // dashboard lost track of the build, but Jenkins itself may still be
  // working - that is not the same as the pipeline having actually failed.
  // Two different stalls read differently: queued-too-long (never started)
  // vs. running-with-no-new-output (started, then went quiet).
  const stalled = /^(Lost contact with Jenkins|No new output from the build)/.test(scan.error ?? '');
  return (
    <div className="scan-fail-banner">
      <div className="scan-fail-icon">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="9" /><path d="M12 8v5M12 16h.01" />
        </svg>
      </div>
      <div className="scan-fail-body">
        <span className="scan-fail-title">
          {stalled ? 'Lost track of the last scan' : 'The last scan attempt failed'}
          {scan.buildNumber && <span className="scan-fail-build">Build #{scan.buildNumber}</span>}
        </span>
        <p className="scan-fail-detail">{scan.error ?? 'No further detail was reported.'}</p>
        {stalled && (
          <p className="scan-fail-note">
            The data below is from the last successful run, not this attempt -
            it has not been overwritten by anything.
          </p>
        )}
      </div>
      <div className="scan-fail-actions">
        {scan.buildUrl && (
          <a className="btn-ghost small" href={scan.buildUrl} target="_blank" rel="noreferrer">
            View in Jenkins ↗
          </a>
        )}
        <button className="btn-ghost small" onClick={onDismiss}>Dismiss</button>
      </div>
    </div>
  );
}

/* ---------- Scan quiet but not dead: still polling, not a failure ---------- */
function ScanStalledBanner({ scan }: { scan: PipelineStatus }) {
  return (
    <div className="scan-fail-banner scan-fail-banner-warn">
      <div className="scan-fail-icon">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="9" /><path d="M12 7v6M12 16h.01" />
        </svg>
      </div>
      <div className="scan-fail-body">
        <span className="scan-fail-title">
          Build has gone quiet, still watching
          {scan.buildNumber && <span className="scan-fail-build">Build #{scan.buildNumber}</span>}
        </span>
        <p className="scan-fail-detail">
          No new output in a while - often just a CPU-heavy scanner stage keeping Jenkins too
          busy to answer. Still polling; this clears itself as soon as it responds again.
        </p>
      </div>
      <div className="scan-fail-actions">
        {scan.buildUrl && (
          <a className="btn-ghost small" href={scan.buildUrl} target="_blank" rel="noreferrer">
            View in Jenkins ↗
          </a>
        )}
      </div>
    </div>
  );
}

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

function Content({ view, data, onGoto, onReload, scan, elapsedLabel, asyncSonarScan }: {
  view: View; data: AiopsOutput; onGoto: (v: View) => void; onReload: () => void;
  scan: PipelineStatus | null; elapsedLabel: string | null;
  asyncSonarScan: AsyncSonarScanStatus | null;
}) {
  const health = healthLabel(data.health_score);
  const [query, setQuery] = useState('');
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [srcFilter, setSrcFilter] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const findingById = (id: string) => data.findings.find((f) => f.id === id);
  const sources = Array.from(new Set(data.findings.flatMap((f) => f.reported_by))).sort();

  const sortedFindings = filterFindings(data.findings, { severity: sevFilter, source: srcFilter, query })
    .sort((a, b) => b.risk_score - a.risk_score);

  const header = (title: string, sub: string) => (
    <header className="page-head">
      <div><h1>{title}</h1><span className="page-sub">{sub}</span></div>
    </header>
  );

  if (view === 'overview') {
    return (
      <>
        {header('Overview', 'Security posture for the latest pipeline run')}
        {/* The live "scanning now" progress banner inside DataSources should
            show whenever a scan is actually running, even before this
            deployment's very first scan has ever completed - gating the
            whole component on `data.sources` (only populated by a completed
            run) made the very first scan look like nothing was happening,
            even though the sidebar's own spinner/elapsed timer confirmed it
            was. Only the per-tool chip row genuinely needs prior data. */}
        {(data.sources || scan || asyncSonarScan?.scanning) && (
          <DataSources sources={data.sources ?? []} scan={scan} elapsedLabel={elapsedLabel} asyncSonarScan={asyncSonarScan} onOpenSettings={() => onGoto('settings')} />
        )}
        <section className="grid">
          <div className={`card health ${health.cls}`}>
            <span className="card-label">Health Score</span>
            <div className="ring"><span className="health-num">{data.health_score}</span></div>
            <span className="health-text">{health.text}</span>
          </div>
          <div className="card">
            <span className="card-label">Alert Reduction</span>
            <span className="stat-num">{data.summary.reduction_pct}%</span>
            <span className="stat-sub">{data.summary.raw_findings} → {data.summary.after_dedup} findings</span>
            {(data.summary.suppressed ?? 0) > 0 && (
              <span className="stat-sub muted-tag">incl. {data.summary.suppressed} suppressed</span>
            )}
          </div>
          <div className="card">
            <span className="card-label">Attack Paths</span>
            <span className="stat-num">{data.summary.clusters}</span>
            <span className="stat-sub">correlated across sources</span>
          </div>
          <div className="card">
            <span className="card-label">Critical / High</span>
            <span className="stat-num">{data.summary.critical} / {data.summary.high}</span>
            <span className="stat-sub">need attention</span>
          </div>
        </section>

        <section className="block">
          <h2>How {data.summary.raw_findings} raw alerts became {data.summary.after_dedup}</h2>
          <div className="card funnel-card">
            <Funnel data={data} />
          </div>
        </section>

        <section className="block">
          <div className="two-col">
            {data.history && data.history.length > 1 && (
              <div className="col-wide">
                <div className="block-head"><h2>Health Trend</h2><button className="link-btn" onClick={() => onGoto('history')}>Details →</button></div>
                <div className="card chart-card"><TrendChart points={data.history} /></div>
              </div>
            )}
            <div>
              <div className="block-head"><h2>Findings by Severity</h2><button className="link-btn" onClick={() => onGoto('findings')}>View all →</button></div>
              <div className="card chart-card"><SeverityDonut summary={data.summary} /></div>
            </div>
          </div>
        </section>

        <section className="block">
          <div className="block-head"><h2>Top Attack Path</h2><button className="link-btn" onClick={() => onGoto('clusters')}>View all →</button></div>
          {data.clusters.length === 0 ? (
            <div className="card donut-empty">No attack paths yet - these appear once findings across sources correlate to the same asset.</div>
          ) : (
            data.clusters.slice(0, 1).map((c) => <ClusterCard key={c.cluster_id} c={c} findingById={findingById} />)
          )}
        </section>
      </>
    );
  }

  if (view === 'clusters') {
    return (
      <>
        {header('Attack Paths', 'Findings correlated across code, container and cloud')}
        {data.clusters.length === 0 ? (
          <div className="card donut-empty">
            {data.findings.length === 0
              ? 'No scan has run yet - attack paths will appear here once one completes.'
              : 'No attack paths in this run - findings correlate into a path when they share the same asset across sources.'}
          </div>
        ) : (
          data.clusters.map((c) => <ClusterCard key={c.cluster_id} c={c} findingById={findingById} defaultOpen />)
        )}
      </>
    );
  }

  if (view === 'findings') {
    const catCounts = SEVERITIES.map((s) => ({ s, n: data.findings.filter((f) => f.severity === s).length }));
    return (
      <>
        {header('Findings', `${data.findings.length} prioritised findings after deduplication`)}

        <div className="toolbar">
          <div className="search">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" />
            </svg>
            <input placeholder="Search by title, resource or CVE…" value={query} onChange={(e) => setQuery(e.target.value)} />
            {query && <button className="clear" onClick={() => setQuery('')}>×</button>}
          </div>
        </div>

        <div className="filters">
          <div className="chip-group">
            <span className="chip-label">Severity</span>
            <button className={`chip ${!sevFilter ? 'on' : ''}`} onClick={() => setSevFilter(null)}>All</button>
            {catCounts.map(({ s, n }) => (
              <button key={s} className={`chip sev-chip-${s.toLowerCase()} ${sevFilter === s ? 'on' : ''}`} onClick={() => setSevFilter(sevFilter === s ? null : s)}>
                {s.charAt(0) + s.slice(1).toLowerCase()} <span className="chip-n">{n}</span>
              </button>
            ))}
          </div>
          <div className="chip-group">
            <span className="chip-label">Source</span>
            <button className={`chip ${!srcFilter ? 'on' : ''}`} onClick={() => setSrcFilter(null)}>All</button>
            {sources.map((s) => (
              <button key={s} className={`chip ${srcFilter === s ? 'on' : ''}`} onClick={() => setSrcFilter(srcFilter === s ? null : s)}>{s}</button>
            ))}
          </div>
        </div>

        <div className="result-count">{sortedFindings.length} of {data.findings.length} findings</div>

        <div className="table-wrap">
          <table className="findings">
            <colgroup>
              <col style={{ width: 34 }} />
              <col style={{ width: 68 }} />
              {/* Severity/Confidence widened from 84/96px - too narrow for
                  their own uppercase, letter-spaced header labels
                  ("SEVERITY", "CONFIDENCE"), confirmed live showing as
                  truncated "SEVERI…"/"CONFIDE…" instead. Title/Resource
                  trimmed by a matching couple of percent so the table's
                  total width is unchanged - still fits the screen with no
                  horizontal scroll needed, just redistributed. */}
              <col style={{ width: 104 }} />
              <col style={{ width: '28%' }} />
              <col style={{ width: 90 }} />
              <col style={{ width: '22%' }} />
              <col style={{ width: 116 }} />
            </colgroup>
            <thead>
              <tr><th></th><th>Risk</th><th>Severity</th><th>Title</th><th>Source</th><th>Resource</th><th>Confidence</th></tr>
            </thead>
            <tbody>
              {sortedFindings.length === 0 && (
                <tr><td colSpan={7} className="no-results">
                  {data.findings.length === 0 ? 'No scan has run yet - findings will appear here once one completes.' : 'No findings match your filters.'}
                </td></tr>
              )}
              {sortedFindings.map((f: Finding) => {
                const isOpen = expanded === f.id;
                return (
                  <FindingRow key={f.id} f={f} isOpen={isOpen} onToggle={() => setExpanded(isOpen ? null : f.id)} clusters={data.clusters} onReload={onReload} />
                );
              })}
            </tbody>
          </table>
        </div>
      </>
    );
  }

  if (view === 'settings') {
    return (
      <>
        {header('Settings', 'Cloud connection, checks and suppression rules')}
        <SettingsPanel data={data} onReload={onReload} />
      </>
    );
  }

  // history
  return (
    <>
      {header('History', 'Health score across recent pipeline runs')}
      {data.history && data.history.length > 1 ? (
        <>
          <div className="card chart-card big"><TrendChart points={data.history} /></div>
          <div className="table-wrap" style={{ marginTop: 20 }}>
            <table className="findings">
              <thead><tr><th>Run</th><th>Date</th><th>Health Score</th><th>Status</th></tr></thead>
              <tbody>
                {[...data.history].reverse().map((h) => {
                  const hl = healthLabel(h.health_score);
                  return (
                    <tr key={h.run_id}>
                      <td className="mono">{h.run_id}</td>
                      <td>{new Date(h.generated_at).toLocaleDateString()}</td>
                      <td><span className={`risk-pill ${hl.cls === 'good' ? 'good' : hl.cls === 'warn' ? 'warn' : 'bad'}`}>{h.health_score}</span></td>
                      <td>{hl.text}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <div className="empty"><p>Historical trend will appear here once multiple pipeline runs are recorded.</p></div>
      )}
    </>
  );
}

/* ---------- Settings ---------- */
const REGIONS = [
  '', 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-central-1',
  'ap-southeast-1', 'ap-southeast-2', 'ap-south-1', 'ap-northeast-1',
];

const CHECK_LABELS: Record<string, string> = {
  ec2: 'EC2 instances — public IPs, IMDSv2 enforcement',
  sg: 'Security groups — 0.0.0.0/0 ingress on sensitive ports',
  s3: 'S3 buckets — public access block, encryption',
  iam: 'IAM — AdministratorAccess, excess access keys',
};

/** Step-by-step setup for read-only AWS access, shown open whenever the
 * connection is missing or incomplete. */
function AwsPolicyGuide({ open }: { open: boolean }) {
  const [copyNote, setCopyNote] = useState<string | null>(null);
  const copyPolicy = async () => {
    try {
      await navigator.clipboard.writeText(READONLY_POLICY_JSON);
      setCopyNote('Copied');
    } catch {
      setCopyNote('Copy blocked - select the text below instead');
    }
    setTimeout(() => setCopyNote(null), 2500);
  };
  return (
    <details className="aws-guide" open={open}>
      <summary>How to give ThreatWeave read-only AWS access</summary>
      <ol className="aws-steps">
        <li>
          <strong>Create a dedicated IAM user.</strong> AWS Console → IAM → Users → Create user,
          for example <code>threatweave-monitor</code>. Leave console access off.
        </li>
        <li>
          <strong>Attach a read-only policy.</strong> Choose <em>Attach policies directly</em> and select the
          AWS managed <code>SecurityAudit</code> policy. For the smallest possible access, create a
          policy from the JSON below instead and attach that.
        </li>
        <li>
          <strong>Create an access key.</strong> Open the user → <em>Security credentials</em> →
          <em> Create access key</em> → <em>Application running outside AWS</em>. Copy the access key ID and
          the secret; AWS shows the secret only once.
        </li>
        <li>
          <strong>Give the keys to ThreatWeave.</strong> Recommended: run <code>aws configure</code> on this
          machine, so the keys stay in <code>~/.aws</code> and pipeline runs use them too. Or enter them in
          the form above for this session only.
        </li>
        <li>
          <strong>Check.</strong> The status above should turn green with ✓ EC2 ✓ S3 ✓ IAM.
        </li>
      </ol>
      <div className="aws-policy">
        <div className="aws-policy-head">
          <span>Minimum policy: exactly the calls the monitor makes</span>
          <button type="button" className="btn-ghost small" onClick={copyPolicy}>{copyNote ?? 'Copy JSON'}</button>
        </div>
        <pre className="mono">{READONLY_POLICY_JSON}</pre>
      </div>
      <p className="set-note">
        Never use root account keys or a user with <code>AdministratorAccess</code>. ThreatWeave only reads, so
        its credentials should only be able to read.
      </p>
    </details>
  );
}

/** Enter AWS keys for this session when no default credentials exist. The
 * API checks them with AWS before keeping them and never sends them back. */
function AwsKeyForm({ onConnected }: { onConnected: (s: AwsStatus) => void }) {
  const empty = { accessKeyId: '', secretAccessKey: '', sessionToken: '', region: '' };
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(empty);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!open) {
    return (
      <button type="button" className="btn-ghost" onClick={() => setOpen(true)}>
        Enter access keys manually
      </button>
    );
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const status = await api.connectAws({
        accessKeyId: form.accessKeyId.trim(),
        secretAccessKey: form.secretAccessKey.trim(),
        ...(form.sessionToken.trim() ? { sessionToken: form.sessionToken.trim() } : {}),
        ...(form.region ? { region: form.region } : {}),
      });
      setForm(empty);
      setOpen(false);
      onConnected(status);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="aws-key-form" onSubmit={submit} autoComplete="off">
      <label className="set-row" htmlFor="aws-key-id">
        <span className="set-label">Access key ID</span>
        <input id="aws-key-id" className="set-input mono" placeholder="AKIA…" spellCheck={false} required
          value={form.accessKeyId} onChange={(e) => setForm({ ...form, accessKeyId: e.target.value })} />
      </label>
      <label className="set-row" htmlFor="aws-secret">
        <span className="set-label">Secret access key</span>
        <input id="aws-secret" type="password" className="set-input mono" autoComplete="new-password" required
          value={form.secretAccessKey} onChange={(e) => setForm({ ...form, secretAccessKey: e.target.value })} />
      </label>
      <label className="set-row" htmlFor="aws-token">
        <span className="set-label">Session token <span className="muted-inline">(temporary keys only)</span></span>
        <input id="aws-token" type="password" className="set-input mono" autoComplete="off"
          value={form.sessionToken} onChange={(e) => setForm({ ...form, sessionToken: e.target.value })} />
      </label>
      <label className="set-row" htmlFor="aws-region">
        <span className="set-label">Default region</span>
        <select id="aws-region" className="set-input" value={form.region}
          onChange={(e) => setForm({ ...form, region: e.target.value })}>
          {REGIONS.map((r) => <option key={r} value={r}>{r || 'Not set'}</option>)}
        </select>
      </label>
      <p className="set-note">
        Checked with AWS before use, then held in the API's memory for this session only: never saved to disk,
        never shown again. Cleared when the API restarts or you disconnect. After each pipeline run the cloud
        checks are re-run with these keys, since Jenkins cannot see them.
      </p>
      {error && <p className="set-note set-note-warn">{error}</p>}
      <div className="form-actions">
        <button type="submit" className="btn-primary" disabled={busy}>{busy ? 'Checking with AWS…' : 'Connect'}</button>
        <button type="button" className="btn-ghost" disabled={busy} onClick={() => { setOpen(false); setError(null); setForm(empty); }}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function SettingsPanel({ data, onReload }: { data: AiopsOutput; onReload: () => void }) {
  const [aws, setAws] = useState<AwsStatus | null>(null);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [sups, setSups] = useState<Suppression[]>([]);
  const [sonarStatus, setSonarStatus] = useState<SonarQubeStatus | null>(null);

  const refresh = useCallback(() => {
    api.getAwsStatus().then(setAws).catch(() => setAws({ connected: false, message: 'API unreachable' }));
    api.getSettings().then(setSettings).catch(() => {});
    api.getSuppressions().then(setSups).catch(() => {});
    api.getSonarQubeStatus().then(setSonarStatus).catch(() => {});
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Only relevant to the all-in-one image's bundled SonarQube - a crash
  // (most likely an out-of-memory kill under real scan load) has no other
  // visible symptom besides the next scan's SAST stage silently failing, so
  // this keeps checking while Settings is open rather than only once at load.
  useEffect(() => {
    const timer = setInterval(() => {
      api.getSonarQubeStatus().then(setSonarStatus).catch(() => {});
    }, 20000);
    return () => clearInterval(timer);
  }, []);

  const save = async (patch: Partial<AppSettings>) => {
    if (!settings) return;
    setSaving(true); setMsg(null);
    try {
      setSettings(await api.updateSettings(patch));
      setMsg('Settings saved');
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const runCloudScan = async () => {
    setScanning(true); setMsg(null);
    try {
      const res = await api.runAwsScan(settings?.awsRegion || undefined);
      setMsg(res.ok ? 'Cloud scan complete — run a full scan to fold the results in.' : 'Cloud scan failed');
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setScanning(false);
    }
  };

  const disconnectAws = async () => {
    setMsg(null);
    try {
      setAws(await api.disconnectAws());
    } catch (e) {
      setMsg((e as Error).message);
    }
  };

  const revoke = async (id: string) => {
    await api.revokeSuppression(id);
    refresh();
    await rescoreAfterSuppressionChange();
    onReload();
  };

  return (
    <div className="settings">
      {sonarStatus?.relevant && !sonarStatus.healthy && (
        <div className="card sonar-crash-banner">
          <div className="sonar-crash-icon">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="9" /><path d="M12 8v5M12 16h.01" />
            </svg>
          </div>
          <div className="sonar-crash-body">
            <strong>
              {sonarStatus.didNotStart ? 'SonarQube did not start - SAST is off'
                : sonarStatus.crashReason === 'oom' ? 'SonarQube ran out of memory and stopped' : 'SonarQube stopped responding'}
            </strong>
            <p>
              {sonarStatus.didNotStart
                ? `${sonarStatus.message ?? 'SonarQube did not start.'} GitLeaks, Trivy, Checkov and the AWS checks are unaffected - only SAST results are missing.${sonarStatus.didNotStart === 'timeout' ? ' This is almost always too little memory for SonarQube.' : ''}`
                : sonarStatus.crashReason === 'oom'
                ? "This container's SonarQube (bundled for SAST) used more memory than the host could give it and was killed. The rest of the pipeline (GitLeaks, Trivy, Checkov) is unaffected — only SAST results are missing until this is fixed."
                : (sonarStatus.message ?? 'SonarQube is not reachable right now.')}
            </p>
            <p className="sonar-crash-fix">
              <strong>Two real fixes:</strong> give this container more memory (raise Docker's memory
              limit, or free up RAM on the host — SonarQube alone needs ~1.5–2GB even after trimming),
              or turn it off with <span className="mono">-e SONARQUBE_AUTOSTART=false</span> and point
              at an external SonarQube instead via <span className="mono">SONAR_HOST_URL</span>/
              <span className="mono">SONAR_TOKEN</span>. Everything else keeps working either way.
            </p>
          </div>
        </div>
      )}
      {/* AWS connection */}
      <div className="card set-card">
        <div className="set-head">
          <h3>AWS connection</h3>
          {aws && (
            <span className={`conn-pill ${!aws.connected ? 'off' : aws.hasFullAccess === false ? 'warn' : 'ok'}`}>
              {!aws.connected ? 'Not connected' : aws.hasFullAccess === false ? 'Connected, limited access' : 'Connected'}
            </span>
          )}
        </div>

        {aws?.connected ? (
          <div className="d-grid">
            <div className="d-item"><span className="d-label">Account</span><span className="d-value mono">{aws.account}</span></div>
            <div className="d-item"><span className="d-label">Identity</span><span className="d-value mono">{aws.arn}</span></div>
            <div className="d-item"><span className="d-label">Profile region</span><span className="d-value mono">{aws.region ?? '—'}</span></div>
            {describeAwsAuthMethod(aws.arn) && (
              <div className="d-item"><span className="d-label">Auth method</span><span className="d-value">{describeAwsAuthMethod(aws.arn)}</span></div>
            )}
            <div className="d-item">
              <span className="d-label">Credentials</span>
              <span className="d-value">
                {aws.credentialSource === 'manual' ? (
                  <>
                    Entered on this page (this session only){' '}
                    <button type="button" className="btn-ghost small" onClick={disconnectAws}>Disconnect</button>
                  </>
                ) : 'Default chain: IAM role, environment, or ~/.aws/credentials'}
              </span>
            </div>
            {aws.permissions && (
              <div className="d-item">
                <span className="d-label">Read access</span>
                <span className="d-value">
                  {(Object.entries(aws.permissions) as [string, boolean][]).map(([service, ok]) => (
                    <span key={service} className={`perm-chip ${ok ? 'ok' : 'off'}`}>
                      {ok ? '✓' : '✗'} {service.toUpperCase()}
                    </span>
                  ))}
                </span>
              </div>
            )}
          </div>
        ) : (
          <div className="conn-help">
            <p>{aws?.message ?? 'Checking…'}</p>
            {aws && aws.messageKind !== 'deployment' && (
              <>
                <p className="empty-sub">
                  Credentials are resolved by Boto3: an IAM role when running on EC2, then environment
                  variables, then <code>~/.aws/credentials</code>. Run <code>aws configure</code> once and
                  reload, or enter access keys here for this session.
                </p>
                <AwsKeyForm onConnected={setAws} />
              </>
            )}
          </div>
        )}

        {aws?.connected && aws.hasFullAccess === false && (
          <p className="set-note set-note-warn">
            Connected, but missing read access for{' '}
            {Object.entries(aws.permissions ?? {}).filter(([, ok]) => !ok).map(([s]) => s.toUpperCase()).join(', ')}
            {' '}— the cloud scan will run but findings from those services will be incomplete. Attach the
            AWS managed <code>SecurityAudit</code> policy (or the minimum policy in the guide below) to the
            credentials shown above and reload.
          </p>
        )}

        <p className="set-note">
          Only read-only permissions are needed. Attach the AWS managed <code>SecurityAudit</code> policy —
          the monitor issues describe/list/get calls only and cannot modify infrastructure.
        </p>

        {aws && aws.messageKind !== 'deployment' && (
          <AwsPolicyGuide open={!aws.connected || aws.hasFullAccess === false} />
        )}
      </div>

      {/* Scan configuration */}
      {settings && (
        <div className="card set-card">
          <div className="set-head"><h3>Cloud checks</h3></div>

          <label className="set-row">
            <span className="set-label">Region</span>
            <select
              className="set-input"
              value={settings.awsRegion}
              onChange={(e) => save({ awsRegion: e.target.value })}
            >
              {REGIONS.map((r) => <option key={r} value={r}>{r || 'Use profile default'}</option>)}
            </select>
          </label>

          <div className="set-row col">
            <span className="set-label">Checks to run</span>
            <div className="check-list">
              {(Object.keys(CHECK_LABELS) as (keyof AppSettings['checks'])[]).map((k) => (
                <label key={k} className="check-item">
                  <input
                    type="checkbox"
                    checked={settings.checks[k]}
                    onChange={(e) => save({ checks: { ...settings.checks, [k]: e.target.checked } })}
                  />
                  <span className="check-name">{k.toUpperCase()}</span>
                  <span className="check-desc">{CHECK_LABELS[k]}</span>
                </label>
              ))}
            </div>
          </div>

          <label className="set-row">
            <span className="set-label">Scan every</span>
            <select
              className="set-input"
              value={settings.scanIntervalMinutes}
              onChange={(e) => save({ scanIntervalMinutes: Number(e.target.value) })}
            >
              {[0, 15, 30, 60, 180].map((m) => (
                <option key={m} value={m}>{m === 0 ? 'Manual only' : `${m} minutes`}</option>
              ))}
            </select>
          </label>

          <div className="form-actions">
            <button className="btn-primary" onClick={runCloudScan} disabled={scanning || !aws?.connected}>
              {scanning ? 'Scanning cloud…' : 'Run cloud scan now'}
            </button>
            {saving && <span className="set-msg">Saving…</span>}
            {msg && !saving && <span className="set-msg">{msg}</span>}
          </div>
        </div>
      )}

      {/* Pipeline target */}
      {settings && <PipelineTargetCard settings={settings} save={save} saving={saving} />}

      {/* Suppressions */}
      <div className="card set-card">
        <div className="set-head">
          <h3>Suppression rules</h3>
          <span className="stat-sub">{sups.length} active</span>
        </div>
        <p className="set-card-desc">
          A pattern-based filter that hides matching findings from every future scan automatically -
          so a known false positive (e.g. test fixtures, a path that's out of scope) doesn't have to
          be re-dismissed by hand every single run. Created from the "Dismiss" action on a finding in
          the Findings page; each one below shows how many findings it's currently hiding.
        </p>
        {sups.length === 0 ? (
          <p className="empty-sub">
            No rules yet. Dismiss a finding from the Findings page to create one.
          </p>
        ) : (
          <div className="rule-list">
            {sups.map((s) => {
              const hit = data.suppressions?.find((x) => x.id === s.id)?.suppressed_count ?? 0;
              return (
                <div className="rule-item" key={s.id}>
                  <div className="rule-main">
                    <span className="rule-reason">{s.reason}</span>
                    <span className="rule-meta">
                      {s.id} · by {s.created_by} · {new Date(s.created_at).toLocaleDateString()}
                    </span>
                  </div>
                  <span className="rule-hits">{hit} suppressed</span>
                  <button className="btn-ghost small" onClick={() => revoke(s.id)}>Revoke</button>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

/* ---------- Pipeline target: what "Run scan" actually scans ---------- */
function PipelineTargetCard({ settings, save, saving }: {
  settings: AppSettings; save: (patch: Partial<AppSettings>) => void; saving: boolean;
}) {
  const p = settings.pipeline;
  // Text fields save on blur, not every keystroke - a partial path mid-edit
  // shouldn't hit the API on each character.
  const [draft, setDraft] = useState(p);
  useEffect(() => { setDraft(p); }, [p]);

  // Only the changed field is sent, so the API records exactly what the user
  // chose - the other fields keep following detection/install values.
  const saveField = (key: keyof typeof p, value: string | boolean) =>
    save({ pipeline: { [key]: value } as never });

  // Typed paths are checked right away, instead of a scan finding out later.
  const [pathChecks, setPathChecks] = useState<{ sourceDir?: PathCheck; iacDir?: PathCheck; targetImage?: PathCheck }>({});
  const checkField = (field: 'sourceDir' | 'iacDir' | 'targetImage', value: string) => {
    api.checkPath(field === 'iacDir' ? 'iac' : field === 'targetImage' ? 'image' : 'source', value)
      .then((r) => setPathChecks((prev) => ({ ...prev, [field]: r })))
      .catch(() => {});
  };
  useEffect(() => {
    if (p.sourceDir) checkField('sourceDir', p.sourceDir);
    if (p.iacDir) checkField('iacDir', p.iacDir);
    if (p.targetImage) checkField('targetImage', p.targetImage);
    else setPathChecks((prev) => ({ ...prev, targetImage: undefined }));
  }, [p.sourceDir, p.iacDir, p.targetImage]);

  const origin = (field: 'sourceDir' | 'iacDir' | 'targetImage' | 'sonarProjectKey') => {
    const label = originLabel(settings.pipelineOrigin?.[field]);
    return label && <span className={`origin-tag origin-${settings.pipelineOrigin?.[field]}`} title={label.title}>{label.text}</span>;
  };
  const checkLine = (field: 'sourceDir' | 'iacDir' | 'targetImage') => {
    const c = pathChecks[field];
    if (!c || c.level === 'info') return null;
    const icon = c.level === 'ok' ? '✓' : c.level === 'warn' ? '⚠' : '✗';
    return <div className={`path-check path-check-${c.level}`}>{icon} {c.message}</div>;
  };

  // Inspects what's actually mounted at /target and offers it as a one-click
  // suggestion - never applied automatically, since "Run scan" acting on
  // something the user didn't explicitly choose would be the wrong kind of
  // "automatic" for a field that controls what gets scanned.
  const [detected, setDetected] = useState<DetectedTarget | null>(null);
  const [dismissed, setDismissed] = useState(false);
  useEffect(() => { api.detectTarget().then(setDetected).catch(() => {}); }, []);

  // The container image is never part of the suggestion: an image can come
  // from a registry or be built elsewhere, so a project without a Dockerfile
  // is no reason to clear one the user typed.
  // Only a real mounted project is worth suggesting; an empty sourceDir from
  // detection means nothing is mounted at /target.
  const suggestionDiffers = detected && detected.sourceDir && !dismissed && (
    detected.sourceDir !== p.sourceDir ||
    (detected.iacDir && detected.iacDir !== p.iacDir) ||
    (detected.projectName && detected.projectName !== p.sonarProjectKey)
  );

  const applyDetected = () => {
    if (!detected) return;
    const patch: Partial<typeof p> = { sourceDir: detected.sourceDir };
    if (detected.projectName) patch.sonarProjectKey = detected.projectName;
    if (detected.iacDir) patch.iacDir = detected.iacDir;
    save({ pipeline: patch as never });
    setDismissed(true);
  };

  return (
    <div className="card set-card">
      <div className="set-head">
        <h3>Pipeline target</h3>
        <span className="stat-sub">what "Run scan" actually scans</span>
      </div>
      <p className="set-note" style={{ marginTop: 0, marginBottom: 16 }}>
        These are the Jenkins job's own parameters: editing them changes what the next
        "Run scan" passes in. They start empty, or with the <span className="mono">SCAN_*</span> values
        given at install time, and are never changed without you. <strong>An empty field means
        that scanner is skipped</strong>, never pointed at a default project.
      </p>
      {!p.sourceDir && !p.iacDir && !p.targetImage && (
        <div className="scan-setup">
          <strong>Tell ThreatWeave what to scan</strong>
          <ol>
            <li>
              <b>Mount your project</b> when starting ThreatWeave, read-only:
              {' '}<span className="mono">-v /path/to/project:/target:ro -e TARGET_PATH=/path/to/project</span>
              {' '}(or <span className="mono">TARGET_PATH</span> in <span className="mono">.env</span>). ThreatWeave never changes your code.
            </li>
            <li><b>Source directory</b>: <span className="mono">/target</span>. GitLeaks looks for secrets, SonarQube for code vulnerabilities.</li>
            <li><b>IaC directory</b>: the folder with your Terraform, CloudFormation or CDK output (<span className="mono">cdk.out</span>), for Checkov.</li>
            <li><b>Container image</b>: the image you deploy, for example <span className="mono">myapp:latest</span>, for Trivy.</li>
            <li>Click <b>Run scan</b>. Fields left empty are skipped; AWS checks run whenever credentials are connected.</li>
          </ol>
          <p>
            To set these once at install time instead, add
            {' '}<span className="mono">-e SCAN_SOURCE_DIR=/target -e SCAN_IAC_DIR=/target/infra -e SCAN_IMAGE=myapp:latest</span>.
          </p>
        </div>
      )}
      {suggestionDiffers && (
        <div className="welcome-banner" style={{ marginBottom: 16 }}>
          <div className="welcome-text">
            <strong>{p.sourceDir ? 'Detected a different project mounted at /target' : 'Found a project mounted at /target'}</strong>
            <span>
              {detected!.projectName ? `Found "${detected!.projectName}" (from its package.json)` : 'Found a project'}
              {detected!.hasDockerfile ? ' with its own Dockerfile - build its image, then set it under Container image.' : '.'}
              {detected!.iacDir ? ` Infrastructure code found in ${detected!.iacDir}.` : ''}
              {' '}Apply these as the real scan target?
            </span>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            <button className="btn-primary" onClick={applyDetected}>Apply detected</button>
            <button className="btn-ghost" onClick={() => setDismissed(true)}>Dismiss</button>
          </div>
        </div>
      )}

      <label className="set-row hinted">
        <span className="set-label-group">
          <span className="set-label">Source directory {origin('sourceDir')}{!p.sourceDir && <span className="skip-tag">GitLeaks and SonarQube skipped</span>}</span>
          <span className="set-hint">What GitLeaks and SonarQube scan. Use <span className="mono">/target</span> for the project you mounted there.</span>
        </span>
        <input
          className="set-input"
          value={draft.sourceDir}
          onChange={(e) => setDraft({ ...draft, sourceDir: e.target.value })}
          onBlur={() => draft.sourceDir !== p.sourceDir && saveField('sourceDir', draft.sourceDir)}
          placeholder="/target"
        />
      </label>
      {checkLine('sourceDir')}

      <label className="set-row hinted">
        <span className="set-label-group">
          <span className="set-label">IaC directory {origin('iacDir')}{!p.iacDir && <span className="skip-tag">Checkov skipped</span>}</span>
          <span className="set-hint">Where your Terraform, CloudFormation or CDK output (<span className="mono">cdk.out</span>) lives, for example <span className="mono">/target/infra</span>. Leave empty if the project has none.</span>
        </span>
        <input
          className="set-input"
          value={draft.iacDir}
          onChange={(e) => setDraft({ ...draft, iacDir: e.target.value })}
          onBlur={() => draft.iacDir !== p.iacDir && saveField('iacDir', draft.iacDir)}
          placeholder="/target/infra"
        />
      </label>
      {detected?.sourceDir && (detected.iacCandidates?.length ?? 0) > 0 && (
        <div className="iac-candidates">
          <span>Found in your project:</span>
          {detected.iacCandidates!.map((c) => (
            <button
              key={c.path}
              type="button"
              className={`iac-chip ${c.path === p.iacDir ? 'active' : ''}`}
              onClick={() => { setDraft({ ...draft, iacDir: c.path }); saveField('iacDir', c.path); }}
              title="Use this folder for Checkov"
            >
              <span className="mono">{c.path}</span> · {iacKindLabel(c.kind, c.files)}
            </button>
          ))}
        </div>
      )}
      {detected?.sourceDir && (detected.iacCandidates?.length ?? 0) === 0 && !p.iacDir && (
        <div className="path-check path-check-warn">
          ⚠ No Terraform, CloudFormation or CDK output found in the project. Enter the folder yourself, or leave it empty to skip Checkov.
        </div>
      )}
      {checkLine('iacDir')}

      <label className="set-row hinted">
        <span className="set-label-group">
          <span className="set-label">Container image {origin('targetImage')}{!p.targetImage && <span className="skip-tag">Trivy skipped</span>}</span>
          <span className="set-hint">The image you deploy, which Trivy pulls and scans, for example <span className="mono">myapp:latest</span>. Leave empty if the project has no container.</span>
        </span>
        <input
          className="set-input"
          value={draft.targetImage}
          onChange={(e) => setDraft({ ...draft, targetImage: e.target.value })}
          onBlur={() => draft.targetImage !== p.targetImage && saveField('targetImage', draft.targetImage)}
          placeholder="leave blank to skip Trivy"
        />
      </label>
      {checkLine('targetImage')}

      <label className="set-row hinted">
        <span className="set-label-group">
          <span className="set-label">SonarQube project key {origin('sonarProjectKey')}</span>
          <span className="set-hint">A name for this project in SonarQube, for example <span className="mono">accesshub</span>. Empty uses the source folder's name.</span>
        </span>
        <input
          className="set-input"
          value={draft.sonarProjectKey}
          onChange={(e) => setDraft({ ...draft, sonarProjectKey: e.target.value })}
          onBlur={() => draft.sonarProjectKey !== p.sonarProjectKey && saveField('sonarProjectKey', draft.sonarProjectKey)}
          placeholder="my-project"
        />
      </label>

      <div className="set-row col">
        <span className="set-label">Run options</span>
        <div className="check-list">
          <label className="check-item">
            <input
              type="checkbox"
              checked={p.runAwsMonitor}
              onChange={(e) => saveField('runAwsMonitor', e.target.checked)}
            />
            <span className="check-name">AWS MONITOR</span>
            <span className="check-desc">Include live cloud governance checks in the run</span>
          </label>
          <label className="check-item">
            <input
              type="checkbox"
              checked={p.failOnCritical}
              onChange={(e) => saveField('failOnCritical', e.target.checked)}
            />
            <span className="check-name">FAIL ON CRITICAL</span>
            <span className="check-desc">Fail the build when the health score comes back critical</span>
          </label>
        </div>
      </div>

      {saving && <span className="set-msg">Saving…</span>}
    </div>
  );
}

/* ---------- Data sources: what actually fed this run, and what didn't ---------- */
const SOURCE_LABELS: Record<string, string> = {
  trivy: 'Trivy (container)',
  sonarqube: 'SonarQube (SAST)',
  gitleaks: 'GitLeaks (secrets)',
  checkov: 'Checkov (IaC)',
  aws: 'AWS monitor (cloud)',
};

/** Maps a Jenkinsfile stage name to the scanner it corresponds to, so a
 * live build's `currentStage` can highlight the matching source chip below.
 * Stages with no direct scanner (Checkout, Docker image build, ...) map to
 * null and are just skipped. */
const STAGE_TO_SOURCE: Record<string, string> = {
  // SonarQube's own multi-minute analysis runs as a detached container, not
  // inside either Jenkins stage that touches it: "(async)" launches it and
  // is done in seconds, then it works unattended through the Scans stage
  // (no chip shown for that span - accurate, nothing is actively waiting on
  // it yet), then "(harvest)" is where this run actually waits for/collects
  // its own result, which is why both map here rather than just the first.
  'SAST - SonarQube (async)': 'sonarqube',
  'SAST - SonarQube (harvest)': 'sonarqube',
  'Secrets - GitLeaks': 'gitleaks',
  'Container - Trivy': 'trivy',
  'IaC - Checkov': 'checkov',
  // The AWS monitor has no stage of its own - see isAwsMonitorRunning.
};

function DataSources({ sources, scan, elapsedLabel, asyncSonarScan, onOpenSettings }: {
  sources: SourceStatus[]; scan?: PipelineStatus | null; elapsedLabel?: string | null;
  asyncSonarScan?: AsyncSonarScanStatus | null; onOpenSettings?: () => void;
}) {
  const label = (s: SourceStatus) => SOURCE_LABELS[s.source] ?? s.source;
  const failed = sources.filter((s) => s.status === 'failed');
  // "not configured" is fixed in Settings; any other skip reason is not.
  const skipped = sources.filter((s) => s.status === 'skipped' && (s.detail ?? 'not configured') === 'not configured');
  const turnedOff = sources.filter((s) => s.status === 'skipped' && !skipped.includes(s));
  const stale = sources.filter((s) => s.status === 'stale');
  const unexplained = sources.filter((s) => s.status === 'missing' || s.status === 'error');
  // The scanners run as parallel branches (see the Jenkinsfile), so more
  // than one is often genuinely active at once - every chip touched so far
  // this run is highlighted, not just whichever produced the most recent
  // console line. activeStages also picks up non-scanner stages (Checkout,
  // the wrapping "Scans" stage itself) via the same console markers, so
  // this is filtered down to real scanners for both the chip set and the
  // "N scanners in parallel" count above.
  const activeScannerStages = (scan?.activeStages ?? []).filter((s) => s in STAGE_TO_SOURCE);
  const runningSources = new Set(activeScannerStages.map((s) => STAGE_TO_SOURCE[s]));
  // The async scan can be genuinely working with no build around to have
  // touched a stage marker at all (see the dedicated banner below) - the
  // chip should still reflect that. Specifically 'running', not just
  // `scanning` (true for 'finished-pending-harvest' too) - confirmed live,
  // the chip kept showing "scanning now…" for a container Docker Desktop
  // already showed as stopped/exited, simply waiting for a later run to
  // harvest its results, not doing any work any more.
  if (asyncSonarScan?.phase === 'running') runningSources.add('sonarqube');
  if (isAwsMonitorRunning(scan?.activeStages, scan?.currentActivity)) runningSources.add('aws');
  return (
    <section className="block sources-block">
      {/* Distinct from the `scan` banner below: a build waiting on this
          exact scan already shows it via its own currentActivity, but
          between builds - the whole reason this scan runs detached - there
          is often no build around to report it at all. Confirmed live:
          pipeline state "success" (idle) while the scan container was
          still genuinely running, with nothing on the dashboard saying so. */}
      {!scan && asyncSonarScan?.scanning && (
        <div className="scan-progress-row async-sonar-row">
          {/* A spinner on "finished scanning" text reads as still working -
              only genuinely true for 'running'. */}
          {asyncSonarScan.phase === 'running' && <span className="spinner" />}
          <div className="scan-progress-text">
            <span className="scan-progress-stage">
              {asyncSonarScan.phase === 'running'
                ? 'SonarQube is scanning in the background'
                : 'SonarQube finished scanning - results will be picked up by the next run'}
            </span>
            <span className="scan-progress-activity">
              {asyncSonarScan.runId && `started by ${asyncSonarScan.runId}`}
              {asyncSonarScan.ageMinutes != null && (
                asyncSonarScan.phase === 'running'
                  ? ` · ${asyncSonarScan.ageMinutes} min so far`
                  : ` · launched ~${asyncSonarScan.ageMinutes} min ago`
              )}
            </span>
          </div>
        </div>
      )}
      {scan && (
        <div className="scan-progress-row">
          <span className="spinner" />
          <div className="scan-progress-text">
            {/* currentStage only changes when a NEW stage/branch marker
                appears in the console - with four scanners kicking off
                within moments of each other, whichever one's marker happens
                to print last "wins" and then never changes again for the
                rest of the run (observed live: stuck on "IaC - Checkov" for
                12+ minutes while SonarQube was still actively working).
                currentActivity is the real, continuously-updating signal -
                it belongs in this banner as the primary text, not buried
                behind a frozen stage label. */}
            <span className="scan-progress-stage">
              {scan.state === 'queued' ? 'Queued, waiting for a Jenkins executor'
                : activeScannerStages.length > 1 ? `Running ${activeScannerStages.length} scanners in parallel`
                  : scan.currentStage ?? 'Starting…'}
            </span>
            {scan.currentActivity && <span className="scan-progress-activity">{scan.currentActivity}</span>}
          </div>
          {elapsedLabel && <span className="scan-elapsed">{elapsedLabel}</span>}
          {scan.stalled && <span className="scan-progress-warn">quiet for a while - still watching</span>}
        </div>
      )}
      {sources.length > 0 && (
      <div className="sources-row">
        {sources.map((s) => {
          const running = runningSources.has(s.source);
          return (
            <span
              key={s.source}
              className={`source-chip source-${s.status}${running ? ' source-running' : ''}`}
              title={
                running ? 'Scanning now - the count shown is still from the last completed run'
                  : s.status === 'ok' ? `${s.findings} findings`
                    : s.status === 'error' ? `Report was present but could not be read: ${s.detail ?? 'unknown error'}`
                      : s.status === 'skipped' ? ((s.detail ?? 'not configured') === 'not configured' ? 'Skipped - no target is set for this scanner in Settings → Pipeline target' : `Skipped - ${s.detail}`)
                        : s.status === 'failed' ? `The scanner failed this run: ${s.detail ?? 'see the Jenkins log'}`
                          : s.status === 'stale' ? `${s.findings} findings reused from an earlier scan of this project - this run's own scan did not finish`
                            : 'No report was produced for this run - the scanner may be disabled, not configured, or its stage failed'
              }
            >
              <span className="source-dot" />
              {SOURCE_LABELS[s.source] ?? s.source}
              {running && <span className="source-reason">scanning now…</span>}
              {!running && s.status === 'ok' && <span className="source-count">{s.findings}</span>}
              {!running && s.status === 'missing' && <span className="source-reason">no report</span>}
              {!running && s.status === 'error' && <span className="source-reason">unreadable</span>}
              {!running && s.status === 'skipped' && <span className="source-reason">{skipped.includes(s) ? 'skipped – not set' : 'off'}</span>}
              {!running && s.status === 'failed' && <span className="source-reason">failed</span>}
              {!running && s.status === 'stale' && <><span className="source-count">{s.findings}</span><span className="source-reason">carried over</span></>}
            </span>
          );
        })}
      </div>
      )}
      {scan && sources.length > 0 && (
        <p className="sources-note">
          A scan is currently running - the numbers above are still from the last completed run
          and will update once this one finishes.
        </p>
      )}
      {!scan && failed.map((s) => (
        <p key={s.source} className="sources-note sources-note-failed">
          <strong>{label(s)} failed this run:</strong> {s.detail ?? 'see the Jenkins log'}. The other
          scanners still ran, and the numbers below use their results.
        </p>
      ))}
      {!scan && stale.length > 0 && (
        <p className="sources-note sources-note-stale">
          {stale.map(label).join(', ')} results are <strong>carried over from an earlier scan</strong> of
          this project - this run's own scan did not finish, so recent code changes may not be reflected yet.
        </p>
      )}
      {!scan && skipped.length > 0 && (
        <p className="sources-note">
          {skipped.map(label).join(', ')} {skipped.length === 1 ? 'was' : 'were'} skipped because no
          target is set.{' '}
          {onOpenSettings && <button type="button" className="link-btn" onClick={onOpenSettings}>Set it in Settings →</button>}
        </p>
      )}
      {!scan && turnedOff.map((s) => (
        <p key={s.source} className="sources-note">{label(s)} was skipped: {s.detail}.</p>
      ))}
      {!scan && unexplained.length > 0 && (
        <p className="sources-note">
          {unexplained.map(label).join(', ')} did not contribute data to this run. That is not
          necessarily a problem (SAST is off unless <code>SONAR_HOST_URL</code> is set, for
          instance) but it does mean the health score and finding counts below are based on
          fewer sources this time.
        </p>
      )}
    </section>
  );
}

/* ---------- Noise-reduction funnel ---------- */
function Funnel({ data }: { data: AiopsOutput }) {
  const raw = data.summary.raw_findings;
  const suppressed = data.summary.suppressed ?? 0;
  const final = data.summary.after_dedup;
  const merged = raw - final - suppressed;
  const afterMerge = raw - merged;

  // Every bar width below is a percentage of `raw` - dividing by zero before
  // any scan has run would render every bar as NaN% instead of empty.
  if (raw === 0) {
    return <div className="donut-empty">No scan has run yet - this will fill in once one completes.</div>;
  }

  // Every stage's `n` is a running total (monotonically non-increasing), not
  // a per-step delta - a funnel only reads as a funnel when width tracks
  // "how much is left," not "how much was removed at this step." The delta
  // is still shown, as the `removed` annotation, so nothing about *why* the
  // count dropped is lost. Built explicitly per case (rather than generically
  // appending an "actionable findings" stage) so a step that removed nothing
  // never produces a stage whose number duplicates the one before it.
  type Stage = { label: string; n: number; cls: string; removed?: number; removedWhy?: string };
  const stages: Stage[] = [{ label: 'Raw findings from all tools', n: raw, cls: 'raw' }];
  if (merged > 0) {
    stages.push({
      label: suppressed > 0 ? 'After merging duplicates & grouping by remediation' : 'Actionable findings',
      n: afterMerge, cls: suppressed > 0 ? 'merged' : 'final', removed: merged, removedWhy: 'merged',
    });
  }
  if (suppressed > 0) {
    stages.push({ label: 'Actionable findings', n: final, cls: 'final', removed: suppressed, removedWhy: 'suppressed' });
  }
  if (merged === 0 && suppressed === 0) {
    stages.push({ label: 'Actionable findings', n: final, cls: 'final' });
  }

  return (
    <div className="funnel">
      {stages.map((s, i) => (
        <div className="funnel-stage" key={s.label}>
          <span className={`funnel-badge funnel-badge-${s.cls}`}>{i + 1}</span>
          <div className="funnel-stage-body">
            <div className="funnel-stage-top">
              <span className="funnel-stage-label">{s.label}</span>
              <span className={`funnel-stage-n funnel-stage-n-${s.cls}`}>
                {s.n} <span className="funnel-stage-pct">({((s.n / raw) * 100).toFixed(0)}%)</span>
              </span>
            </div>
            <span className="funnel-bar-wrap">
              <span className={`funnel-bar funnel-bar-${s.cls}`} style={{ width: `${(s.n / raw) * 100}%` }} />
            </span>
            {s.removed != null && (
              <span className="funnel-removed">−{s.removed} {s.removedWhy} this step</span>
            )}
          </div>
          {i < stages.length - 1 && <span className="funnel-connector" />}
        </div>
      ))}
      {(data.suppressions?.length ?? 0) > 0 && (
        <div className="sup-list">
          {data.suppressions!.filter((s) => s.suppressed_count > 0).map((s) => (
            <div className="sup-item" key={s.id}>
              <span className="sup-count">{s.suppressed_count}</span>
              <span className="sup-reason">{s.reason}</span>
              <span className="sup-by">{s.created_by}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ---------- Attack-path visual chain ---------- */
const STAGE_ICONS: Record<string, ReactNode> = {
  code: (<><path d="M8 8l-4 4 4 4" /><path d="M16 8l4 4-4 4" /><path d="M13 6l-2 12" /></>),
  container: (<><rect x="3" y="7" width="18" height="12" rx="1.5" /><path d="M3 11h18M8 7V5h8v2" /></>),
  cloud: (<><path d="M17 17a4 4 0 001-7.9A5.5 5.5 0 006.5 8 4.5 4.5 0 007 17h10z" /><path d="M12 12v5M9.5 14.5L12 12l2.5 2.5" /></>),
  dot: (<circle cx="12" cy="12" r="3" />),
};

function AttackChain({ path }: { path: string }) {
  const steps = path.split('->').map((s) => s.trim());
  const stageOf = (text: string): { kind: string; stage: string } => {
    const t = text.toLowerCase();
    if (t.includes('code') || t.includes('sonar')) return { kind: 'code', stage: 'Source Code' };
    if (t.includes('container') || t.includes('trivy') || t.includes('image')) return { kind: 'container', stage: 'Container' };
    if (t.includes('internet') || t.includes('exposed') || t.includes('aws') || t.includes('sg')) return { kind: 'cloud', stage: 'Cloud Exposure' };
    return { kind: 'dot', stage: 'Finding' };
  };
  return (
    <div className="chain">
      {steps.map((s, i) => {
        const { kind, stage } = stageOf(s);
        const label = s.replace(/\(([^)]+)\)/, '').trim();
        const tool = s.match(/\(([^)]+)\)/)?.[1];
        return (
          <div className="chain-seg" key={i}>
            <div className={`chain-node node-${kind}`}>
              <span className="chain-step">Step {i + 1} · {stage}</span>
              <div className="chain-main">
                <span className="chain-icon">
                  <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{STAGE_ICONS[kind]}</svg>
                </span>
                <span className="chain-texts">
                  <span className="chain-label">{label}</span>
                  {tool && <span className="chain-tool">{tool}</span>}
                </span>
              </div>
            </div>
            {i < steps.length - 1 && (
              <div className="chain-arrow">
                <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12h15M13 6l6 6-6 6" /></svg>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ---------- Expandable cluster card ---------- */
function ClusterCard({ c, findingById, defaultOpen = false }: { c: Cluster; findingById: (id: string) => Finding | undefined; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const members = c.finding_ids.map(findingById).filter(Boolean) as Finding[];
  return (
    <div className="cluster">
      <button className="cluster-head" onClick={() => setOpen(!open)}>
        <span className="cluster-title">
          <svg className={`caret ${open ? 'open' : ''}`} viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 6l6 6-6 6" /></svg>
          {c.title}
        </span>
        <span className="cluster-meta"><span className="member-count">{c.finding_ids.length} findings</span><span className="risk-pill bad">{c.risk_score}</span></span>
      </button>

      <AttackChain path={c.attack_path} />

      <div className="expl">
        <div className="expl-row"><span className="lbl">Why it matters</span><span className="val">{c.explanation.why_it_matters}</span></div>
        <div className="expl-row"><span className="lbl">What is at risk</span><span className="val">{c.explanation.what_is_at_risk}</span></div>
        <div className="expl-row"><span className="lbl">Recommended action</span><span className="val">{c.explanation.recommended_action}</span></div>
      </div>

      {open && members.length > 0 && (
        <div className="members">
          <span className="members-title">Correlated findings in this path</span>
          {members.map((m) => (
            <div className="member" key={m.id}>
              <span className={`sev sev-${m.severity.toLowerCase()}`}>{m.severity}</span>
              <div className="member-body">
                <span className="member-title">{m.title}</span>
                <span className="member-res mono">{m.affected_resource}</span>
              </div>
              <span className="member-src">{m.source}</span>
              <ScoreCell f={m} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ---------- Shared score breakdown ---------- */
type ScorePart = { key: string; label: string; w: number; v: number };

function scoreParts(f: Finding): ScorePart[] {
  return [
    { key: 'P_RF', label: 'ML probability', w: 0.45, v: f.scores.P_RF },
    { key: 'S_retrieval', label: 'Retrieval (BM25)', w: 0.25, v: f.scores.S_retrieval },
    { key: 'S_asset', label: 'Asset exposure', w: 0.20, v: f.scores.S_asset },
    { key: 'S_EPSS', label: 'Exploit (EPSS)', w: 0.10, v: f.scores.S_EPSS },
  ];
}

const SEV_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const scoreBand = (n: number) => (n >= 80 ? 3 : n >= 50 ? 2 : n >= 25 ? 1 : 0);

/** Plain-language note comparing the source tool's severity label to the
 * computed risk score. Always returns something, even when the two roughly
 * agree — a finding with nothing shown here used to be indistinguishable
 * from one where the explanation was simply missing/broken; a same-numbered
 * score can be a big surprise for one severity label and unremarkable for
 * another (a CRITICAL landing at 47 is a steep drop; a LOW landing at 47 is
 * a much smaller rise), so the "nothing unusual" case gets said explicitly
 * rather than left to look like an omission. */
function reasoningNote(f: Finding): { text: string; mismatch: boolean } {
  const sevBand = SEV_RANK[f.severity] ?? 2;
  const riskBand = scoreBand(f.risk_score);
  const tools = f.reported_by.join('/');
  // LOW/INFO severity (band <=1) but a mid/high risk score (band >=2), or
  // the reverse: CRITICAL/HIGH severity but the score landed low.
  const higher = sevBand <= 1 && riskBand >= 2;
  const lower = sevBand >= 3 && riskBand <= 1;

  if (!higher && !lower) {
    return {
      mismatch: false,
      text: `${f.risk_score} is within the expected range for a ${tools}-reported "${f.severity}" ` +
        `finding — nothing here points to a signal strong enough to move it notably higher or lower.`,
    };
  }

  const parts = scoreParts(f);
  const bySignal = (keys: string[]) =>
    parts.filter((p) => keys.includes(p.key)).sort((a, b) => b.v - a.v)[0];
  const textSignal = bySignal(['P_RF', 'S_retrieval']);
  const exposureSignal = bySignal(['S_asset', 'S_EPSS']);

  if (higher) {
    return {
      mismatch: true,
      text: `ThreatWeave scored this higher than ${tools}'s own "${f.severity}" label because ` +
        `${textSignal.label} rated the finding's text as ${(textSignal.v * 100).toFixed(0)}% likely severe, ` +
        `independently of that label — the severity tag is what ${tools} reported, the ${f.risk_score} is ThreatWeave's own composite estimate. ` +
        `${exposureSignal.label} is only ${(exposureSignal.v * 100).toFixed(0)}%, which is what keeps it from scoring even higher.`,
    };
  }
  return {
    mismatch: true,
    text: `ThreatWeave scored this lower than ${tools}'s own "${f.severity}" label because the model and ` +
      `retrieval signals did not find the finding's text to closely resemble known severe cases, and ` +
      `${exposureSignal.label} is only ${(exposureSignal.v * 100).toFixed(0)}% — nothing here confirms it is reachable or actively exploited.`,
  };
}

/* A small radial gauge instead of a plain numeric badge - severity readable
 * by how much of the ring is filled, at a glance, before reading the
 * number at all (the same idea behind DefectDojo's own "Risk" column). */
function RiskGauge({ score, cls }: { score: number; cls: string }) {
  const r = 15;
  const c = 2 * Math.PI * r;
  const filled = Math.max(0, Math.min(100, score)) / 100 * c;
  return (
    <svg className={`risk-gauge ${cls}`} width="38" height="38" viewBox="0 0 36 36">
      <circle cx="18" cy="18" r={r} className="risk-gauge-track" />
      <circle
        cx="18" cy="18" r={r} className="risk-gauge-fill"
        strokeDasharray={`${filled} ${c}`}
        transform="rotate(-90 18 18)"
      />
      <text x="18" y="19" textAnchor="middle" dominantBaseline="middle" className="risk-gauge-text">{score}</text>
    </svg>
  );
}

/* ---------- Risk score with breakdown tooltip ---------- */
function ScoreCell({ f }: { f: Finding }) {
  const cls = f.risk_score >= 80 ? 'bad' : f.risk_score >= 50 ? 'warn' : 'good';
  const parts = scoreParts(f);
  return (
    <span className="score-cell">
      <RiskGauge score={f.risk_score} cls={cls} />
      <div className="score-pop">
        <div className="pop-head">Risk breakdown <span className="pop-formula">0.45·P<sub>RF</sub> + 0.25·S<sub>ret</sub> + 0.20·S<sub>asset</sub> + 0.10·S<sub>EPSS</sub></span></div>
        {parts.map((p) => (
          <div className="pop-row" key={p.key}>
            <span className="pop-label">{p.label}<span className="pop-w">×{p.w}</span></span>
            <span className="pop-bar"><span className="pop-fill" style={{ width: `${p.v * 100}%` }} /></span>
            <span className="pop-val">{formatScoreValue(p.v)}</span>
          </div>
        ))}
        <div className="pop-foot">Confidence: <strong>{f.confidence}</strong></div>
      </div>
    </span>
  );
}

/* ---------- Generic collapsible section for the finding detail panel ----------
 * The detail panel accumulated a lot of real, useful content (technical
 * description, score breakdown, metadata, related CVEs) that read fine one
 * at a time but became overwhelming stacked flat with equal visual weight -
 * a reader could not tell what to look at first. Each section is its own,
 * independently-collapsed accordion item so only what someone actually
 * wants to dig into takes up space; everything else stays a one-line,
 * scannable header. */
function DetailSection({ title, defaultOpen = false, children }: {
  title: ReactNode; defaultOpen?: boolean; children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={`detail-section ${open ? 'open' : ''}`}>
      <button type="button" className="detail-section-head" onClick={() => setOpen((v) => !v)}>
        <svg className={`detail-caret ${open ? 'open' : ''}`} viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M9 6l6 6-6 6" /></svg>
        <span className="detail-section-title">{title}</span>
      </button>
      {open && <div className="detail-section-body">{children}</div>}
    </div>
  );
}

/* ---------- Always-visible: the short "why" sentence, not the full breakdown ---------- */
function ScoreSummary({ f }: { f: Finding }) {
  const note = reasoningNote(f);
  const cls = f.risk_score >= 80 ? 'bad' : f.risk_score >= 50 ? 'warn' : 'good';
  return (
    <div className="reasoning-summary">
      <span className="reasoning-compare">
        {f.reported_by.join('/')} reported <span className={`sev sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
        <span className="reasoning-vs">→</span>
        ThreatWeave computed <span className={`risk-pill ${cls}`}>{f.risk_score}</span>
      </span>
      <p className={`reasoning-note ${note.mismatch ? '' : 'reasoning-note-plain'}`}>{note.text}</p>
    </div>
  );
}

/* ---------- Inside the "Score breakdown" section: the four factor bars ---------- */
function ScoreBreakdown({ f }: { f: Finding }) {
  const parts = scoreParts(f);
  // Collapsed by default: the four bars alone are already fairly compact -
  // the per-factor evidence sentences (which words drove the ML score,
  // which known CVEs it resembles, ...) are real and worth keeping, but
  // showing all of them by default made this one section alone taller than
  // the rest of the panel combined. One toggle for the whole set, not
  // per-row - "just the numbers" and "explain everything" are the two
  // states worth having, not a mix.
  const [showEvidence, setShowEvidence] = useState(false);
  const hasEvidence = parts.some((p) => evidenceText(p.key, f));
  return (
    <div className="reasoning">
      <div className="reasoning-bars">
        {parts.map((p) => {
          const evidence = evidenceText(p.key, f);
          return (
            <div className="reasoning-row-wrap" key={p.key}>
              <div className="reasoning-row">
                <span className="reasoning-label">{p.label}<span className="pop-w">×{p.w}</span></span>
                <span className="reasoning-bar"><span className="reasoning-fill" style={{ width: `${p.v * 100}%` }} /></span>
                <span className="reasoning-val">{formatScoreValue(p.v)}</span>
              </div>
              {showEvidence && evidence && <p className="reasoning-evidence">{evidence}</p>}
            </div>
          );
        })}
      </div>
      {hasEvidence && (
        <button type="button" className="reasoning-evidence-toggle" onClick={() => setShowEvidence((v) => !v)}>
          {showEvidence ? '▾ Hide evidence' : '▸ Show evidence for each factor'}
        </button>
      )}
      <p className="reasoning-formula">0.45·P<sub>RF</sub> + 0.25·S<sub>ret</sub> + 0.20·S<sub>asset</sub> + 0.10·S<sub>EPSS</sub> — the severity badge is the source tool's own label and is never overwritten; the score is ThreatWeave's independent estimate.</p>
    </div>
  );
}

/* ---------- Scan-by-shape summary cards: kind, exposure, fix ----------
 * One consistent icon per card *type* (not one icon per possible kind
 * label, which would need maintaining a mapping for every current and
 * future template) - the shield always means "what kind of issue",
 * globe/lock always means "reachability", wrench always means "the fix".
 * Recognising the shape is what makes this faster to scan than reading a
 * sentence, matching how Snyk/Dependabot lead with a compact summary
 * before the full detail. */
function ShieldAlertIcon() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M12 8v4M12 16h.01" />
    </svg>
  );
}
function GlobeIcon() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z" />
    </svg>
  );
}
function LockIcon() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="11" width="16" height="9" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </svg>
  );
}
function WrenchIcon() {
  return (
    <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L4 17l3 3 5.3-5.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2-2z" />
    </svg>
  );
}

function SummaryCards({ f }: { f: Finding }) {
  return (
    <div className="summary-cards">
      {f.explanation_kind && (
        <span className="summary-card kind">
          <ShieldAlertIcon />
          {f.explanation_kind}
        </span>
      )}
      <span className={`summary-card ${f.internet_facing ? 'exposed' : ''}`}>
        {f.internet_facing ? <GlobeIcon /> : <LockIcon />}
        {f.internet_facing ? 'Internet-facing' : 'Internal only'}
      </span>
      {f.explanation_fix && (
        <span className="summary-card fix" title={f.explanation_fix}>
          <WrenchIcon />
          {f.explanation_fix}
        </span>
      )}
    </div>
  );
}

/* ---------- Expandable finding row ---------- */
function FindingRow({ f, isOpen, onToggle, clusters, onReload }: {
  f: Finding; isOpen: boolean; onToggle: () => void; clusters: Cluster[]; onReload: () => void;
}) {
  const cluster = f.cluster_id ? clusters.find((c) => c.cluster_id === f.cluster_id) : undefined;
  const detail = (label: string, value: ReactNode) => (
    <div className="d-item"><span className="d-label">{label}</span><span className="d-value">{value}</span></div>
  );
  return (
    <>
      <tr className={`f-row ${isOpen ? 'open' : ''}`} onClick={onToggle}>
        <td className="caret-cell">
          <svg className={`caret ${isOpen ? 'open' : ''}`} viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 6l6 6-6 6" /></svg>
        </td>
        <td><ScoreCell f={f} /></td>
        <td><span className={`sev sev-${f.severity.toLowerCase()}`}>{f.severity}</span></td>
        <td className="title-cell">
          {f.title}
          {(f.merged_count ?? 1) > 1 && <span className="tag grouped">{f.merged_count} CVEs · 1 fix</span>}
          {f.internet_facing && <span className="tag">internet-facing</span>}
          {describeFindingAge(f.first_seen) && <span className="tag age">{describeFindingAge(f.first_seen)}</span>}
        </td>
        <td>{f.reported_by.join(', ')}</td>
        <td className="mono">{f.affected_resource}</td>
        <td>{f.confidence}</td>
      </tr>
      {isOpen && (
        <tr className="detail-row">
          <td colSpan={7}>
            <div className="detail">
              {/* Always visible: scan-by-shape cards for what kind of issue
                  this is, whether it's reachable, and what to do - the same
                  three facts the old paragraph carried, but as something a
                  reader can take in at a glance instead of parsing a
                  sentence for. The full sentence stays too, just visually
                  secondary now, for anyone who wants the complete reasoning
                  rather than the summary. Everything past this point is
                  real, but supporting - opened on demand. */}
              <SummaryCards f={f} />
              <p className="d-expl">{f.explanation}</p>
              <ScoreSummary f={f} />

              {cluster && (
                <div className="d-cluster">
                  <span className="d-cluster-tag">Part of attack path</span>
                  <span className="d-cluster-title">{cluster.title}</span>
                  <span className="risk-pill bad">{cluster.risk_score}</span>
                </div>
              )}

              <div className="detail-sections">
                {isRealDescription(f.description) && f.description !== f.explanation && (
                  <DetailSection title="What this actually is">
                    <p className="d-technical-text">{f.description}</p>
                  </DetailSection>
                )}

                <DetailSection title="Score breakdown">
                  <ScoreBreakdown f={f} />
                </DetailSection>

                <DetailSection title="Details">
                  <div className="d-grid">
                    {detail('Location / Resource', <span className="mono">{f.affected_resource}</span>)}
                    {detail('Reported by', f.reported_by.join(', '))}
                    {detail('Type', f.type)}
                    {detail('Environment', f.environment)}
                    {detail('Internet facing', f.internet_facing ? 'Yes — publicly reachable' : 'No — internal only')}
                    {f.cve_id && detail('CVE', <a className="cve-link" href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noreferrer">{f.cve_id} ↗</a>)}
                    {f.cvss_score != null && detail('CVSS base score', f.cvss_score.toFixed(1))}
                    {detail('Confidence', <span title={confidenceExplanation(f)}>{f.confidence}</span>)}
                    {f.first_seen && detail('First detected', new Date(f.first_seen).toLocaleString())}
                    {f.last_seen && detail('Last seen', new Date(f.last_seen).toLocaleString())}
                  </div>
                  <p className="d-confidence-note">{confidenceExplanation(f)}</p>
                </DetailSection>

                {(f.related_cves?.length ?? 0) > 1 && (
                  <DetailSection title={`All ${f.related_cves!.length} CVEs cleared by this one upgrade`}>
                    <div className="cve-chips">
                      {f.related_cves!.map((c) => (
                        c.startsWith('CVE-')
                          ? <a key={c} className="cve-chip" href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer">{c}</a>
                          : <span key={c} className="cve-chip">{c}</span>
                      ))}
                    </div>
                  </DetailSection>
                )}
              </div>

              <DismissPanel f={f} onDone={onReload} />
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

/* ---------- Dismiss / suppress a finding ---------- */
function DismissPanel({ f, onDone }: { f: Finding; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [scope, setScope] = useState<'this' | 'rule' | 'path'>('this');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Which findings the chosen scope will match on future runs.
  const scopes = [
    { id: 'this' as const, label: 'Only this finding', hint: f.cve_id ?? f.affected_resource },
    ...(f.rule_id ? [{ id: 'rule' as const, label: `All "${f.rule_id}" from ${f.source}`, hint: 'same tool rule' }] : []),
    { id: 'path' as const, label: 'This path pattern', hint: dirGlob(f.affected_resource) },
  ];

  const submit = async () => {
    if (!reason.trim()) { setErr('A reason is required'); return; }
    setBusy(true); setErr(null);
    try {
      const body: NewSuppression = { reason: reason.trim(), created_by: 'dashboard' };
      if (scope === 'this') {
        if (f.cve_id) body.cve_id = f.cve_id;
        else {
          // source + resource_pattern alone is too broad whenever a tool
          // reports more than one distinct check against the same
          // resource - confirmed live: Checkov flagged 7 different checks
          // against one S3 bucket, all sharing the exact same
          // affected_resource string, so "only this finding" ended up
          // suppressing all 7 instead of the one the analyst actually
          // picked. rule_id (when the finding has one) narrows the match
          // back down to that single check.
          body.source = f.source;
          body.resource_pattern = f.affected_resource;
          if (f.rule_id) body.rule_id = f.rule_id;
        }
      } else if (scope === 'rule') {
        body.source = f.source;
        body.rule_id = f.rule_id!;
      } else {
        body.source = f.source;
        body.resource_pattern = dirGlob(f.affected_resource);
      }
      await api.createSuppression(body);
      setOpen(false); setReason('');
      await rescoreAfterSuppressionChange();
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <div className="dismiss-bar">
        <button className="dismiss-btn" onClick={() => setOpen(true)}>
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M18 6L6 18M6 6l12 12" /></svg>
          Dismiss as false positive
        </button>
        <span className="dismiss-note">Suppressed findings are filtered on future runs and can be restored.</span>
      </div>
    );
  }

  return (
    <div className="dismiss-form">
      <span className="d-label">Suppress which findings?</span>
      <div className="scope-opts">
        {scopes.map((s) => (
          <label key={s.id} className={`scope-opt ${scope === s.id ? 'on' : ''}`}>
            <input type="radio" name={`scope-${f.id}`} checked={scope === s.id} onChange={() => setScope(s.id)} />
            <span className="scope-label">{s.label}</span>
            <span className="scope-hint mono">{s.hint}</span>
          </label>
        ))}
      </div>
      <input
        className="reason-input"
        placeholder="Reason (required) — e.g. test fixture, accepted risk, not exploitable here"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
      />
      {err && <span className="form-err">{err}</span>}
      <div className="form-actions">
        <button className="btn-primary" onClick={submit} disabled={busy}>
          {busy ? 'Saving…' : 'Suppress'}
        </button>
        <button className="btn-ghost" onClick={() => { setOpen(false); setErr(null); }}>Cancel</button>
      </div>
    </div>
  );
}

/** Short date label for a chart x-axis, e.g. "Aug 29, 14:20" - distinct from
 * a full ISO timestamp because axis space is tight and several runs on the
 * same day need to stay distinguishable. Falls back to the raw run_id if
 * generated_at is missing or unparseable, so an axis label is never blank. */
function shortRunLabel(p: HistoryPoint): string {
  const d = new Date(p.generated_at);
  if (Number.isNaN(d.getTime())) return p.run_id;
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) +
    ', ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

/** Axis tick that leads with time, not date - pipeline runs are frequent
 * enough (several per day, sometimes minutes apart) that a run of "Aug 29 /
 * Aug 29 / Aug 29" date-only ticks looks organised but says nothing: every
 * shown run that day is indistinguishable from the others. The date is
 * still shown, but only on the first tick and on the first tick after the
 * date actually changes - exactly where it carries information. */
function axisTickLabel(p: HistoryPoint, showDate: boolean): string {
  const d = new Date(p.generated_at);
  if (Number.isNaN(d.getTime())) return p.run_id;
  const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
  if (!showDate) return time;
  return `${d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}, ${time}`;
}

/* ---------- Health trend line chart (pure SVG) ---------- */
function TrendChart({ points }: { points: HistoryPoint[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const W = 640, H = 230, padL = 34, padR = 16, padT = 14, padB = 60;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const xs = points.map((_, i) => padL + (points.length === 1 ? plotW / 2 : (i * plotW) / (points.length - 1)));
  const y = (score: number) => padT + plotH - (score / 100) * plotH;
  const ys = points.map((p) => y(p.health_score));
  const line = xs.map((x, i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${ys[i].toFixed(1)}`).join(' ');
  const area = `${line} L${xs[xs.length - 1].toFixed(1)},${padT + plotH} L${xs[0].toFixed(1)},${padT + plotH} Z`;
  // Every label would overlap on a long run history - thin them out so at
  // most ~5 are drawn (date-only ticks, rotated, still need real width),
  // always keeping the first and last run visible.
  const labelStep = Math.max(1, Math.ceil(points.length / 5));
  const active = hover ?? points.length - 1;
  const activePoint = points[active];

  return (
    <div className="trend-wrap">
      <div className="trend-legend">
        <span>Health score (0–100, higher is healthier)</span>
        <span className="trend-legend-swatches">
          <span className="trend-swatch good" />Healthy 80+
          <span className="trend-swatch warn" />At risk 50–79
          <span className="trend-swatch bad" />Critical &lt;50
        </span>
      </div>
      <svg className="trend" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet">
        {/* Risk-zone background bands, so the line's position reads as
            good/at-risk/critical at a glance instead of needing the y-axis
            numbers decoded first. */}
        <rect x={padL} y={y(100)} width={plotW} height={y(80) - y(100)} className="trend-band good" />
        <rect x={padL} y={y(80)} width={plotW} height={y(50) - y(80)} className="trend-band warn" />
        <rect x={padL} y={y(50)} width={plotW} height={y(0) - y(50)} className="trend-band bad" />

        {[0, 25, 50, 75, 100].map((g) => (
          <g key={g}>
            <line x1={padL} y1={y(g)} x2={W - padR} y2={y(g)} className="grid-line" />
            <text x={padL - 6} y={y(g) + 3} textAnchor="end" className="grid-text">{g}</text>
          </g>
        ))}

        {(() => {
          let lastDate: string | null = null;
          return points.map((p, i) => {
            if (!(i === 0 || i === points.length - 1 || i % labelStep === 0)) return null;
            const d = new Date(p.generated_at);
            const dateKey = Number.isNaN(d.getTime()) ? null : d.toDateString();
            const showDate = lastDate === null || dateKey !== lastDate;
            lastDate = dateKey;
            return (
              <text
                key={`lbl-${p.run_id}`} x={xs[i]} y={H - padB + 18} textAnchor="end" className="trend-x-text"
                transform={`rotate(-35 ${xs[i]} ${H - padB + 18})`}
              >
                {axisTickLabel(p, showDate)}
              </text>
            );
          });
        })()}

        <path d={area} className="trend-area" />
        <path d={line} className="trend-line" />

        {active != null && <line x1={xs[active]} y1={padT} x2={xs[active]} y2={padT + plotH} className="trend-guide" />}

        {points.map((p, i) => (
          <circle
            key={p.run_id}
            cx={xs[i]} cy={ys[i]} r={i === active ? 6 : 4}
            className={`trend-dot ${healthLabel(p.health_score).cls}`}
            onMouseEnter={() => setHover(i)}
            onMouseLeave={() => setHover(null)}
          />
        ))}
      </svg>
      {activePoint && (
        <div className="trend-tooltip">
          <span className="trend-tooltip-run">{activePoint.run_id}</span>
          <span className="trend-tooltip-date">{shortRunLabel(activePoint)}</span>
          <span className={`trend-tooltip-score ${healthLabel(activePoint.health_score).cls}`}>
            {activePoint.health_score} · {healthLabel(activePoint.health_score).text}
          </span>
        </div>
      )}
    </div>
  );
}

/** Findings-by-severity donut - mirrors the always-visible "what does the
 * current mix look like" summary common to other AppSec dashboards, as a
 * companion to the trend chart (trend shows direction, this shows current
 * composition - neither alone answers both questions). */
function SeverityDonut({ summary }: { summary: AiopsOutput['summary'] }) {
  const segments: { label: string; n: number; cls: string }[] = [
    { label: 'Critical', n: summary.critical, cls: 'crit' },
    { label: 'High', n: summary.high, cls: 'high' },
    { label: 'Medium', n: summary.medium, cls: 'med' },
    { label: 'Low', n: summary.low, cls: 'low' },
  ];
  const total = segments.reduce((sum, s) => sum + s.n, 0);
  const r = 60, c = 2 * Math.PI * r;
  let offset = 0;

  if (total === 0) {
    return <div className="donut-empty">No open findings after deduplication.</div>;
  }

  const severe = summary.critical + summary.high;
  const severePct = Math.round((severe / total) * 100);

  return (
    <div className="donut-card-body">
      <div className="donut-wrap">
        <svg width="150" height="150" viewBox="0 0 150 150">
          <g transform="rotate(-90 75 75)">
            <circle cx="75" cy="75" r={r} className="donut-track" />
            {segments.filter((s) => s.n > 0).map((s) => {
              const len = (s.n / total) * c;
              const dash = `${len} ${c - len}`;
              const el = <circle key={s.label} cx="75" cy="75" r={r} className={`donut-seg donut-${s.cls}`}
                strokeDasharray={dash} strokeDashoffset={-offset} />;
              offset += len;
              return el;
            })}
          </g>
          <text x="75" y="70" textAnchor="middle" className="donut-total">{total}</text>
          <text x="75" y="88" textAnchor="middle" className="donut-total-label">findings</text>
        </svg>
        <ul className="donut-legend">
          {segments.map((s) => (
            <li key={s.label}>
              <span className={`donut-swatch donut-${s.cls}`} />
              <span className="donut-legend-label">{s.label}</span>
              <span className="donut-legend-n">{s.n}</span>
            </li>
          ))}
        </ul>
      </div>
      {severe > 0 && (
        <p className="donut-insight">
          <strong>{severe} of {total} ({severePct}%)</strong> are Critical or High severity — prioritise these first.
        </p>
      )}
    </div>
  );
}
