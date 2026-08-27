import { useCallback, useEffect, useState, type ReactNode } from 'react';
import type { AiopsOutput, Finding, Cluster, HistoryPoint, Suppression, SourceStatus } from './types';
import { api, type PipelineStatus, type NewSuppression, type AwsStatus, type AppSettings } from './api';
import { healthLabel, dirGlob, filterFindings } from './lib';
import './App.css';

type View = 'overview' | 'findings' | 'clusters' | 'history' | 'settings';

const NAV: { id: View; label: string; icon: string }[] = [
  { id: 'overview', label: 'Overview', icon: 'M3 12l9-9 9 9M5 10v10h5v-6h4v6h5V10' },
  { id: 'findings', label: 'Findings', icon: 'M4 6h16M4 12h16M4 18h10' },
  { id: 'clusters', label: 'Attack Paths', icon: 'M5 5a2 2 0 110 4 2 2 0 010-4zm14 10a2 2 0 110 4 2 2 0 010-4zM7 7l10 10' },
  { id: 'history', label: 'History', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
  { id: 'settings', label: 'Settings', icon: 'M12 15a3 3 0 100-6 3 3 0 000 6zM19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09A1.65 1.65 0 008 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06A1.65 1.65 0 004.6 15a1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06A1.65 1.65 0 009 4.6a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06A1.65 1.65 0 0019.4 9c.14.63.68 1.1 1.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z' },
];

export default function App() {
  const [data, setData] = useState<AiopsOutput | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<View>('overview');
  const [scan, setScan] = useState<PipelineStatus | null>(null);

  const load = useCallback(() => {
    api.getFindings()
      .then((d) => { setData(d); setError(null); })
      .catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => { load(); }, [load]);

  // "Run scan" triggers the real Jenkins pipeline (scanners -> engine), not
  // just a re-score of old data - queued and running both need polling,
  // since a build can sit queued for a moment before an executor picks it up.
  const scanInFlight = scan?.state === 'queued' || scan?.state === 'running';
  useEffect(() => {
    if (!scanInFlight) return;
    const timer = setInterval(async () => {
      try {
        const status = await api.getPipelineStatus();
        setScan(status);
        if (status.state === 'success' || status.state === 'failed') load();
      } catch {
        clearInterval(timer);
      }
    }, 2000);
    return () => clearInterval(timer);
  }, [scanInFlight, load]);

  const runScan = async () => {
    try {
      setScan(await api.runPipeline());
    } catch (e) {
      setError((e as Error).message);
    }
  };

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
              <><span className="spinner" /> {scan?.state === 'queued' ? 'Queued…' : 'Scanning…'}</>
            ) : (
              <>
                <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 12a9 9 0 11-3-6.7M21 3v6h-6" />
                </svg>
                Run scan
              </>
            )}
          </button>
          {scan?.state === 'failed' && <span className="scan-err">Scan failed</span>}
          {scan?.buildNumber && <span className="run-chip">Build #{scan.buildNumber}</span>}
          {data && <span className="run-chip">Run {data.run_id}</span>}
        </div>
      </aside>

      <main className="main">
        {error && (
          <div className="state">
            <p>Could not reach the API: {error}</p>
            <span className="empty-sub">Is the NestJS backend running on port 4000?</span>
          </div>
        )}
        {!error && !data && <div className="state">Loading findings…</div>}
        {!error && data && scan?.state === 'failed' && (
          <ScanFailureBanner scan={scan} onDismiss={() => setScan(null)} />
        )}
        {data && <Content view={view} data={data} onGoto={setView} onReload={load} />}
      </main>
    </div>
  );
}

/* ---------- Scan failure: the real reason, not just "Scan failed" ---------- */
function ScanFailureBanner({ scan, onDismiss }: { scan: PipelineStatus; onDismiss: () => void }) {
  // A stall timeout is a distinct case worth explaining differently: the
  // dashboard lost track of the build, but Jenkins itself may still be
  // working - that is not the same as the pipeline having actually failed.
  const stalled = scan.error?.startsWith('Lost contact with Jenkins');
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

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

function Content({ view, data, onGoto, onReload }: {
  view: View; data: AiopsOutput; onGoto: (v: View) => void; onReload: () => void;
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
        {data.sources && <DataSources sources={data.sources} />}
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

        {data.history && data.history.length > 1 && (
          <section className="block">
            <div className="block-head"><h2>Health Trend</h2><button className="link-btn" onClick={() => onGoto('history')}>Details →</button></div>
            <div className="card chart-card"><TrendChart points={data.history} /></div>
          </section>
        )}

        <section className="block">
          <div className="block-head"><h2>Top Attack Path</h2><button className="link-btn" onClick={() => onGoto('clusters')}>View all →</button></div>
          {data.clusters.slice(0, 1).map((c) => <ClusterCard key={c.cluster_id} c={c} findingById={findingById} />)}
        </section>
      </>
    );
  }

  if (view === 'clusters') {
    return (
      <>
        {header('Attack Paths', 'Findings correlated across code, container and cloud')}
        {data.clusters.map((c) => <ClusterCard key={c.cluster_id} c={c} findingById={findingById} defaultOpen />)}
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
              <col style={{ width: 84 }} />
              <col style={{ width: '30%' }} />
              <col style={{ width: 90 }} />
              <col style={{ width: '24%' }} />
              <col style={{ width: 96 }} />
            </colgroup>
            <thead>
              <tr><th></th><th>Risk</th><th>Severity</th><th>Title</th><th>Source</th><th>Resource</th><th>Confidence</th></tr>
            </thead>
            <tbody>
              {sortedFindings.length === 0 && (
                <tr><td colSpan={7} className="no-results">No findings match your filters.</td></tr>
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

function SettingsPanel({ data, onReload }: { data: AiopsOutput; onReload: () => void }) {
  const [aws, setAws] = useState<AwsStatus | null>(null);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [sups, setSups] = useState<Suppression[]>([]);

  const refresh = useCallback(() => {
    api.getAwsStatus().then(setAws).catch(() => setAws({ connected: false, message: 'API unreachable' }));
    api.getSettings().then(setSettings).catch(() => {});
    api.getSuppressions().then(setSups).catch(() => {});
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

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

  const revoke = async (id: string) => {
    await api.revokeSuppression(id);
    refresh();
    onReload();
  };

  return (
    <div className="settings">
      {/* AWS connection */}
      <div className="card set-card">
        <div className="set-head">
          <h3>AWS connection</h3>
          {aws && (
            <span className={`conn-pill ${aws.connected ? 'ok' : 'off'}`}>
              {aws.connected ? 'Connected' : 'Not connected'}
            </span>
          )}
        </div>

        {aws?.connected ? (
          <div className="d-grid">
            <div className="d-item"><span className="d-label">Account</span><span className="d-value mono">{aws.account}</span></div>
            <div className="d-item"><span className="d-label">Identity</span><span className="d-value mono">{aws.arn}</span></div>
            <div className="d-item"><span className="d-label">Profile region</span><span className="d-value mono">{aws.region ?? '—'}</span></div>
          </div>
        ) : (
          <div className="conn-help">
            <p>{aws?.message ?? 'Checking…'}</p>
            <p className="empty-sub">
              Credentials are resolved by Boto3: an IAM role when running on EC2, then environment
              variables, then <code>~/.aws/credentials</code>. Run <code>aws configure</code> once
              and reload — nothing needs to be entered here.
            </p>
          </div>
        )}

        <p className="set-note">
          Only read-only permissions are needed. Attach the AWS managed <code>SecurityAudit</code> policy —
          the monitor issues describe/list/get calls only and cannot modify infrastructure.
        </p>
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

  const saveField = (key: keyof typeof p, value: string | boolean) =>
    save({ pipeline: { ...p, [key]: value } as never });

  return (
    <div className="card set-card">
      <div className="set-head">
        <h3>Pipeline target</h3>
        <span className="stat-sub">what "Run scan" actually scans</span>
      </div>
      <p className="set-note" style={{ marginTop: 0, marginBottom: 16 }}>
        These map directly to the Jenkins job's own parameters — editing them
        here changes what the next "Run scan" click passes in, nothing more.
        Container-internal paths only work if the target is mounted at that
        path when the container starts (see the README's "Scanning your own
        project" section).
      </p>

      <label className="set-row">
        <span className="set-label">Source directory</span>
        <input
          className="set-input"
          value={draft.sourceDir}
          onChange={(e) => setDraft({ ...draft, sourceDir: e.target.value })}
          onBlur={() => draft.sourceDir !== p.sourceDir && saveField('sourceDir', draft.sourceDir)}
          placeholder="/target"
        />
      </label>

      <label className="set-row">
        <span className="set-label">IaC directory</span>
        <input
          className="set-input"
          value={draft.iacDir}
          onChange={(e) => setDraft({ ...draft, iacDir: e.target.value })}
          onBlur={() => draft.iacDir !== p.iacDir && saveField('iacDir', draft.iacDir)}
          placeholder="/target/infra"
        />
      </label>

      <label className="set-row">
        <span className="set-label">Container image</span>
        <input
          className="set-input"
          value={draft.targetImage}
          onChange={(e) => setDraft({ ...draft, targetImage: e.target.value })}
          onBlur={() => draft.targetImage !== p.targetImage && saveField('targetImage', draft.targetImage)}
          placeholder="scratch"
        />
      </label>

      <label className="set-row">
        <span className="set-label">SonarQube project key</span>
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

function DataSources({ sources }: { sources: SourceStatus[] }) {
  const missingOrError = sources.filter((s) => s.status !== 'ok');
  return (
    <section className="block sources-block">
      <div className="sources-row">
        {sources.map((s) => (
          <span
            key={s.source}
            className={`source-chip source-${s.status}`}
            title={
              s.status === 'ok' ? `${s.findings} findings`
                : s.status === 'error' ? `Report was present but could not be read: ${s.detail ?? 'unknown error'}`
                  : 'No report was produced for this run - the scanner may be disabled, not configured, or its stage failed'
            }
          >
            <span className="source-dot" />
            {SOURCE_LABELS[s.source] ?? s.source}
            {s.status === 'ok' && <span className="source-count">{s.findings}</span>}
            {s.status === 'missing' && <span className="source-reason">no report</span>}
            {s.status === 'error' && <span className="source-reason">unreadable</span>}
          </span>
        ))}
      </div>
      {missingOrError.length > 0 && (
        <p className="sources-note">
          This run's numbers only reflect the sources marked above as having
          findings - {missingOrError.map((s) => SOURCE_LABELS[s.source] ?? s.source).join(', ')} did
          not contribute data to it. That is not necessarily a problem (SAST
          is off unless <code>SONAR_HOST_URL</code> is set, for instance) but
          it does mean the health score and finding counts below are based on
          fewer than five sources this time.
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

  const rows = [
    { label: 'Raw findings from all tools', n: raw, cls: 'raw' },
    { label: 'Merged duplicates & grouped by remediation', n: merged, cls: 'merged', delta: true },
    { label: 'Suppressed by analyst rules', n: suppressed, cls: 'suppressed', delta: true },
    { label: 'Actionable findings', n: final, cls: 'final' },
  ].filter((r) => r.n > 0 || r.cls === 'final');

  return (
    <div className="funnel">
      {rows.map((r) => (
        <div className="funnel-row" key={r.label}>
          <span className="funnel-label">{r.label}</span>
          <span className="funnel-bar-wrap">
            <span className={`funnel-bar ${r.cls}`} style={{ width: `${(r.n / raw) * 100}%` }} />
          </span>
          <span className={`funnel-n ${r.cls}`}>{r.delta ? `−${r.n}` : r.n}</span>
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

/* ---------- Risk score with breakdown tooltip ---------- */
function ScoreCell({ f }: { f: Finding }) {
  const cls = f.risk_score >= 80 ? 'bad' : f.risk_score >= 50 ? 'warn' : 'good';
  const parts = scoreParts(f);
  return (
    <span className="score-cell">
      <span className={`risk-pill ${cls}`}>{f.risk_score}</span>
      <div className="score-pop">
        <div className="pop-head">Risk breakdown <span className="pop-formula">0.45·P<sub>RF</sub> + 0.25·S<sub>ret</sub> + 0.20·S<sub>asset</sub> + 0.10·S<sub>EPSS</sub></span></div>
        {parts.map((p) => (
          <div className="pop-row" key={p.key}>
            <span className="pop-label">{p.label}<span className="pop-w">×{p.w}</span></span>
            <span className="pop-bar"><span className="pop-fill" style={{ width: `${p.v * 100}%` }} /></span>
            <span className="pop-val">{p.v.toFixed(2)}</span>
          </div>
        ))}
        <div className="pop-foot">Confidence: <strong>{f.confidence}</strong></div>
      </div>
    </span>
  );
}

/* ---------- Always-visible "why this score" panel in the expanded row ---------- */
function RiskReasoning({ f }: { f: Finding }) {
  const parts = scoreParts(f);
  const note = reasoningNote(f);
  const cls = f.risk_score >= 80 ? 'bad' : f.risk_score >= 50 ? 'warn' : 'good';
  return (
    <div className="reasoning">
      <div className="reasoning-head">
        <span>Why this score</span>
        <span className="reasoning-compare">
          {f.reported_by.join('/')} reported <span className={`sev sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
          <span className="reasoning-vs">→</span>
          ThreatWeave computed <span className={`risk-pill ${cls}`}>{f.risk_score}</span>
        </span>
      </div>

      <p className={`reasoning-note ${note.mismatch ? '' : 'reasoning-note-plain'}`}>{note.text}</p>

      <div className="reasoning-bars">
        {parts.map((p) => (
          <div className="reasoning-row" key={p.key}>
            <span className="reasoning-label">{p.label}<span className="pop-w">×{p.w}</span></span>
            <span className="reasoning-bar"><span className="reasoning-fill" style={{ width: `${p.v * 100}%` }} /></span>
            <span className="reasoning-val">{p.v.toFixed(2)}</span>
          </div>
        ))}
      </div>
      <p className="reasoning-formula">0.45·P<sub>RF</sub> + 0.25·S<sub>ret</sub> + 0.20·S<sub>asset</sub> + 0.10·S<sub>EPSS</sub> — the severity badge is the source tool's own label and is never overwritten; the score is ThreatWeave's independent estimate.</p>
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
        </td>
        <td>{f.reported_by.join(', ')}</td>
        <td className="mono">{f.affected_resource}</td>
        <td>{f.confidence}</td>
      </tr>
      {isOpen && (
        <tr className="detail-row">
          <td colSpan={7}>
            <div className="detail">
              <p className="d-expl">{f.explanation}</p>
              <RiskReasoning f={f} />
              <div className="d-grid">
                {detail('Location / Resource', <span className="mono">{f.affected_resource}</span>)}
                {detail('Reported by', f.reported_by.join(', '))}
                {detail('Type', f.type)}
                {detail('Environment', f.environment)}
                {detail('Internet facing', f.internet_facing ? 'Yes — publicly reachable' : 'No — internal only')}
                {f.cve_id && detail('CVE', <a className="cve-link" href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noreferrer">{f.cve_id} ↗</a>)}
                {f.cvss_score != null && detail('CVSS base score', f.cvss_score.toFixed(1))}
                {detail('Confidence', f.confidence)}
              </div>
              {(f.related_cves?.length ?? 0) > 1 && (
                <div className="d-cves">
                  <span className="d-label">All {f.related_cves!.length} CVEs cleared by this one upgrade</span>
                  <div className="cve-chips">
                    {f.related_cves!.map((c) => (
                      c.startsWith('CVE-')
                        ? <a key={c} className="cve-chip" href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer">{c}</a>
                        : <span key={c} className="cve-chip">{c}</span>
                    ))}
                  </div>
                </div>
              )}
              {cluster && (
                <div className="d-cluster">
                  <span className="d-cluster-tag">Part of attack path</span>
                  <span className="d-cluster-title">{cluster.title}</span>
                  <span className="risk-pill bad">{cluster.risk_score}</span>
                </div>
              )}

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
        else { body.source = f.source; body.resource_pattern = f.affected_resource; }
      } else if (scope === 'rule') {
        body.source = f.source;
        body.rule_id = f.rule_id!;
      } else {
        body.source = f.source;
        body.resource_pattern = dirGlob(f.affected_resource);
      }
      await api.createSuppression(body);
      setOpen(false); setReason('');
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

/* ---------- Health trend line chart (pure SVG) ---------- */
function TrendChart({ points }: { points: HistoryPoint[] }) {
  const W = 640, H = 180, pad = 28;
  const xs = points.map((_, i) => pad + (i * (W - 2 * pad)) / (points.length - 1));
  const ys = points.map((p) => H - pad - (p.health_score / 100) * (H - 2 * pad));
  const line = xs.map((x, i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${ys[i].toFixed(1)}`).join(' ');
  const area = `${line} L${xs[xs.length - 1].toFixed(1)},${H - pad} L${xs[0].toFixed(1)},${H - pad} Z`;
  return (
    <svg className="trend" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet">
      {[0, 25, 50, 75, 100].map((g) => {
        const y = H - pad - (g / 100) * (H - 2 * pad);
        return (<g key={g}><line x1={pad} y1={y} x2={W - pad} y2={y} className="grid-line" /><text x={4} y={y + 3} className="grid-text">{g}</text></g>);
      })}
      <path d={area} className="trend-area" />
      <path d={line} className="trend-line" />
      {points.map((p, i) => (
        <g key={p.run_id}>
          <circle cx={xs[i]} cy={ys[i]} r={4} className={`trend-dot ${healthLabel(p.health_score).cls}`} />
          <title>{`${p.run_id}: ${p.health_score}`}</title>
        </g>
      ))}
    </svg>
  );
}
