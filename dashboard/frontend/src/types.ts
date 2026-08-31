export interface Scores {
  P_RF: number;
  S_retrieval: number;
  S_asset: number;
  S_EPSS: number;
}

/** Concrete, per-finding evidence behind each of the four score components -
 * not the formula (that's fixed and the same for every finding), the actual
 * reason *this* finding landed where it did. */
export interface ScoreEvidence {
  p_rf_basis?: 'model' | 'cvss' | 'severity';
  /** Which words in this finding's own title/description drove the trained
   * model's prediction, ranked by contribution - empty when p_rf_basis is
   * not 'model' (nothing was computed, since that path doesn't use the model). */
  p_rf_terms?: { term: string; source: 'description' | 'cwe'; weight: number }[];
  retrieval_basis?: 'corpus' | 'severity';
  /** The known, previously-scored CVEs this finding's text most closely
   * resembles - the actual evidence behind the BM25 similarity number. */
  retrieval_matches?: { id: string; similarity: number }[];
  asset_basis?: 'internet_facing' | 'reachable_via_exposure' | 'no_route';
  epss_available?: boolean;
}

export interface Finding {
  id: string;
  source: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  /** The source tool's own technical description of the actual flaw (e.g.
   * Trivy's real per-CVE text) - distinct from `explanation`, which is
   * ThreatWeave's own deterministic "why this matters / what to do"
   * summary. Both are worth showing: one explains what the vulnerability
   * technically *is*, the other explains why it matters here. */
  description?: string;
  affected_resource: string;
  /** Short, human label for a quick-scan card (e.g. "SQL Injection",
   * "Exposed Secret") - distinct from the full `explanation` sentence. */
  explanation_kind?: string;
  /** The actionable clause on its own, not buried at the end of a paragraph. */
  explanation_fix?: string;
  cve_id: string | null;
  cvss_score: number | null;
  rule_id?: string | null;
  environment: string;
  internet_facing: boolean;
  reported_by: string[];
  related_cves?: string[];
  merged_count?: number;
  fix_version?: string | null;
  risk_score: number;
  scores: Scores;
  score_evidence?: ScoreEvidence;
  confidence: string;
  cluster_id: string | null;
  explanation: string;
  /** When this exact finding (by its stable cross-run identity, not the
   * per-run `id`) was first and most recently detected. first_seen never
   * changes across runs; last_seen advances every run it's still present.
   * Absent on output written before this feature existed. */
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface ClusterExplanation {
  why_it_matters: string;
  what_is_at_risk: string;
  recommended_action: string;
}

export interface Cluster {
  cluster_id: string;
  title: string;
  risk_score: number;
  attack_path: string;
  finding_ids: string[];
  explanation: ClusterExplanation;
}

export interface Summary {
  raw_findings: number;
  after_dedup: number;
  reduction_pct: number;
  clusters: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  suppressed?: number;
}

export interface Suppression {
  id: string;
  reason: string;
  created_by: string;
  created_at: string;
  suppressed_count: number;
}

export interface HistoryPoint {
  run_id: string;
  generated_at: string;
  health_score: number;
}

export interface SourceStatus {
  source: string;
  file: string;
  status: 'ok' | 'missing' | 'error';
  findings: number;
  detail?: string;
}

export interface AiopsOutput {
  run_id: string;
  generated_at: string;
  health_score: number;
  summary: Summary;
  sources?: SourceStatus[];
  clusters: Cluster[];
  findings: Finding[];
  history?: HistoryPoint[];
  suppressions?: Suppression[];
}
