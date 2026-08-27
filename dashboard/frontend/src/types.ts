export interface Scores {
  P_RF: number;
  S_retrieval: number;
  S_asset: number;
  S_EPSS: number;
}

export interface Finding {
  id: string;
  source: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  affected_resource: string;
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
  confidence: string;
  cluster_id: string | null;
  explanation: string;
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
