import type { Finding } from './types';

/** Score values (0-1) shown to 2 decimal places look identical to zero once
 * they drop below 0.01 - and EPSS scores routinely do, since real-world
 * exploitation probability is genuinely tiny for most CVEs (confirmed live:
 * 29 of 33 cached EPSS scores were real, nonzero values like 0.00366, every
 * one of which would have displayed as the exact same "0.00" a true miss
 * shows). Falling back to more decimal places only when needed keeps a
 * normal score ("0.68") uncluttered while making a real-but-small one
 * visibly different from an actual zero. */
export function formatScoreValue(v: number): string {
  if (v === 0) return '0.00';
  if (v < 0.01) return v.toFixed(4);
  return v.toFixed(2);
}

/** Whether a finding's `description` is genuine explanatory prose worth
 * showing as "What this actually is" - Checkov's own `description` field is
 * always a bare URL to Prisma Cloud's policy docs (confirmed live: every
 * single Checkov finding), never real technical detail, so it would be
 * misleading to present it as one. Trivy's is genuine prose. */
export function isRealDescription(description: string | undefined): boolean {
  if (!description) return false;
  return !/^https?:\/\/\S+$/.test(description.trim());
}

/** Which of the three confidence tiers a finding fell into, and why -
 * Confidence is derived entirely from P_RF (the ML probability, already
 * shown in the "Why this score" panel), so this explains that connection
 * rather than leaving "Moderate" or "Needs Analyst Review" as an
 * unexplained label with no visible basis. Thresholds match scorer.py's
 * _confidence() exactly: >=0.85 High, >=0.60 Moderate, else review. */
export function confidenceExplanation(f: Finding): string {
  const p = Math.round(f.scores.P_RF * 100);
  if (f.confidence === 'High Confidence') {
    return `The ML model rated this finding's text ${p}% likely severe (≥85%) - confident enough to trust its judgement without a manual check.`;
  }
  if (f.confidence === 'Moderate') {
    return `The ML model rated this finding's text ${p}% likely severe (60-84%) - reasonably confident, but not high enough to skip a manual look.`;
  }
  return `The ML model rated this finding's text only ${p}% likely severe (below 60%) - too uncertain to trust alone, so an analyst should review it directly.`;
}

/** Concrete, per-finding evidence behind one score component - not the
 * formula (fixed for every finding), the actual reason *this* finding's
 * number is what it is. Every branch is grounded in a real field from
 * score_evidence; nothing here is inferred or guessed on the frontend. */
export function evidenceText(key: string, f: Finding): string | null {
  const ev = f.score_evidence;
  if (!ev) return null;

  if (key === 'P_RF') {
    if (ev.p_rf_basis === 'model') {
      const terms = ev.p_rf_terms ?? [];
      if (!terms.length) return 'The trained model scored this finding\'s text, but no single term stood out as the main driver.';
      return `Driven mostly by: ${terms.map((t) => `"${t.term}"`).join(', ')} in this finding's own ${terms[0].source} - words the model learned are associated with severe findings, present here specifically.`;
    }
    if (ev.p_rf_basis === 'cvss') return 'No trained-model prediction available for this run - using this finding\'s own CVSS score ÷ 10 as a substitute.';
    if (ev.p_rf_basis === 'severity') return `No trained model and no CVSS score for this finding - falling back to a fixed value for its reported "${f.severity}" label.`;
    return null;
  }

  if (key === 'S_retrieval') {
    if (ev.retrieval_basis === 'corpus') {
      const matches = ev.retrieval_matches ?? [];
      if (!matches.length) return 'Compared against the known-CVE corpus, but nothing matched this finding\'s text closely enough to be conclusive.';
      return `This finding's text most closely resembles: ${matches.map((m) => `${m.id} (similarity ${m.similarity.toFixed(1)})`).join(', ')} - real, previously-scored vulnerabilities, not a lookup by name.`;
    }
    if (ev.retrieval_basis === 'severity') return `No comparison corpus available for this run - falling back to a fixed value for its reported "${f.severity}" label.`;
    return null;
  }

  if (key === 'S_asset') {
    if (ev.asset_basis === 'internet_facing') return 'This finding is itself the public exposure - reported as internet-facing by the scanner that found it.';
    if (ev.asset_basis === 'reachable_via_exposure') return 'Not directly internet-facing itself, but running on an asset another finding proved is reachable from the internet (e.g. an open security group) - inherited exposure, weaker evidence than a direct report.';
    if (ev.asset_basis === 'no_route') return 'No finding in this run established a route from the internet to this resource.';
    return null;
  }

  if (key === 'S_EPSS') {
    if (ev.epss_available) return `Live exploitation-probability data from FIRST.org's EPSS dataset for ${f.cve_id}.`;
    if (f.cve_id) return `${f.cve_id} has no published EPSS score yet - defaults to 0 rather than guessing.`;
    return 'No CVE attached to this finding, so no EPSS lookup applies - defaults to 0.';
  }

  return null;
}

/** Health-score band shown on the ring gauge and its colour class. */
export function healthLabel(score: number): { text: string; cls: string } {
  if (score >= 80) return { text: 'Healthy', cls: 'good' };
  if (score >= 50) return { text: 'At Risk', cls: 'warn' };
  return { text: 'Critical', cls: 'bad' };
}

/** Milliseconds since a scan started -> "3m 42s" / "8s", for the live elapsed
 * timer next to "Run scan". Negative/invalid input (clock skew, not started
 * yet) clamps to 0s rather than showing something nonsensical like "-4s". */
/** The AWS monitor runs inside the pipeline's final "AIOps engine &
 * dashboard update" stage but takes only seconds of it - the engine takes
 * the rest. Only the monitor's own console output means it is actually
 * running, so the AWS chip is not shown as "scanning" for the whole stage. */
export function isAwsMonitorRunning(activeStages: string[] | undefined, currentActivity: string | undefined): boolean {
  if (!(activeStages ?? []).includes('AIOps engine & dashboard update')) return false;
  return /aws_monitor|monitor\.py|Connected to AWS|^Identity:|checking (EC2|Security groups|S3|IAM)/i.test(currentActivity ?? '');
}

/** Settings label for where a pipeline target's value came from; null when
 * there is nothing worth saying (an empty field already shows "skipped"). */
export function originLabel(origin: string | undefined): { text: string; title: string } | null {
  switch (origin) {
    case 'detected': return { text: 'Detected', title: 'Found automatically in the mounted project' };
    case 'saved': return { text: 'Set by you', title: 'Saved in Settings - detection never overwrites it' };
    case 'install': return { text: 'From install', title: 'Given with -e SCAN_... when ThreatWeave was started' };
    default: return null;
  }
}

/** Short label for a detected IaC folder, e.g. "3 CDK templates". */
export function iacKindLabel(kind: string, files: number): string {
  const name = kind === 'cdk' ? 'CDK template' : kind === 'cloudformation' ? 'CloudFormation template' : 'Terraform file';
  return `${files} ${name}${files === 1 ? '' : 's'}`;
}

export function formatElapsed(ms: number): string {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

/** How the AWS connection shown in Settings is actually authenticated -
 * Boto3's identity ARN encodes this, but only to someone who already knows
 * the shape (`assumed-role/` vs `user/`). A laptop and an EC2 deployment use
 * the exact same code path and the exact same "Connected" pill; without
 * this, there is no way for a reader of the dashboard to tell "this is
 * using a static access key" from "this is using an EC2 instance role"
 * short of reading the raw ARN themselves. */
export function describeAwsAuthMethod(arn: string | undefined): string | null {
  if (!arn) return null;
  if (arn.includes(':assumed-role/')) return 'IAM role (e.g. an EC2 instance role) - temporary, auto-rotated credentials';
  if (arn.includes(':user/')) return 'IAM user - a static access key from ~/.aws/credentials or environment variables';
  if (arn.includes(':root')) return 'AWS account root user - not recommended, prefer an IAM user or role';
  return null;
}

/** The smallest IAM policy the AWS monitor can run under: exactly the
 * read-only calls aws_monitor/monitor.py makes (EC2 instances and security
 * groups, S3 public access block and encryption, IAM roles/users/keys).
 * sts:GetCallerIdentity needs no permission, so it is not listed. The AWS
 * managed SecurityAudit policy is a broader read-only alternative. */
export const READONLY_POLICY = {
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'ThreatWeaveReadOnly',
      Effect: 'Allow',
      Action: [
        'ec2:DescribeInstances',
        'ec2:DescribeSecurityGroups',
        's3:ListAllMyBuckets',
        's3:GetBucketPublicAccessBlock',
        's3:GetEncryptionConfiguration',
        'iam:ListRoles',
        'iam:ListAttachedRolePolicies',
        'iam:ListUsers',
        'iam:ListAttachedUserPolicies',
        'iam:ListAccessKeys',
      ],
      Resource: '*',
    },
  ],
};

export const READONLY_POLICY_JSON = JSON.stringify(READONLY_POLICY, null, 2);

/** How long a finding has been open, from its stable first_seen date (not
 * its per-run `id`, which is a fresh UUID every scan and can't answer this).
 * "New" on the very run it was first detected (first_seen === last_seen),
 * since "open for 0 days" reads as a bug rather than as brand-new. Absent
 * first_seen (older output written before this feature existed) returns
 * null so the caller can omit the age display entirely rather than showing
 * a wrong or confusing value. */
export function describeFindingAge(first_seen: string | null | undefined, now = new Date()): string | null {
  if (!first_seen) return null;
  const first = new Date(first_seen);
  if (Number.isNaN(first.getTime())) return null;
  const days = Math.floor((now.getTime() - first.getTime()) / (1000 * 60 * 60 * 24));
  if (days <= 0) return 'New';
  if (days === 1) return 'Open 1 day';
  return `Open ${days} days`;
}

/** "test/foo/bar.js:12" -> "test/foo/*" so a suppression rule covers the directory. */
export function dirGlob(resource: string): string {
  const noLine = resource.replace(/:\d+$/, '');
  const idx = noLine.lastIndexOf('/');
  return idx > 0 ? `${noLine.slice(0, idx)}/*` : `${noLine}*`;
}

export interface FindingFilters {
  severity?: string | null;
  source?: string | null;
  query?: string;
}

/**
 * The Findings page's client-side filter chain: severity chip, source chip,
 * and free-text search over title/resource/CVE. Extracted from App.tsx so it
 * is testable without rendering the component tree; behaviour is unchanged.
 */
export function filterFindings(findings: Finding[], { severity, source, query }: FindingFilters): Finding[] {
  return findings
    .filter((f) => (severity ? f.severity === severity : true))
    .filter((f) => (source ? f.reported_by.includes(source) : true))
    .filter((f) => {
      if (!query?.trim()) return true;
      const q = query.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        f.affected_resource.toLowerCase().includes(q) ||
        (f.cve_id?.toLowerCase().includes(q) ?? false)
      );
    });
}
