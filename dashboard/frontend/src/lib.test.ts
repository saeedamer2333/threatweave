import { describe, it, expect } from 'vitest';
import { isAwsMonitorRunning, healthLabel, dirGlob, filterFindings, formatElapsed, describeAwsAuthMethod, evidenceText, formatScoreValue, confidenceExplanation, isRealDescription, describeFindingAge, READONLY_POLICY, READONLY_POLICY_JSON } from './lib';
import type { Finding } from './types';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'f-1', source: 'trivy', type: 'VULNERABILITY', severity: 'HIGH',
    title: 'title', affected_resource: 'resource', cve_id: null, cvss_score: null,
    environment: 'production', internet_facing: false, reported_by: ['trivy'],
    risk_score: 50, scores: { P_RF: 0, S_retrieval: 0, S_asset: 0, S_EPSS: 0 },
    confidence: 'Moderate', cluster_id: null, explanation: '',
    ...overrides,
  };
}

describe('healthLabel', () => {
  it('labels 80 and above as Healthy', () => {
    expect(healthLabel(80)).toEqual({ text: 'Healthy', cls: 'good' });
    expect(healthLabel(100)).toEqual({ text: 'Healthy', cls: 'good' });
  });

  it('labels 50-79 as At Risk', () => {
    expect(healthLabel(50)).toEqual({ text: 'At Risk', cls: 'warn' });
    expect(healthLabel(79)).toEqual({ text: 'At Risk', cls: 'warn' });
  });

  it('labels below 50 as Critical', () => {
    expect(healthLabel(49)).toEqual({ text: 'Critical', cls: 'bad' });
    expect(healthLabel(0)).toEqual({ text: 'Critical', cls: 'bad' });
  });

  it('matches the real build-306 score (13) as Critical', () => {
    // Regression anchor: this is the exact score cited throughout the FYP
    // document's Chapter 4 screenshots and captions.
    expect(healthLabel(13).text).toBe('Critical');
  });
});

describe('dirGlob', () => {
  it('turns a file:line resource into a directory glob', () => {
    expect(dirGlob('test/fixtures/creds.json:12')).toBe('test/fixtures/*');
  });

  it('strips the line number when present', () => {
    expect(dirGlob('src/config.ts:42')).toBe('src/*');
  });

  it('handles a resource with no line number', () => {
    expect(dirGlob('src/config.ts')).toBe('src/*');
  });

  it('handles a resource with no directory separator', () => {
    expect(dirGlob('README.md')).toBe('README.md*');
  });
});

describe('formatElapsed', () => {
  it('shows seconds only under a minute', () => {
    expect(formatElapsed(8_000)).toBe('8s');
    expect(formatElapsed(59_000)).toBe('59s');
  });

  it('shows minutes and seconds once past a minute', () => {
    expect(formatElapsed(60_000)).toBe('1m 0s');
    expect(formatElapsed(222_000)).toBe('3m 42s');
  });

  it('clamps negative/invalid elapsed time to 0s rather than showing something nonsensical', () => {
    expect(formatElapsed(-500)).toBe('0s');
  });
});

describe('filterFindings', () => {
  const findings = [
    finding({ id: 'f-1', severity: 'CRITICAL', source: 'trivy', reported_by: ['trivy'], title: 'lodash prototype pollution', cve_id: 'CVE-2019-10744' }),
    finding({ id: 'f-2', severity: 'HIGH', source: 'sonarqube', reported_by: ['sonarqube'], title: 'SQL injection risk', cve_id: null }),
    finding({ id: 'f-3', severity: 'MEDIUM', source: 'checkov', reported_by: ['checkov'], title: 'missing encryption', affected_resource: 'aws_s3_bucket.logs' }),
  ];

  it('returns everything when no filters are set', () => {
    expect(filterFindings(findings, {})).toHaveLength(3);
  });

  it('filters by severity', () => {
    const result = filterFindings(findings, { severity: 'HIGH' });
    expect(result.map((f) => f.id)).toEqual(['f-2']);
  });

  it('filters by source, matching against reported_by not source alone', () => {
    const merged = finding({ id: 'f-4', severity: 'LOW', reported_by: ['trivy', 'sonarqube'] });
    const result = filterFindings([...findings, merged], { source: 'sonarqube' });
    expect(result.map((f) => f.id)).toEqual(['f-2', 'f-4']);
  });

  it('searches title case-insensitively', () => {
    const result = filterFindings(findings, { query: 'SQL' });
    expect(result.map((f) => f.id)).toEqual(['f-2']);
  });

  it('searches CVE id', () => {
    const result = filterFindings(findings, { query: 'cve-2019-10744' });
    expect(result.map((f) => f.id)).toEqual(['f-1']);
  });

  it('searches affected_resource', () => {
    const result = filterFindings(findings, { query: 's3_bucket' });
    expect(result.map((f) => f.id)).toEqual(['f-3']);
  });

  it('does not throw when a finding has a null cve_id and the query does not match it', () => {
    const result = filterFindings(findings, { query: 'nonexistent-term' });
    expect(result).toHaveLength(0);
  });

  it('combines severity, source and query filters together', () => {
    const result = filterFindings(findings, { severity: 'CRITICAL', source: 'trivy', query: 'lodash' });
    expect(result.map((f) => f.id)).toEqual(['f-1']);
  });

  it('treats a blank query as no filter', () => {
    expect(filterFindings(findings, { query: '   ' })).toHaveLength(3);
  });
});

describe('READONLY_POLICY', () => {
  const actions = READONLY_POLICY.Statement[0].Action;

  it('grants exactly the read calls aws_monitor/monitor.py makes', () => {
    expect([...actions].sort()).toEqual([
      'ec2:DescribeInstances', 'ec2:DescribeSecurityGroups',
      'iam:ListAccessKeys', 'iam:ListAttachedRolePolicies', 'iam:ListAttachedUserPolicies', 'iam:ListRoles', 'iam:ListUsers',
      's3:GetBucketPublicAccessBlock', 's3:GetEncryptionConfiguration', 's3:ListAllMyBuckets',
    ]);
  });

  it('never grants a write action', () => {
    expect(actions.every((a) => /:(Describe|List|Get)/.test(a))).toBe(true);
  });

  it('is valid JSON when copied', () => {
    expect(JSON.parse(READONLY_POLICY_JSON)).toEqual(READONLY_POLICY);
  });
});

describe('describeAwsAuthMethod', () => {
  it('labels an assumed-role ARN as an IAM role', () => {
    const result = describeAwsAuthMethod('arn:aws:sts::194722404383:assumed-role/threatweave-ec2-role/i-0abc123');
    expect(result).toContain('IAM role');
  });

  it('labels a user ARN as a static access key', () => {
    const result = describeAwsAuthMethod('arn:aws:iam::194722404383:user/Cli-Access');
    expect(result).toContain('static access key');
  });

  it('flags the root user distinctly, as not recommended', () => {
    const result = describeAwsAuthMethod('arn:aws:iam::194722404383:root');
    expect(result).toContain('root');
    expect(result).toContain('not recommended');
  });

  it('returns null for an unrecognised ARN shape rather than guessing', () => {
    expect(describeAwsAuthMethod('arn:aws:iam::194722404383:federated-user/someone')).toBeNull();
  });

  it('returns null when there is no ARN yet', () => {
    expect(describeAwsAuthMethod(undefined)).toBeNull();
  });
});

describe('describeFindingAge', () => {
  const now = new Date('2026-08-10T00:00:00Z');

  it('shows "New" when first detected in the run being viewed', () => {
    expect(describeFindingAge('2026-08-10T00:00:00Z', now)).toBe('New');
  });

  it('singularises exactly one day open', () => {
    expect(describeFindingAge('2026-08-09T00:00:00Z', now)).toBe('Open 1 day');
  });

  it('pluralises several days open', () => {
    expect(describeFindingAge('2026-08-01T00:00:00Z', now)).toBe('Open 9 days');
  });

  it('returns null when first_seen is absent, rather than a wrong value', () => {
    expect(describeFindingAge(null, now)).toBeNull();
    expect(describeFindingAge(undefined, now)).toBeNull();
  });

  it('returns null for an unparseable date', () => {
    expect(describeFindingAge('not-a-date', now)).toBeNull();
  });
});

describe('formatScoreValue', () => {
  // Regression: confirmed live against real cached EPSS data - 29 of 33
  // real, nonzero scores (e.g. 0.00366) were displaying as the exact same
  // "0.00" a genuine miss shows, making real data visually indistinguishable
  // from no data at all.
  it('shows a genuine zero as 0.00', () => {
    expect(formatScoreValue(0)).toBe('0.00');
  });

  it('shows a small but real nonzero value with more precision, not as 0.00', () => {
    expect(formatScoreValue(0.00366)).toBe('0.0037');
    expect(formatScoreValue(0.00366)).not.toBe('0.00');
  });

  it('shows a normal-sized value to 2 decimal places as before', () => {
    expect(formatScoreValue(0.68)).toBe('0.68');
  });

  it('treats exactly 0.01 as a normal-sized value, not a small one', () => {
    expect(formatScoreValue(0.01)).toBe('0.01');
  });
});

describe('isRealDescription', () => {
  // Regression: confirmed live - every single Checkov finding's own
  // `description` field is a bare URL to Prisma Cloud's policy docs, never
  // real prose. Showing it as "What this actually is" was misleading.
  it('rejects a bare URL, matching what Checkov always provides', () => {
    expect(isRealDescription('https://docs.prismacloud.io/en/enterprise-edition/policy-reference/x')).toBe(false);
  });

  it('accepts genuine prose, matching what Trivy provides', () => {
    expect(isRealDescription('A flaw was found in glibc. The strfmon function is vulnerable to a buffer overflow.')).toBe(true);
  });

  it('rejects undefined and empty string', () => {
    expect(isRealDescription(undefined)).toBe(false);
    expect(isRealDescription('')).toBe(false);
  });

  it('accepts text that happens to contain a URL as part of a real sentence', () => {
    expect(isRealDescription('See https://example.com for more detail on this specific flaw.')).toBe(true);
  });
});

describe('confidenceExplanation', () => {
  it('explains High Confidence in terms of the actual P_RF percentage', () => {
    const f = finding({ confidence: 'High Confidence', scores: { P_RF: 0.9, S_retrieval: 0, S_asset: 0, S_EPSS: 0 } });
    const result = confidenceExplanation(f);
    expect(result).toContain('90%');
    expect(result).toContain('≥85%');
  });

  it('explains Moderate in terms of the actual P_RF percentage', () => {
    const f = finding({ confidence: 'Moderate', scores: { P_RF: 0.68, S_retrieval: 0, S_asset: 0, S_EPSS: 0 } });
    const result = confidenceExplanation(f);
    expect(result).toContain('68%');
    expect(result).toContain('60-84%');
  });

  it('explains Needs Analyst Review in terms of the actual P_RF percentage', () => {
    const f = finding({ confidence: 'Needs Analyst Review', scores: { P_RF: 0.3, S_retrieval: 0, S_asset: 0, S_EPSS: 0 } });
    const result = confidenceExplanation(f);
    expect(result).toContain('30%');
    expect(result).toContain('below 60%');
  });
});

describe('evidenceText', () => {
  it('returns null when a finding has no score_evidence at all', () => {
    expect(evidenceText('P_RF', finding())).toBeNull();
  });

  it('names the specific terms that drove a model-based P_RF prediction', () => {
    const f = finding({ score_evidence: {
      p_rf_basis: 'model',
      p_rf_terms: [{ term: 'sql injection', source: 'description', weight: 0.12 }],
    } });
    const result = evidenceText('P_RF', f);
    expect(result).toContain('sql injection');
  });

  it('explains the CVSS fallback distinctly from the model path', () => {
    const f = finding({ score_evidence: { p_rf_basis: 'cvss' } });
    expect(evidenceText('P_RF', f)).toContain('CVSS');
  });

  it('explains the severity fallback and names the actual reported severity', () => {
    const f = finding({ severity: 'CRITICAL', score_evidence: { p_rf_basis: 'severity' } });
    expect(evidenceText('P_RF', f)).toContain('CRITICAL');
  });

  it('lists the specific nearest-known-CVE matches for a corpus-based retrieval score', () => {
    const f = finding({ score_evidence: {
      retrieval_basis: 'corpus',
      retrieval_matches: [{ id: 'CVE-2021-44228', similarity: 8.4 }],
    } });
    expect(evidenceText('S_retrieval', f)).toContain('CVE-2021-44228');
  });

  it('distinguishes direct internet-facing exposure from inherited exposure', () => {
    const direct = finding({ score_evidence: { asset_basis: 'internet_facing' } });
    const inherited = finding({ score_evidence: { asset_basis: 'reachable_via_exposure' } });
    expect(evidenceText('S_asset', direct)).toContain('itself the public exposure');
    expect(evidenceText('S_asset', inherited)).toContain('inherited exposure');
  });

  it('names the actual CVE when EPSS data was found', () => {
    const f = finding({ cve_id: 'CVE-2021-44228', score_evidence: { epss_available: true } });
    expect(evidenceText('S_EPSS', f)).toContain('CVE-2021-44228');
  });

  it('distinguishes "no EPSS data for this CVE" from "no CVE at all"', () => {
    const withCve = finding({ cve_id: 'CVE-2021-44228', score_evidence: { epss_available: false } });
    const withoutCve = finding({ cve_id: null, score_evidence: { epss_available: false } });
    expect(evidenceText('S_EPSS', withCve)).toContain('CVE-2021-44228');
    expect(evidenceText('S_EPSS', withoutCve)).toContain('No CVE attached');
  });

  it('returns null for an unrecognised score key rather than guessing', () => {
    const f = finding({ score_evidence: { p_rf_basis: 'model' } });
    expect(evidenceText('not_a_real_key', f)).toBeNull();
  });
});

describe('isAwsMonitorRunning', () => {
  const stage = ['AIOps engine & dashboard update'];

  it('is running while the monitor itself is printing', () => {
    expect(isAwsMonitorRunning(stage, '+ python3 /workspace/aws_monitor/monitor.py --output x')).toBe(true);
    expect(isAwsMonitorRunning(stage, 'checking S3 buckets ... 1 finding(s)')).toBe(true);
    expect(isAwsMonitorRunning(stage, 'Connected to AWS account 123456789012, region ap-southeast-1')).toBe(true);
  });

  it('is not running once the engine has taken over the same stage', () => {
    expect(isAwsMonitorRunning(stage, '+ python3 engine.py --input /workspace/findings/scan-inputs')).toBe(false);
    expect(isAwsMonitorRunning(stage, '4/7 score')).toBe(false);
  });

  it('is not running outside that stage', () => {
    expect(isAwsMonitorRunning(['Scans'], 'checking EC2 instances ... 0 finding(s)')).toBe(false);
    expect(isAwsMonitorRunning(undefined, undefined)).toBe(false);
  });
});
