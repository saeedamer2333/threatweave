import { describe, it, expect } from 'vitest';
import { healthLabel, dirGlob, filterFindings, formatElapsed } from './lib';
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

  it('matches the real build-9 score (15) as Critical', () => {
    // Regression anchor: this is the exact score cited throughout the FYP
    // document's Chapter 4 screenshots and captions.
    expect(healthLabel(15).text).toBe('Critical');
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
