import type { Finding } from './types';

/** Health-score band shown on the ring gauge and its colour class. */
export function healthLabel(score: number): { text: string; cls: string } {
  if (score >= 80) return { text: 'Healthy', cls: 'good' };
  if (score >= 50) return { text: 'At Risk', cls: 'warn' };
  return { text: 'Critical', cls: 'bad' };
}

/** Milliseconds since a scan started -> "3m 42s" / "8s", for the live elapsed
 * timer next to "Run scan". Negative/invalid input (clock skew, not started
 * yet) clamps to 0s rather than showing something nonsensical like "-4s". */
export function formatElapsed(ms: number): string {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
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
