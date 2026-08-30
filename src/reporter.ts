/**
 * Output formatting for scan reports.
 * Supports text, JSON, markdown, SARIF 2.1.0, and GitLab Dependency
 * Scanning report output.
 */

import { randomUUID } from "node:crypto";
import type {
  Finding,
  IncidentCluster,
  PolicyEffect,
  PolicyEffectEntry,
  SbomAnnotation,
  SbomComponent,
  SbomProperty,
  ScanReport,
  Severity,
} from "./types.js";
import { describeInventoryCoverage } from "./sbom-generator.js";

/** bom-ref of the component every SBOM this tool emits is about. */
const SUBJECT_BOM_REF = "target";

const PARTIAL_SCAN_WARNING =
  "Scan incomplete: one or more configured checks or files could not be fully evaluated. No clean verdict can be established until coverage gaps are resolved.";

/**
 * v5.29 (issue 168). One sentence, rendered identically by all nine formats,
 * so a reader who has met it in the CLI recognises it in a pull request
 * comment, in SARIF, or in a GitLab report.
 *
 * The wording is the point. A narrowed scan and a clean scan produce the same
 * empty finding list, and until this block existed nothing in markdown, SARIF,
 * SBOM, GitLab, JUnit, HTML or the badge distinguished them. The `ignore:` form
 * did not even increment suppressedCount, because it prunes files before any
 * rule opens them, so the text format had nothing to print either.
 */
const POLICY_EFFECT_HEADLINE =
  "Policy narrowed this scan. The rules and paths below produced no findings because the loaded config switched them off, not because the code was examined and found clean.";

/** "EVAL_ATOB (no reason given)" or "EVAL_ATOB (reason as written)". */
function policyEntryText(entry: PolicyEffectEntry): string {
  return entry.reason ? `${entry.id} (${entry.reason})` : `${entry.id} (no reason given)`;
}

/**
 * The non-empty groups, ordered by how completely each one hides code:
 * `ignore` never opens the file, `rules.disable` drops the finding before it
 * is counted, `suppress` at least records that something was removed.
 */
function policyEffectGroups(
  effect: PolicyEffect,
): Array<{ label: string; entries: PolicyEffectEntry[] }> {
  return [
    { label: "Paths not scanned (ignore)", entries: effect.ignoredGlobs },
    { label: "Rules disabled (rules.disable)", entries: effect.disabledRules },
    { label: "Rules suppressed (suppress)", entries: effect.suppressedRules },
  ].filter((group) => group.entries.length > 0);
}

/**
 * Single-line rendering for the formats that carry a string rather than a
 * block: the SARIF notification, the GitLab scan message, the SBOM property
 * and the JUnit testsuite property.
 */
function policyEffectLine(effect: PolicyEffect): string {
  const parts = policyEffectGroups(effect).map(
    (group) => `${group.label}: ${group.entries.map(policyEntryText).join(", ")}`,
  );
  return `${POLICY_EFFECT_HEADLINE} Config: ${effect.configFile}. ${parts.join(". ")}.`;
}

/**
 * The coverage denominator, for the machine formats (unreleased, issue 205).
 *
 * `filesScanned` and `totalFiles` are computed on every scan and reach the
 * report, but SARIF, GitLab and JUnit never read either one. A verdict with no
 * denominator describes only what was FOUND, never how much was LOOKED AT, so
 * "nothing found in 0 files" and "nothing found in a real tree" produced the
 * same artefact. `null` means the report carried no summary at all - which is
 * "could not answer", and is deliberately not rendered as 0.
 */
function coverageProperties(report: ScanReport): {
  filesScanned: number | null;
  totalFiles: number | null;
  scanType: string;
} {
  return {
    filesScanned: report.summary?.filesScanned ?? null,
    totalFiles: report.summary?.totalFiles ?? null,
    scanType: report.scanType,
  };
}

/** One line stating the denominator, for formats that carry strings not objects. */
function coverageLine(report: ScanReport): string {
  const scanned = report.summary?.filesScanned;
  const total = report.summary?.totalFiles;
  if (scanned === undefined || total === undefined) {
    return "Coverage: not recorded in this report.";
  }
  if (scanned === 0) {
    return `Coverage: 0 of ${total} files were examined. This result describes nothing about the target and is not a clean verdict.`;
  }
  return `Coverage: ${scanned} of ${total} files were examined.`;
}

/**
 * The SLSA grade together with what produced it and what was never checked
 * (unreleased, issues 188/190). A bare level cannot express "not assessed", so no
 * format may render the number without this beside it.
 */
function slsaProperties(report: ScanReport): {
  level: number;
  basis: string[];
  notAssessed: string[];
  attestation?: { present: boolean; kind?: string; structurallyValid: boolean; signatureStatus?: string };
} | undefined {
  const assessment = report.slsaAssessment;
  if (!assessment) return undefined;
  return {
    level: assessment.level,
    basis: [...assessment.basis],
    notAssessed: [...assessment.notAssessed],
    attestation: {
      present: assessment.attestation.present,
      kind: assessment.attestation.kind,
      structurallyValid: assessment.attestation.structurallyValid,
      signatureStatus: assessment.attestation.signatureStatus,
    },
  };
}

/** Default CLI gate semantics for a collection of findings. */
export function getFindingsExitCode(
  findings: ReadonlyArray<Pick<Finding, "severity">>,
): 0 | 1 | 2 {
  if (findings.some((finding) => finding.severity === "critical")) return 2;
  return findings.some((finding) => finding.severity === "high") ? 1 : 0;
}

/**
 * A partial scan is an indeterminate result, never a successful clean gate.
 * Critical findings retain the CLI's stronger exit code 2; otherwise partial
 * coverage exits 1, independently of --fail-on.
 */
export function getReportExitCode(
  report: ScanReport,
  failOn?: string,
): 0 | 1 | 2 {
  if (!failOn && report.summary.critical > 0) return 2;
  if (report.partialScan) return 1;

  if (failOn) {
    const severityOrder: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      info: 0,
    };
    const threshold = severityOrder[failOn] ?? 0;
    return report.findings.some(
      (finding) => (severityOrder[finding.severity] ?? 0) >= threshold,
    )
      ? 1
      : 0;
  }

  return report.summary.high > 0 ? 1 : 0;
}

/**
 * Defensively remove stale clean-verdict recommendations from partial reports.
 * Scanner-specific generators also understand partial coverage, but reports can
 * be loaded from older JSON or constructed by API consumers.
 */
function normalizePartialReport(report: ScanReport): ScanReport {
  if (!report.partialScan) return report;

  const recommendations = report.recommendations.filter(
    (recommendation) =>
      !/(?:no malicious indicators|appears (?:clean|safe)|no findings)/i.test(
        recommendation,
      ),
  );
  if (!recommendations.some((recommendation) => /scan (?:is )?incomplete/i.test(recommendation))) {
    recommendations.unshift(PARTIAL_SCAN_WARNING);
  }

  return { ...report, recommendations };
}

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "\x1b[91m", // bright red
  high: "\x1b[31m",     // red
  medium: "\x1b[33m",   // yellow
  low: "\x1b[36m",      // cyan
  info: "\x1b[37m",     // white
};
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

/**
 * Format a scan report for output.
 */
export function formatReport(
  report: ScanReport,
  format: "text" | "json" | "markdown" | "sarif" | "sbom" | "html" | "badge" | "gitlab" | "junit",
): string {
  const outputReport = normalizePartialReport(report);
  switch (format) {
    case "json":
      return formatJson(outputReport);
    case "markdown":
      return formatMarkdown(outputReport);
    case "sarif":
      return formatSarif(outputReport);
    case "sbom":
      return formatSbom(outputReport);
    case "html":
      return formatHtml(outputReport);
    case "badge":
      return formatBadge(outputReport);
    case "gitlab":
      return formatGitlab(outputReport);
    case "junit":
      return formatJunit(outputReport);
    case "text":
    default:
      return formatText(outputReport);
  }
}

/**
 * Format as JSON.
 */
function formatJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Format as human-readable text with box-drawing borders and visual gauges.
 */
function formatText(report: ScanReport): string {
  const lines: string[] = [];

  // ── layout constants ───────────────────────────────────────────────────────
  const VERSION = "6.0.7";
  const W = 76; // visible chars between "│ " and " │" (total line = 80)

  // ── ANSI helpers ───────────────────────────────────────────────────────────
  const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");
  const visLen = (s: string) => stripAnsi(s).length;
  /** Pad string to n *visible* chars, appending ch. */
  const padR = (s: string, n: number, ch = " ") =>
    s + ch.repeat(Math.max(0, n - visLen(s)));
  /** Truncate to n visible chars, adding ellipsis if needed. */
  const trunc = (s: string, n: number) =>
    visLen(s) <= n ? s : stripAnsi(s).slice(0, n - 1) + "…";
  /** Word-wrap plain text to lines of at most maxWidth visible chars. */
  const wrapText = (s: string, maxWidth: number): string[] => {
    const plain = stripAnsi(s);
    if (plain.length <= maxWidth) return [plain];
    const words = plain.split(/(\s+)/);
    const result: string[] = [];
    let line = "";
    for (const w of words) {
      if (line.length + w.length > maxWidth && line.length > 0) {
        result.push(line.trimEnd());
        line = w.trimStart();
      } else {
        line += w;
      }
    }
    if (line.trim()) result.push(line.trimEnd());
    return result.length > 0 ? result : [plain.slice(0, maxWidth)];
  };

  // ── box-drawing helpers ────────────────────────────────────────────────────
  const boxTop = (title = "") => {
    if (!title) return "┌" + "─".repeat(78) + "┐";
    const t = `  ${title}  `;
    const rem = 78 - t.length;
    const l = Math.floor(rem / 2);
    return "┌" + "─".repeat(l) + t + "─".repeat(rem - l) + "┐";
  };
  const boxBot  = ()  => "└" + "─".repeat(78) + "┘";
  const boxDiv  = ()  => "├" + "─".repeat(78) + "┤";
  const boxBlank = () => "│" + " ".repeat(78) + "│";
  const boxDot  = ()  => "│ " + DIM + "·".repeat(76) + RESET + " │";
  /** Row whose visible content is exactly W chars (padding added automatically). */
  const boxRow  = (s = "") => "│ " + padR(s, W) + " │";

  // ── color/bar helpers ──────────────────────────────────────────────────────
  const scoreColor = (score: number) =>
    score === 0    ? "\x1b[32m"  // green
    : score <= 10  ? "\x1b[36m"  // cyan
    : score <= 30  ? "\x1b[33m"  // yellow
    : score <= 60  ? "\x1b[31m"  // red
    : "\x1b[91m";                 // bright red

  const trustColor = (score: number) =>
    score >= 80 ? "\x1b[32m" : score >= 50 ? "\x1b[33m" : "\x1b[31m";

  const riskColor = (score: number) =>
    score <= 20 ? "\x1b[32m" : score <= 50 ? "\x1b[33m" : "\x1b[31m";

  const mkBar = (value: number, max: number, width: number) => {
    const n = max > 0 ? Math.round((value / max) * width) : 0;
    return "█".repeat(n) + "░".repeat(width - n);
  };

  // ── HEADER ─────────────────────────────────────────────────────────────────
  lines.push("");
  lines.push("╔" + "═".repeat(78) + "╗");
  {
    const label = "  supply-chain-guard";          // 20 visible chars
    const ver   = `v${VERSION}  `;                 // e.g. "v5.1.0  " = 8 visible
    const spaces = " ".repeat(Math.max(0, 78 - label.length - ver.length));
    lines.push("║" + BOLD + label + RESET + spaces + DIM + ver + RESET + "║");
  }
  lines.push("╚" + "═".repeat(78) + "╝");
  lines.push("");

  // ── METADATA ───────────────────────────────────────────────────────────────
  const metaRow = (key: string, val: string) =>
    `  ${BOLD}${key.padEnd(10)}${RESET}${val}`;

  lines.push(metaRow("Target", report.target));
  if (report.scanType === "directory" || report.scanType === "github") {
    lines.push(metaRow("Type", `${report.scanType}  ·  ${report.summary.filesScanned} / ${report.summary.totalFiles} files scanned`));
  } else {
    lines.push(metaRow("Type", report.scanType));
  }
  lines.push(metaRow("Duration", `${report.durationMs}ms`));
  lines.push(metaRow("Time", report.timestamp));
  lines.push(
    metaRow(
      "Commit",
      report.commit
        ? `${report.commit}${report.branch ? ` (${report.branch})` : ""}`
        : "[not a git repository]",
    ),
  );
  if (report.detectionSet) {
    const ds = report.detectionSet;
    const dsInfo = `v${ds.bundledVersion} (${ds.effectiveEntryCount} entries${ds.cacheMerged ? `, merged cache` : ""}${ds.generatedAt ? `, generated ${ds.generatedAt}` : ""})`;
    lines.push(metaRow("Detection Set", dsInfo));
  }
  if (report.partialScan) {
    lines.push(metaRow("Status", "\x1b[33mPARTIAL - coverage incomplete\x1b[0m"));
  }
  lines.push("");

  // ── RISK SCORE ─────────────────────────────────────────────────────────────
  {
    const sc    = report.score;
    const scCol = report.partialScan ? "\x1b[33m" : scoreColor(sc);
    const level = report.partialScan ? "PARTIAL" : report.riskLevel.toUpperCase();
    const BAR_W = 36;
    const filled = Math.round((sc / 100) * BAR_W);
    const gauge  = scCol + "█".repeat(filled) + DIM + "░".repeat(BAR_W - filled) + RESET;
    const scoreStr = `${sc} / 100`;

    lines.push(boxTop("RISK SCORE"));
    lines.push(boxBlank());
    lines.push(boxRow(`  ${scCol}${BOLD}${scoreStr}${RESET}   ${gauge}   ${BOLD}${scCol}${level}${RESET}`));

    if (report.slsaLevel !== undefined) {
      const slsaCol = report.slsaLevel >= 3 ? "\x1b[32m" : report.slsaLevel === 2 ? "\x1b[36m" : report.slsaLevel === 1 ? "\x1b[33m" : "\x1b[31m";
      const slsaBar = slsaCol + mkBar(report.slsaLevel, 3, 24) + RESET;
      lines.push(boxRow(`  ${DIM}SLSA${RESET}        ${slsaBar}  ${slsaCol}${BOLD}${report.slsaLevel}/3${RESET}`));
      // (unreleased, issues 188/190): the bar used to be the whole story. A full green
      // 3/3 was produced by an unsigned attestation, and by a commented-out
      // publish step, with nothing beside it to say what had been checked. The
      // grade is a posture score from a static read, and now says so here.
      if (report.slsaAssessment) {
        const detail = (label: string, colour: string, item: string) => {
          const wrapped = wrapText(`${label} ${item}`, W - 6);
          wrapped.forEach((line, i) =>
            lines.push(boxRow(`    ${colour}${i === 0 ? line : `  ${line}`}${RESET}`)),
          );
        };
        for (const item of report.slsaAssessment.basis) detail("from:", DIM, item);
        // The caveat block is rendered from Level 2 up: that is where the tool
        // starts making a provenance claim a reader can over-read. Levels 0 and
        // 1 assert no provenance, so the same nine lines there would be noise
        // that trains readers to skip the block. Every MACHINE format carries
        // `notAssessed` unconditionally, so nothing is lost from an artefact.
        if (report.slsaLevel >= 2) {
          for (const item of report.slsaAssessment.notAssessed) {
            detail("NOT ASSESSED:", "\x1b[33m", item);
          }
        }
      }
    }
    if (report.sbomDocument) {
      lines.push(boxRow(`  ${DIM}SBOM${RESET}        CycloneDX 1.6  ·  ${report.sbomDocument.components.length} components`));
      // Issue 195: a bare count cannot distinguish an empty inventory from an
      // unread one. The same sentence the --sbom-output stderr line prints
      // belongs here too, or the default text report is still that bare count.
      for (const line of wrapText(describeInventoryCoverage(report.sbomDocument), W - 6)) {
        lines.push(boxRow(`    ${DIM}${line}${RESET}`));
      }
    }

    lines.push(boxBlank());
    lines.push(boxBot());
    lines.push("");
  }

  // ── FINDINGS SUMMARY ───────────────────────────────────────────────────────
  {
    const totalFindings =
      report.summary.critical + report.summary.high +
      report.summary.medium  + report.summary.low  + report.summary.info;

    lines.push(boxTop("FINDINGS SUMMARY"));

    if (totalFindings === 0 && report.partialScan) {
      lines.push(boxBlank());
      lines.push(boxRow(`  \x1b[33m${BOLD}!  No reported findings - scan incomplete${RESET}`));
      lines.push(boxBlank());
    } else if (totalFindings === 0) {
      lines.push(boxBlank());
      lines.push(boxRow(`  \x1b[32m${BOLD}✓  No findings - clean${RESET}`));
      lines.push(boxBlank());
    } else {
      const maxCount = Math.max(
        report.summary.critical, report.summary.high,
        report.summary.medium,  report.summary.low, report.summary.info,
      );
      const BAR_W = 32;
      const sevRow = (label: string, count: number, color: string) => {
        const countStr = String(count).padStart(3);
        const b = count > 0
          ? color + mkBar(count, maxCount, BAR_W) + RESET
          : DIM + "─".repeat(BAR_W) + RESET;
        return boxRow(`  ${color}${BOLD}${label.padEnd(10)}${RESET}  ${countStr}  ${b}`);
      };
      lines.push(sevRow("CRITICAL", report.summary.critical, SEVERITY_COLORS.critical));
      lines.push(sevRow("HIGH",     report.summary.high,     SEVERITY_COLORS.high));
      lines.push(sevRow("MEDIUM",   report.summary.medium,   SEVERITY_COLORS.medium));
      lines.push(sevRow("LOW",      report.summary.low,      SEVERITY_COLORS.low));
      lines.push(sevRow("INFO",     report.summary.info,     SEVERITY_COLORS.info));
      if (report.suppressedCount && report.suppressedCount > 0) {
        lines.push(boxBlank());
        lines.push(boxRow(`  ${DIM}${report.suppressedCount} finding(s) suppressed by policy / baseline${RESET}`));
      }
    }

    lines.push(boxBot());
    lines.push("");
  }

  // ── POLICY IN EFFECT ───────────────────────────────────────────────────────
  // Deliberately outside the box: an entry carries a free-text reason of any
  // length, and a wrapped reason must never be truncated to keep a border
  // aligned. The whole purpose of this block is that nothing it names is lost.
  if (report.policyEffect) {
    const effect = report.policyEffect;
    lines.push(`${BOLD}POLICY IN EFFECT${RESET}  ${DIM}${effect.configFile}${RESET}`);
    for (const line of wrapText(POLICY_EFFECT_HEADLINE, W)) lines.push(line);
    lines.push("");
    for (const group of policyEffectGroups(effect)) {
      lines.push(`  ${BOLD}${group.label}${RESET}`);
      for (const entry of group.entries) {
        lines.push(`    - ${policyEntryText(entry)}`);
      }
    }
    lines.push("");
  }

  // ── FINDINGS DETAIL ────────────────────────────────────────────────────────
  if (report.findings.length > 0) {
    const sorted = [...report.findings].sort(
      (a, b) => severityRank(b.severity) - severityRank(a.severity),
    );

    lines.push(boxTop("FINDINGS"));
    lines.push(boxBlank());

    for (let i = 0; i < sorted.length; i++) {
      const f      = sorted[i];
      const color  = SEVERITY_COLORS[f.severity];
      const label  = `[${f.severity.toUpperCase()}]`;   // e.g. "[CRITICAL]" = 10
      const indent = " ".repeat(label.length + 2);
      const avail  = W - label.length - 4;              // content width after indent

      lines.push(boxRow(`  ${color}${BOLD}${label}${RESET}  ${BOLD}${trunc(f.rule, avail)}${RESET}`));
      // Description - word-wrapped
      for (const dl of wrapText(f.description, avail)) {
        lines.push(boxRow(`  ${indent}${dl}`));
      }
      if (f.file) {
        const loc = f.line ? `${f.file}:${f.line}` : f.file;
        lines.push(boxRow(`  ${indent}${DIM}${trunc(loc, avail)}${RESET}`));
      }
      // Match - word-wrapped, first line gets "match  " tag
      if (f.match) {
        const matchTag = "match  ";
        const matchPad = " ".repeat(matchTag.length);
        const matchLines = wrapText(f.match, avail - matchTag.length);
        lines.push(boxRow(`  ${indent}${DIM}${matchTag}${RESET}${matchLines[0]}`));
        for (let ml = 1; ml < matchLines.length; ml++) {
          lines.push(boxRow(`  ${indent}${DIM}${matchPad}${RESET}${matchLines[ml]}`));
        }
      }
      // Fix - word-wrapped, first line gets "fix    " tag
      const fixTag = "fix    ";
      const fixPad = " ".repeat(fixTag.length);
      const fixLines = wrapText(f.recommendation, avail - fixTag.length);
      lines.push(boxRow(`  ${indent}${DIM}${fixTag}${RESET}${fixLines[0]}`));
      for (let fl = 1; fl < fixLines.length; fl++) {
        lines.push(boxRow(`  ${indent}${DIM}${fixPad}${RESET}${fixLines[fl]}`));
      }

      if (i < sorted.length - 1) {
        lines.push(boxBlank());
        lines.push(boxDot());
        lines.push(boxBlank());
      }
    }

    lines.push(boxBlank());
    lines.push(boxBot());
    lines.push("");
  }

  // ── TRUST BREAKDOWN ────────────────────────────────────────────────────────
  if (report.trustBreakdown) {
    const tb   = report.trustBreakdown;
    const BAR_W = 32;
    const tbRow = (label: string, dim: { score: number; assessed?: boolean }) => {
      if (dim.assessed === false) {
        return boxRow(`  ${label.padEnd(14)}${DIM}[not assessed]${RESET}`);
      }
      const col = trustColor(dim.score);
      return boxRow(`  ${label.padEnd(14)}${col}${mkBar(dim.score, 100, BAR_W)}${RESET}  ${col}${dim.score}/100${RESET}`);
    };

    lines.push(boxTop("TRUST BREAKDOWN"));
    lines.push(tbRow("Publisher",    tb.publisherTrust));
    lines.push(tbRow("Code",         tb.codeQuality));
    lines.push(tbRow("Dependencies", tb.dependencyTrust));
    lines.push(tbRow("Release",      tb.releaseProcess));
    lines.push(boxDiv());
    lines.push(boxRow(`  ${"Overall".padEnd(14)}${trustColor(tb.overallScore)}${mkBar(tb.overallScore, 100, BAR_W)}${RESET}  ${trustColor(tb.overallScore)}${tb.overallScore}/100${RESET}`));
    lines.push(boxBot());
    lines.push("");
  }

  // ── RISK DIMENSIONS ────────────────────────────────────────────────────────
  if (report.riskDimensions) {
    const rd    = report.riskDimensions;
    const BAR_W = 32;
    const rdRow = (label: string, score: number) => {
      const col = riskColor(score);
      return boxRow(`  ${label.padEnd(14)}${col}${mkBar(score, 100, BAR_W)}${RESET}  ${col}${score}/100${RESET}`);
    };

    lines.push(boxTop("RISK DIMENSIONS"));
    lines.push(rdRow("Code Risk",   rd.codeRisk));
    lines.push(rdRow("Dep Risk",    rd.dependencyRisk));
    lines.push(rdRow("Repo Trust",  rd.repoTrust));
    lines.push(rdRow("CI/CD Risk",  rd.ciCdRisk));
    if (rd.threatIntelMatches > 0) {
      lines.push(boxRow(`  ${SEVERITY_COLORS.critical}${BOLD}Threat Intel    ${rd.threatIntelMatches} match(es)${RESET}`));
    }
    lines.push(boxRow(`  ${DIM}Confidence      ${Math.round(rd.confidence * 100)}%${RESET}`));
    lines.push(boxBot());
    lines.push("");
  }

  // ── CORRELATED INCIDENTS ───────────────────────────────────────────────────
  if (report.incidents && report.incidents.length > 0) {
    lines.push(boxTop("CORRELATED INCIDENTS"));
    lines.push(boxBlank());
    for (const incident of report.incidents) {
      const conf  = Math.round(incident.confidence * 100);
      const color = SEVERITY_COLORS[incident.severity];
      const label = `[${incident.severity.toUpperCase()}]`;
      const matched = incident.matchedIndicatorsCount ?? incident.indicators.length;
      const total = incident.totalIndicatorsCount ?? incident.indicators.length;
      lines.push(boxRow(`  ${color}${BOLD}${label}${RESET}  ${BOLD}${trunc(incident.name, W - label.length - 20)}${RESET}  ${DIM}${conf}% confidence${RESET}`));
      lines.push(boxRow(`  ${DIM}${trunc(incident.narrative, W - 2)}${RESET}`));
      lines.push(boxRow(`  Indicators (${matched}/${total}): ${DIM}${trunc(incident.indicators.join(", "), W - 20)}${RESET}`));
      lines.push(boxBlank());
    }
    lines.push(boxBot());
    lines.push("");
  }

  // ── REMEDIATION PLAN ───────────────────────────────────────────────────────
  if (report.remediations && report.remediations.length > 0) {
    lines.push(boxTop("REMEDIATION PLAN"));
    lines.push(boxBlank());
    for (const rem of report.remediations.slice(0, 5)) {
      const pColor = rem.priority === "critical" ? SEVERITY_COLORS.critical
        : rem.priority === "high" ? SEVERITY_COLORS.high : SEVERITY_COLORS.medium;
      const label = `[${rem.priority.toUpperCase()}]`;
      lines.push(boxRow(`  ${pColor}${BOLD}${label}${RESET}  ${BOLD}${trunc(rem.title, W - label.length - 4)}${RESET}`));
      for (const step of rem.steps) {
        lines.push(boxRow(`       ${DIM}→  ${trunc(step, W - 10)}${RESET}`));
      }
      lines.push(boxBlank());
    }
    lines.push(boxBot());
    lines.push("");
  }

  // ── RECOMMENDATIONS ────────────────────────────────────────────────────────
  if (report.recommendations.length > 0) {
    lines.push(boxTop("RECOMMENDATIONS"));
    lines.push(boxBlank());
    for (const rec of report.recommendations) {
      lines.push(boxRow(`  ›  ${trunc(rec, W - 5)}`));
    }
    lines.push(boxBlank());
    lines.push(boxBot());
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Format as markdown (for PR comments, GitHub Actions).
 */
// Neutralize attacker-controlled scan content before it is embedded in the
// markdown report (which the GitHub Action posts as a PR comment). Without this,
// a scanned package whose content contains backticks, newlines, or HTML can break
// out of an inline code span or header and inject arbitrary markdown or HTML.
function mdInlineCode(value: unknown): string {
  // Content placed inside a backtick code span: a backtick or newline closes it.
  return String(value)
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/[\u200b-\u200f\u202a-\u202e\ufeff]/g, "")
    .replace(/`/g, "'");
}

function mdText(value: unknown): string {
  // Content placed as plain Markdown (headers, lists, and cells) must remain
  // text. HTML entities render as the original punctuation but are not parsed
  // as image, link, emphasis, heading, or table syntax.
  return String(value)
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/[\u200b-\u200f\u202a-\u202e\ufeff]/g, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/`/g, "'")
    .replace(
      /\\|!|\[|\]|\(|\)|\*|_|#|~|\|/g,
      (character) => `&#${character.charCodeAt(0)};`,
    );
}

function mdCell(value: unknown): string {
  // Inline code inside a markdown TABLE cell: also escape the pipe, which GFM
  // treats as a column separator even inside a backtick span.
  return mdInlineCode(value).replace(/\|/g, "\\|");
}

function formatMarkdown(report: ScanReport): string {
  const lines: string[] = [];

  // Header
  lines.push("## 🛡️ supply-chain-guard Scan Report");
  lines.push("");
  lines.push(`| Property | Value |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Tool | \`${mdCell(report.tool || "supply-chain-guard v6.0.7")}\` |`);
  lines.push(`| Target | \`${mdCell(report.target)}\` |`);
  lines.push(`| Type | ${mdText(report.scanType)} |`);
  lines.push(`| Time | ${mdText(report.timestamp)} |`);
  lines.push(`| Commit | \`${mdCell(report.commit ?? "none (not a git repository)")}\` |`);
  if (report.detectionSet) {
    const ds = report.detectionSet;
    lines.push(
      `| Detection Set | \`v${mdCell(ds.bundledVersion)} (${ds.effectiveEntryCount} entries${ds.cacheMerged ? ", merged cache" : ""}${ds.generatedAt ? `, generated ${ds.generatedAt}` : ""})\` |`,
    );
  }
  lines.push(`| Duration | ${mdText(report.durationMs)}ms |`);
  lines.push(
    report.partialScan
      ? `| **Risk Score** | **${report.score}/100** (PARTIAL; detected risk: ${report.riskLevel.toUpperCase()}) |`
      : `| **Risk Score** | **${report.score}/100** (${report.riskLevel.toUpperCase()}) |`,
  );
  if (report.partialScan) {
    lines.push("| **Scan Status** | **PARTIAL - coverage incomplete** |");
  }
  lines.push("");

  // Policy in effect (v5.29, issue 168). Placed ABOVE the summary on purpose:
  // markdown is the Action's default format and the body of its pull request
  // comment, so this is the one rendering a human reviewer actually reads
  // before deciding a green check means the change is clean.
  if (report.policyEffect) {
    const effect = report.policyEffect;
    lines.push("### ⚠️ Policy in effect");
    lines.push("");
    // The headline and the group labels are this module's own constants and are
    // emitted verbatim. Everything that came out of the config file - rule ids,
    // globs, reasons - goes through the escapers, because a policy file in a
    // scanned tree is attacker-controlled input like any other scanned content.
    lines.push(`> ${POLICY_EFFECT_HEADLINE}`);
    lines.push(">");
    lines.push(`> Loaded from \`${mdInlineCode(effect.configFile)}\` in the scanned tree.`);
    lines.push("");
    for (const group of policyEffectGroups(effect)) {
      lines.push(`- **${group.label}:**`);
      for (const entry of group.entries) {
        const reason = entry.reason ? mdText(entry.reason) : "_no reason given_";
        lines.push(`  - \`${mdInlineCode(entry.id)}\` ${reason}`);
      }
    }
    lines.push("");
  }

  // Summary
  lines.push("### Summary");
  lines.push("");

  if (report.scanType === "directory" || report.scanType === "github") {
    lines.push(
      `Scanned ${report.summary.filesScanned} of ${report.summary.totalFiles} files.`,
    );
    lines.push("");
  }

  if (report.partialScan) {
    lines.push("> **Scan incomplete:** No clean verdict can be established until coverage gaps are resolved.");
    lines.push("");
  }

  if (report.findings.length === 0 && !report.partialScan) {
    lines.push("> ✅ No malicious indicators detected.");
    lines.push("");
  } else {
    const badges: string[] = [];
    if (report.summary.critical > 0)
      badges.push(`🔴 ${report.summary.critical} critical`);
    if (report.summary.high > 0) badges.push(`🟠 ${report.summary.high} high`);
    if (report.summary.medium > 0)
      badges.push(`🟡 ${report.summary.medium} medium`);
    if (report.summary.low > 0) badges.push(`🔵 ${report.summary.low} low`);
    if (report.summary.info > 0) badges.push(`⚪ ${report.summary.info} info`);
    lines.push(badges.join(" | "));
    lines.push("");
  }

  // Findings
  if (report.findings.length > 0) {
    lines.push("### Findings");
    lines.push("");

    const sorted = [...report.findings].sort(
      (a, b) => severityRank(b.severity) - severityRank(a.severity),
    );

    for (const finding of sorted) {
      lines.push(
        `#### ${SEVERITY_ICONS[finding.severity]} [${finding.severity.toUpperCase()}] ${mdText(finding.description)}`,
      );
      lines.push("");
      lines.push(`- **Rule:** \`${mdInlineCode(finding.rule)}\``);
      if (finding.file) {
        const location = finding.line
          ? `${finding.file}:${finding.line}`
          : finding.file;
        lines.push(`- **File:** \`${mdInlineCode(location)}\``);
      }
      if (finding.match) {
        lines.push(`- **Match:** \`${mdInlineCode(finding.match)}\``);
      }
      lines.push(`- **Recommendation:** ${mdText(finding.recommendation)}`);
      lines.push("");
    }
  }

  // Recommendations
  if (report.recommendations.length > 0) {
    lines.push("### Recommendations");
    lines.push("");
    for (const rec of report.recommendations) {
      lines.push(`- ${mdText(rec)}`);
    }
    lines.push("");
  }

  lines.push(
    `---\n*Generated by [supply-chain-guard](https://github.com/homeofe/supply-chain-guard)*`,
  );

  return lines.join("\n");
}

/**
 * Map finding severity to SARIF level.
 */
function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
    default:
      return "note";
  }
}

/**
 * Format as SARIF 2.1.0 for GitHub Code Scanning.
 */
function formatSarif(report: ScanReport): string {
  const rules: Array<{
    id: string;
    shortDescription: { text: string };
    defaultConfiguration: { level: string };
  }> = [];
  const ruleIndex = new Map<string, number>();

  const results: Array<Record<string, unknown>> = [];

  for (const finding of report.findings.filter((f) => !f.suppressed)) {
    if (!ruleIndex.has(finding.rule)) {
      ruleIndex.set(finding.rule, rules.length);
      rules.push({
        id: finding.rule,
        shortDescription: { text: finding.description },
        defaultConfiguration: { level: sarifLevel(finding.severity) },
      });
    }

    const result: Record<string, unknown> = {
      ruleId: finding.rule,
      ruleIndex: ruleIndex.get(finding.rule),
      level: sarifLevel(finding.severity),
      message: { text: finding.description },
    };

    // v5.30: incident membership on the result itself. SARIF 2.1.0 property
    // bags are the standard slot for tool-specific correlation data, and
    // without it a SARIF consumer sees only the flat finding list - which is
    // the thing the correlation engine exists to turn into evidence.
    const incidentIds = incidentIdsOf(finding);
    if (incidentIds.length > 0) {
      result.properties = {
        incidentIds,
        incidentNames: incidentIds.map(
          (id) => report.incidents?.find((i) => i.id === id)?.name ?? id,
        ),
      };
    }

    if (finding.file) {
      const region: Record<string, number> = {};
      if (finding.line) {
        region.startLine = finding.line;
      }
      result.locations = [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.file },
            ...(finding.line ? { region } : {}),
          },
        },
      ];
    }

    results.push(result);
  }

  // Run-level notifications. Partial coverage stays FIRST: it was the only
  // notification before v5.29 and consumers index it positionally.
  const notifications: Array<Record<string, unknown>> = [];
  if (report.partialScan) {
    notifications.push({
      level: "warning",
      message: { text: PARTIAL_SCAN_WARNING },
    });
  }
  if (report.policyEffect) {
    notifications.push({
      level: "warning",
      message: { text: policyEffectLine(report.policyEffect) },
    });
  }

  // The v5.2.40 rule still holds: suppressed FINDINGS never enter machine
  // output. What goes in here is policy METADATA - which rules and paths the
  // config removed - which is the opposite of leaking a suppressed result and
  // is the only way a SARIF consumer can tell a narrowed scan from a clean one.
  //
  // (unreleased, issue 205): the invocation is now ALWAYS emitted, because it is the
  // only place a SARIF artefact can state its own denominator. A SARIF file
  // with zero results and no coverage was byte-identical whether it examined a
  // clean tree or nothing at all.
  const invocations = [
    {
      executionSuccessful: !report.partialScan,
      startTimeUtc: report.timestamp,
      endTimeUtc: report.timestamp,
      toolExecutionNotifications: notifications,
      properties: {
        ...(report.policyEffect ? { policyEffect: report.policyEffect } : {}),
        coverage: coverageProperties(report),
        ...(report.slsaAssessment ? { slsa: slsaProperties(report) } : {}),
      },
    },
  ];

  // v5.30: the incident list itself, on the run's property bag. The README's
  // NIS2 bullet names SARIF as a format the incident record is retained in, and
  // before this the whole document contained no incident name, no confidence
  // and no indicator list.
  const incidentList =
    report.incidents && report.incidents.length > 0
      ? report.incidents.map((incident) => ({
          id: incident.id,
          name: incident.name,
          severity: incident.severity,
          confidence: incident.confidence,
          indicators: incident.indicators,
          matchedIndicatorsCount: incident.matchedIndicatorsCount ?? incident.indicators.length,
          totalIndicatorsCount: incident.totalIndicatorsCount ?? incident.indicators.length,
          narrative: incident.narrative,
          findingCount: incident.findings.length,
        }))
      : undefined;

  const runProperties =
    incidentList || report.detectionSet
      ? {
          ...(incidentList ? { incidents: incidentList } : {}),
          ...(report.detectionSet ? { detectionSet: report.detectionSet } : {}),
        }
      : undefined;

  const versionControlProvenance = report.commit
    ? [
        {
          repositoryUri: report.repositoryUri ?? report.target,
          revisionId: report.commit,
          ...(report.branch ? { branch: report.branch } : {}),
        },
      ]
    : undefined;

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0" as const,
    runs: [
      {
        tool: {
          driver: {
            name: "supply-chain-guard",
            version: "6.0.7",
            informationUri: "https://github.com/homeofe/supply-chain-guard",
            rules,
          },
        },
        invocations,
        results,
        ...(versionControlProvenance ? { versionControlProvenance } : {}),
        ...(runProperties ? { properties: runProperties } : {}),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

/**
 * Get numeric rank for severity sorting.
 */
function severityRank(severity: Severity): number {
  const ranks: Record<Severity, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    info: 0,
  };
  return ranks[severity];
}

/**
 * Every incident a finding is an indicator of.
 *
 * `correlationIds` is the field to read; `correlationId` is the pre-v5.30
 * single-valued one, kept working for reports parsed from older JSON.
 */
function incidentIdsOf(finding: Finding): string[] {
  if (finding.correlationIds && finding.correlationIds.length > 0) {
    return finding.correlationIds;
  }
  return finding.correlationId ? [finding.correlationId] : [];
}

/**
 * The bom-ref of the component a finding's file belongs to, or the subject.
 *
 * CycloneDX 1.6 defines `vulnerabilities[].affects[].ref` as a reference to a
 * bom-ref in the SAME document. Before v5.30 this was `finding.file`, a path
 * relative to the scanned tree, so every reference resolved to nothing and a
 * consumer walking the graph could attribute no finding to any component. The
 * schema does not catch it: `refLinkType` is an unconstrained string.
 *
 * Prefix matching is attempted only when the inventory came from
 * package-lock.json, because only then are bom-refs relative paths
 * ("node_modules/@babel/parser", "packages/app"). On the package.json fallback
 * a bom-ref is a bare dependency key, and matching a file path against those
 * would attribute findings to components by coincidence.
 *
 * The deepest matching component wins, so a file inside a nested duplicate is
 * attributed to the nested copy rather than to the hoisted one.
 */
function resolveAffectedRef(
  file: string | undefined,
  components: SbomComponent[],
  refsArePaths: boolean,
): string {
  if (!file || !refsArePaths) return SUBJECT_BOM_REF;
  const normalized = file.replace(/\\/g, "/").replace(/^\.\//, "");
  let best = SUBJECT_BOM_REF;
  let bestLength = -1;
  for (const component of components) {
    const ref = component["bom-ref"];
    if (normalized !== ref && !normalized.startsWith(`${ref}/`)) continue;
    if (ref.length > bestLength) {
      best = ref;
      bestLength = ref.length;
    }
  }
  return best;
}

/**
 * One CycloneDX annotation per correlated incident.
 *
 * The incident is not inventory - it is commentary about a set of entries
 * already in the document - and `annotations` is the slot CycloneDX 1.6
 * provides for exactly that. `subjects` are the bom-refs of the vulnerability
 * entries the incident groups, so the link is navigable in both directions:
 * from the incident to its indicators, and from each entry via its
 * `supply-chain-guard:incident` properties.
 *
 * An incident whose findings all ended up suppressed contributes no subjects
 * and is dropped, because an annotation about nothing is not evidence.
 */
function buildIncidentAnnotations(
  incidents: IncidentCluster[] | undefined,
  subjectsByIncident: Map<string, string[]>,
  timestamp: string,
  toolVersion: string,
): SbomAnnotation[] {
  const annotations: SbomAnnotation[] = [];
  for (const incident of incidents ?? []) {
    const subjects = [...new Set(subjectsByIncident.get(incident.id) ?? [])];
    if (subjects.length === 0) continue;
    annotations.push({
      "bom-ref": `scg-${incident.id}`,
      subjects,
      annotator: {
        component: { type: "application", name: "supply-chain-guard", version: toolVersion },
      },
      timestamp,
      text:
        `Correlated incident ${incident.id}: ${incident.name}. ` +
        `Severity ${incident.severity}, compound confidence ${(incident.confidence * 100).toFixed(0)}%. ` +
        `Indicators (${incident.indicators.length}): ${incident.indicators.join(", ")}. ` +
        `${incident.narrative} ` +
        `Correlated by supply-chain-guard from findings in this scan; this is not advisory data.`,
    });
  }
  return annotations;
}

/**
 * Format as CycloneDX 1.6 JSON SBOM.
 * Uses the sbomDocument generated from actual package.json/lockfile if available,
 * otherwise falls back to a findings-based SBOM.
 *
 * v5.30: this is the ONE renderer behind both documented SBOM commands.
 * `--sbom-output <file>` used to serialise `report.sbomDocument` directly and
 * therefore shipped a file with no `vulnerabilities` key at all, while
 * `--format sbom` merged the findings in - two different documents from one
 * scan, both offered as the same artefact by the README.
 */
function formatSbom(report: ScanReport): string {
  const provenanceProperties: SbomProperty[] = [
    {
      name: "supply-chain-guard:commit",
      value: report.commit ?? "none (not a git repository)",
    },
    ...(report.detectionSet
      ? [
          {
            name: "supply-chain-guard:detection-set:version",
            value: report.detectionSet.bundledVersion,
          },
          {
            name: "supply-chain-guard:detection-set:entry-count",
            value: String(report.detectionSet.effectiveEntryCount),
          },
          ...(report.detectionSet.generatedAt
            ? [
                {
                  name: "supply-chain-guard:detection-set:generated-at",
                  value: report.detectionSet.generatedAt,
                },
              ]
            : []),
          {
            name: "supply-chain-guard:detection-set:cache-merged",
            value: String(report.detectionSet.cacheMerged),
          },
        ]
      : []),
  ];

  const partialScanProperty = {
    name: "supply-chain-guard:scan-status",
    value: "partial",
  };
  // CycloneDX metadata.properties is a name/value list, which is exactly the
  // slot for "this document describes a deliberately narrowed scan" (v5.29).
  const policyEffectProperties = report.policyEffect
    ? [
        {
          name: "supply-chain-guard:policy-config",
          value: report.policyEffect.configFile,
        },
        {
          name: "supply-chain-guard:policy-effect",
          value: policyEffectLine(report.policyEffect),
        },
      ]
    : [];

  // v4.9: use the proper CycloneDX 1.6 document if available
  if (report.sbomDocument) {
    const document = report.sbomDocument;
    const metadata = document.metadata;
    const refsArePaths =
      metadata.properties?.some(
        (p) =>
          p.name === "supply-chain-guard:sbom:component-source" &&
          p.value === "package-lock.json",
      ) ?? false;

    const subjectsByIncident = new Map<string, string[]>();
    const findingVulnerabilities = report.findings
      .filter((f) => !f.suppressed)
      .map((finding, idx) => {
        const bomRef = `scg-finding-${idx}`;
        const properties: SbomProperty[] = [];
        // CycloneDX gives a vulnerability no field for a source location, so
        // the path lives here while `affects` keeps pointing at a bom-ref that
        // exists. Dropping the path would lose the only thing that says WHERE.
        if (finding.file) {
          properties.push({ name: "supply-chain-guard:file", value: finding.file });
        }
        if (finding.line !== undefined) {
          properties.push({ name: "supply-chain-guard:line", value: String(finding.line) });
        }
        for (const incidentId of incidentIdsOf(finding)) {
          properties.push({ name: "supply-chain-guard:incident", value: incidentId });
          const subjects = subjectsByIncident.get(incidentId) ?? [];
          subjects.push(bomRef);
          subjectsByIncident.set(incidentId, subjects);
        }
        return {
          "bom-ref": bomRef,
          id: finding.rule,
          source: { name: "supply-chain-guard" },
          ratings: [{ severity: finding.severity, method: "other" }],
          description: finding.description,
          recommendation: finding.recommendation,
          affects: [
            { ref: resolveAffectedRef(finding.file, document.components, refsArePaths) },
          ],
          ...(properties.length > 0 ? { properties } : {}),
        };
      });

    const annotations = buildIncidentAnnotations(
      report.incidents,
      subjectsByIncident,
      metadata.timestamp,
      metadata.tools.components[0]?.version ?? "6.0.7",
    );

    const withVulns = {
      ...document,
      metadata: {
        ...metadata,
        properties: [
          ...(metadata.properties ?? []),
          ...provenanceProperties,
          ...(report.partialScan ? [partialScanProperty] : []),
          ...policyEffectProperties,
        ],
      },
      vulnerabilities: [...(document.vulnerabilities ?? []), ...findingVulnerabilities],
      ...(annotations.length > 0 ? { annotations } : {}),
    };
    return JSON.stringify(withVulns, null, 2);
  }

  // Fallback: findings-based SBOM (legacy, no lockfile present)
  const fallbackSubjectsByIncident = new Map<string, string[]>();
  const fallbackVulnerabilities = report.findings
    .filter((f) => !f.suppressed)
    .map((finding, idx) => {
      const bomRef = `vuln-${idx}`;
      const properties: SbomProperty[] = [];
      if (finding.file) {
        properties.push({ name: "supply-chain-guard:file", value: finding.file });
      }
      if (finding.line !== undefined) {
        properties.push({ name: "supply-chain-guard:line", value: String(finding.line) });
      }
      for (const incidentId of incidentIdsOf(finding)) {
        properties.push({ name: "supply-chain-guard:incident", value: incidentId });
        const subjects = fallbackSubjectsByIncident.get(incidentId) ?? [];
        subjects.push(bomRef);
        fallbackSubjectsByIncident.set(incidentId, subjects);
      }
      return {
        "bom-ref": bomRef,
        id: finding.rule,
        source: { name: "supply-chain-guard" },
        ratings: [{ severity: finding.severity, method: "other" }],
        description: finding.description,
        recommendation: finding.recommendation,
        // This branch emits no components at all, so the subject is the only
        // bom-ref anything can resolve to.
        affects: [{ ref: SUBJECT_BOM_REF }],
        ...(properties.length > 0 ? { properties } : {}),
      };
    });
  const fallbackAnnotations = buildIncidentAnnotations(
    report.incidents,
    fallbackSubjectsByIncident,
    report.timestamp,
    "6.0.7",
  );

  const sbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: report.timestamp,
      tools: {
        components: [
          { type: "application", name: "supply-chain-guard", version: "6.0.7" },
        ],
      },
      component: {
        type: "application" as const,
        name: report.target,
        "bom-ref": "target",
      },
      properties: [
        ...provenanceProperties,
        ...(report.partialScan ? [partialScanProperty] : []),
        ...policyEffectProperties,
      ],
    },
    components: [] as unknown[],
    vulnerabilities: fallbackVulnerabilities,
    ...(fallbackAnnotations.length > 0 ? { annotations: fallbackAnnotations } : {}),
  };

  return JSON.stringify(sbom, null, 2);
}

/**
 * Format as Shields.io endpoint JSON (https://shields.io/badges/endpoint-badge).
 *
 * The badge derives from the FINDINGS SUMMARY, not from the score-based
 * riskLevel: a single critical finding scores ~25 points ("medium" risk
 * level), which would render a yellow badge while the CLI exit code is 2 -
 * a security badge must never look calmer than the gate it represents
 * (verification-gate finding MF-2, v5.5 series). Mapping mirrors the exit-code
 * semantics: critical = red, high = orange, medium = yellow, else green.
 */
function formatBadge(report: ScanReport): string {
  const s = report.summary;
  let message: string;
  let color: string;
  if (!s) {
    // Defensive: reports parsed from external JSON may lack a summary.
    message = "unknown";
    color = "lightgrey";
  } else if (s.critical > 0) {
    message = `${s.critical} critical`;
    color = "red";
  } else if (s.high > 0) {
    message = `${s.high} high`;
    color = "orange";
  } else if (report.partialScan) {
    message = "partial";
    color = "orange";
  } else if (s.medium > 0) {
    message = `${s.medium} medium`;
    color = "yellow";
  } else if (s.low > 0) {
    message = `${s.low} low`;
    color = "brightgreen";
  } else {
    message = "clean";
    color = "brightgreen";
  }
  // v5.29 (issue 168): the badge is the most compressed reading of a report,
  // and "clean" on a scan whose config removed a rule is the single most
  // misleading string this tool can publish. The suffix is additive, so it
  // qualifies a critical count exactly as it qualifies a clean one, and it can
  // never make the badge look calmer than the gate it represents.
  if (report.policyEffect) {
    message = `${message} (policy-narrowed)`;
  }
  return JSON.stringify({
    schemaVersion: 1,
    label: "supply-chain-guard",
    message,
    color,
    tool: report.tool || "supply-chain-guard v6.0.7",
    version: report.tool ? (report.tool.includes("@") ? report.tool.split("@")[1] : report.tool.replace(/^supply-chain-guard v?/, "")) : "6.0.7",
    timestamp: report.timestamp,
    commit: report.commit ?? "none",
    detectionSet: report.detectionSet,
  });
}

/**
 * Map internal severity to the GitLab security report severity enum
 * (Info | Unknown | Low | Medium | High | Critical).
 */
function gitlabSeverity(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "Critical";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    case "info":
    default:
      return "Info";
  }
}

/**
 * Format a timestamp for GitLab security reports. The schema requires the
 * pattern ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$ - ISO 8601 WITHOUT
 * milliseconds and without the trailing "Z".
 */
function gitlabTime(epochMs: number): string {
  const d = Number.isFinite(epochMs) ? new Date(epochMs) : new Date();
  return d.toISOString().slice(0, 19);
}

/**
 * Format as a GitLab Dependency Scanning report
 * (gl-dependency-scanning-report.json).
 *
 * Targets security-report-schemas v15.2.4, the current 15.x line that
 * GitLab validates dependency_scanning artifacts against (see
 * gitlab-org/security-products/security-report-schemas, dist/
 * dependency-scanning-report-format.json). Required top-level fields:
 * version, vulnerabilities[], scan{analyzer, scanner, start_time,
 * end_time, status, type}. Exposed to the GitLab security UI via
 * artifacts:reports:dependency_scanning (see examples/gitlab-ci.yml).
 *
 * Suppressed findings are excluded, mirroring SARIF/SBOM (v5.2.40 rule:
 * policy/baseline suppressions must never leak into machine output).
 */
function formatGitlab(report: ScanReport): string {
  const startMs = Date.parse(report.timestamp);
  const scannerBlock = {
    id: "supply_chain_guard",
    name: "supply-chain-guard",
    url: "https://github.com/homeofe/supply-chain-guard",
    vendor: { name: "supply-chain-guard" },
    version: "6.0.7",
  };

  const vulnerabilities = report.findings
    .filter((f) => !f.suppressed)
    .map((finding, idx) => ({
      // id must be unique per vulnerability; findings can share a rule.
      id: `${finding.rule}-${idx}`,
      // The v15.2.4 schema caps name at 255 chars; GitLab discards the ENTIRE
      // report on validation failure, so an over-long name would hide all
      // findings exactly when they exist (v5.6 gate finding M4). Full text
      // stays in description.
      name: finding.description.length > 255
        ? finding.description.slice(0, 252) + "..."
        : finding.description,
      description: finding.description,
      severity: gitlabSeverity(finding.severity),
      solution: finding.recommendation,
      identifiers: [
        {
          type: "supply_chain_guard_rule",
          name: finding.rule,
          value: finding.rule,
        },
      ],
      location: {
        // location.file and location.dependency are required by the schema;
        // findings without a file anchor fall back to the scanned manifest.
        file: finding.file ?? "package.json",
        dependency: {
          // Use the per-finding file, not report.target: the scan target can
          // be an absolute runner path (e.g. /home/runner/work/...), and
          // leaking it into a shared GitLab report is needless disclosure
          // (v5.6.1). The file is the meaningful, stable coordinate here.
          package: { name: finding.file ?? "package.json" },
          version: "unknown",
        },
      },
    }));

  const gitlab = {
    version: "15.2.4",
    scan: {
      analyzer: scannerBlock,
      scanner: scannerBlock,
      type: "dependency_scanning" as const,
      start_time: gitlabTime(startMs),
      end_time: gitlabTime(startMs + (report.durationMs ?? 0)),
      status: report.partialScan ? ("failure" as const) : ("success" as const),
      // scan.messages is the schema's own slot for analyzer-level notices
      // (security-report-schemas v15.2.4: items require {level, value}, level in
      // info|warn|fatal). A custom key would also validate, since the scan object
      // does not set additionalProperties:false, but only this one is rendered by
      // the GitLab security UI, and rendering is the entire point here.
      //
      // (unreleased, issue 205): the coverage line is ALWAYS present, so a GitLab
      // report states its own denominator. Warn rather than info when the
      // denominator is zero: a report of nothing examined must not read calmer
      // than the gate it represents.
      messages: [
        {
          level: (report.summary?.filesScanned === 0 ? "warn" : "info") as "warn" | "info",
          value: coverageLine(report),
        },
        {
          level: "info" as const,
          value: `Commit: ${report.commit ?? "none (not a git repository)"}`,
        },
        ...(report.detectionSet
          ? [
              {
                level: "info" as const,
                value: `Detection set: v${report.detectionSet.bundledVersion} (${report.detectionSet.effectiveEntryCount} entries${report.detectionSet.cacheMerged ? ", merged cache" : ""})`,
              },
            ]
          : []),
        ...(report.policyEffect
          ? [{ level: "warn" as const, value: policyEffectLine(report.policyEffect) }]
          : []),
      ],
    },
    vulnerabilities,
  };

  return JSON.stringify(gitlab, null, 2);
}

/**
 * Escape a value for inclusion in XML text or a double-quoted attribute.
 */
function xmlEscape(value: unknown): string {
  return String(value)
    // Drop control chars that are illegal in XML 1.0 (except tab/LF/CR).
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * Format as a JUnit XML report (one <testsuite>, one <testcase> per finding).
 * high/critical findings become <failure> (type=severity, message=description);
 * everything else is a passing testcase. Suppressed findings are excluded,
 * mirroring the other machine formats (SARIF/SBOM/GitLab).
 *
 * Consumed by CI systems that render test reports (Jenkins JUnit plugin,
 * GitLab junit artifacts, GitHub test reporters).
 */
function formatJunit(report: ScanReport): string {
  const findings = report.findings.filter((f) => !f.suppressed);
  const isFailure = (s: Severity) => s === "critical" || s === "high";
  const failureCount = findings.filter((f) => isFailure(f.severity)).length;
  const errorCount = report.partialScan ? 1 : 0;
  const testCount = findings.length + errorCount;
  const timeSeconds = ((report.durationMs ?? 0) / 1000).toFixed(3);

  const lines: string[] = [];
  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push(
    `<testsuite name="supply-chain-guard" timestamp="${xmlEscape(report.timestamp)}" tests="${testCount}" failures="${failureCount}" errors="${errorCount}" time="${timeSeconds}">`,
  );

  // Run metadata belongs in <properties>, which every JUnit consumer renders
  // and which leaves the tests/failures/errors counts untouched (v5.29).
  //
  // (unreleased, issue 205): the coverage properties are ALWAYS emitted, so a JUnit
  // artefact states its own denominator instead of only what was found.
  lines.push("  <properties>");
  lines.push(
    `    <property name="supply-chain-guard:tool-version" value="${xmlEscape(report.tool || "supply-chain-guard v6.0.7")}"/>`,
  );
  lines.push(
    `    <property name="supply-chain-guard:timestamp" value="${xmlEscape(report.timestamp)}"/>`,
  );
  lines.push(
    `    <property name="supply-chain-guard:commit" value="${xmlEscape(report.commit ?? "none (not a git repository)")}"/>`,
  );
  if (report.detectionSet) {
    lines.push(
      `    <property name="supply-chain-guard:detection-set:version" value="${xmlEscape(report.detectionSet.bundledVersion)}"/>`,
    );
    lines.push(
      `    <property name="supply-chain-guard:detection-set:entry-count" value="${xmlEscape(String(report.detectionSet.effectiveEntryCount))}"/>`,
    );
    if (report.detectionSet.generatedAt) {
      lines.push(
        `    <property name="supply-chain-guard:detection-set:generated-at" value="${xmlEscape(report.detectionSet.generatedAt)}"/>`,
      );
    }
    lines.push(
      `    <property name="supply-chain-guard:detection-set:cache-merged" value="${xmlEscape(String(report.detectionSet.cacheMerged))}"/>`,
    );
  }
  const coverage = coverageProperties(report);
  lines.push(
    `    <property name="supply-chain-guard:files-scanned" value="${xmlEscape(coverage.filesScanned ?? "not-recorded")}"/>`,
  );
  lines.push(
    `    <property name="supply-chain-guard:total-files" value="${xmlEscape(coverage.totalFiles ?? "not-recorded")}"/>`,
  );
  lines.push(
    `    <property name="supply-chain-guard:coverage" value="${xmlEscape(coverageLine(report))}"/>`,
  );
  if (report.slsaAssessment) {
    lines.push(
      `    <property name="supply-chain-guard:slsa-level" value="${xmlEscape(report.slsaAssessment.level)}"/>`,
    );
    lines.push(
      `    <property name="supply-chain-guard:slsa-basis" value="${xmlEscape(report.slsaAssessment.basis.join("; "))}"/>`,
    );
    lines.push(
      `    <property name="supply-chain-guard:slsa-not-assessed" value="${xmlEscape(report.slsaAssessment.notAssessed.join("; "))}"/>`,
    );
  }
  if (report.policyEffect) {
    lines.push(
      `    <property name="supply-chain-guard:policy-config" value="${xmlEscape(report.policyEffect.configFile)}"/>`,
    );
    lines.push(
      `    <property name="supply-chain-guard:policy-effect" value="${xmlEscape(policyEffectLine(report.policyEffect))}"/>`,
    );
  }
  lines.push("  </properties>");

  if (report.partialScan) {
    lines.push('  <testcase name="SCAN_INCOMPLETE" classname="supply-chain-guard">');
    lines.push(
      `    <error type="partial-scan" message="Scan incomplete">${xmlEscape(PARTIAL_SCAN_WARNING)}</error>`,
    );
    lines.push("  </testcase>");
  }

  for (const f of findings) {
    const loc = f.file ? (f.line ? `${f.file}:${f.line}` : f.file) : report.target;
    const name = xmlEscape(`${f.rule} (${loc})`);
    const classname = xmlEscape(f.file ?? report.target);
    if (isFailure(f.severity)) {
      const body = xmlEscape(`${f.description}\n${f.recommendation}`);
      lines.push(`  <testcase name="${name}" classname="${classname}">`);
      lines.push(
        `    <failure type="${xmlEscape(f.severity)}" message="${xmlEscape(f.description)}">${body}</failure>`,
      );
      lines.push(`  </testcase>`);
    } else {
      lines.push(`  <testcase name="${name}" classname="${classname}"/>`);
    }
  }

  lines.push(`</testsuite>`);
  return lines.join("\n");
}

/**
 * Format as standalone HTML report.
 */
function formatHtml(report: ScanReport): string {
  const severityColors: Record<Severity, string> = {
    critical: "#dc2626",
    high: "#ea580c",
    medium: "#ca8a04",
    low: "#2563eb",
    info: "#6b7280",
  };

  const severityBg: Record<Severity, string> = {
    critical: "#fef2f2",
    high: "#fff7ed",
    medium: "#fefce8",
    low: "#eff6ff",
    info: "#f9fafb",
  };

  const scoreColor =
    report.partialScan ? "#d97706"
    : report.score === 0 ? "#22c55e"
    : report.score <= 10 ? "#06b6d4"
    : report.score <= 30 ? "#ca8a04"
    : report.score <= 60 ? "#dc2626"
    : "#991b1b";

  const sorted = [...report.findings].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity),
  );

  const findingsHtml = sorted
    .map(
      (f, i) => `
    <tr class="finding" data-severity="${f.severity}">
      <td><span class="badge" style="background:${severityColors[f.severity]}">${f.severity.toUpperCase()}</span></td>
      <td>${escapeHtml(f.rule)}</td>
      <td>${escapeHtml(f.description)}</td>
      <td>${f.file ? escapeHtml(f.file) + (f.line ? `:${f.line}` : "") : "-"}</td>
      <td class="match">${f.match ? escapeHtml(f.match) : "-"}</td>
    </tr>`,
    )
    .join("\n");

  const recsHtml = report.recommendations
    .map((r) => `<li>${escapeHtml(r)}</li>`)
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>supply-chain-guard Report - ${escapeHtml(report.target)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;color:#1e293b;line-height:1.6}
.container{max-width:1200px;margin:0 auto;padding:24px}
header{background:linear-gradient(135deg,#1e293b,#334155);color:#fff;padding:32px;border-radius:12px;margin-bottom:24px}
header h1{font-size:24px;margin-bottom:8px}
header .meta{display:flex;gap:24px;flex-wrap:wrap;font-size:14px;opacity:0.85}
.score-card{display:flex;align-items:center;gap:24px;background:#fff;padding:24px;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.1);margin-bottom:24px}
.score-num{font-size:48px;font-weight:800;color:${scoreColor}}
.score-label{font-size:14px;color:#64748b}
.score-level{font-size:20px;font-weight:600;text-transform:uppercase;color:${scoreColor}}
.partial-warning{background:#fffbeb;border:1px solid #f59e0b;color:#92400e;padding:16px 20px;border-radius:10px;margin-bottom:24px}
.policy-warning{background:#fffbeb;border:1px solid #f59e0b;color:#92400e;padding:16px 20px;border-radius:10px;margin-bottom:24px}
.policy-warning ul{margin:8px 0 0 20px}
.summary{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.summary .chip{padding:8px 16px;border-radius:8px;font-weight:600;font-size:14px}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.1);padding:24px;margin-bottom:24px}
.card h2{font-size:18px;margin-bottom:16px;color:#1e293b}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;padding:12px 8px;border-bottom:2px solid #e2e8f0;color:#64748b;font-weight:600}
td{padding:10px 8px;border-bottom:1px solid #f1f5f9;vertical-align:top}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;color:#fff;font-size:12px;font-weight:700}
.match{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace;font-size:12px;color:#64748b}
.filter-bar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.filter-btn{padding:6px 14px;border-radius:6px;border:1px solid #e2e8f0;background:#fff;cursor:pointer;font-size:13px;transition:all 0.2s}
.filter-btn:hover,.filter-btn.active{background:#1e293b;color:#fff;border-color:#1e293b}
ul{padding-left:20px}
li{margin-bottom:8px}
footer{text-align:center;padding:24px;color:#94a3b8;font-size:13px}
@media(max-width:768px){.score-card{flex-direction:column;text-align:center}.meta{flex-direction:column;gap:4px}}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>${escapeHtml(report.tool || "supply-chain-guard v6.0.7")} Scan Report</h1>
    <div class="meta">
      <span>Target: ${escapeHtml(report.target)}</span>
      <span>Type: ${report.scanType}</span>
      <span>Time: ${report.timestamp}</span>
      <span>Commit: ${escapeHtml(report.commit ?? "none (not a git repository)")}</span>
      ${report.detectionSet ? `<span>Detection Set: v${escapeHtml(report.detectionSet.bundledVersion)} (${report.detectionSet.effectiveEntryCount} entries${report.detectionSet.cacheMerged ? ", merged cache" : ""}${report.detectionSet.generatedAt ? `, generated ${escapeHtml(report.detectionSet.generatedAt)}` : ""})</span>` : ""}
      <span>Duration: ${report.durationMs}ms</span>
    </div>
  </header>

  ${report.partialScan ? `<div class="partial-warning"><strong>Scan incomplete.</strong> Coverage gaps prevented a complete verdict. Resolve skipped or unreadable files before treating this result as clean.</div>` : ""}
  ${report.policyEffect ? `<div class="policy-warning"><strong>Policy in effect.</strong> ${escapeHtml(POLICY_EFFECT_HEADLINE)} Loaded from <code>${escapeHtml(report.policyEffect.configFile)}</code>.${policyEffectGroups(report.policyEffect).map((group) => `<ul><li>${escapeHtml(group.label)}: ${group.entries.map((entry) => escapeHtml(policyEntryText(entry))).join(", ")}</li></ul>`).join("")}</div>` : ""}

  <div class="score-card">
    <div>
      <div class="score-num">${report.score}</div>
      <div class="score-label">/ 100 Risk Score</div>
    </div>
    <div>
      <div class="score-level">${report.partialScan ? "partial" : report.riskLevel}</div>
      <div class="score-label">${report.summary.filesScanned} files scanned of ${report.summary.totalFiles} total</div>
    </div>
  </div>

  <div class="summary">
    ${report.summary.critical > 0 ? `<span class="chip" style="background:${severityBg.critical};color:${severityColors.critical}">${SEVERITY_ICONS.critical} ${report.summary.critical} Critical</span>` : ""}
    ${report.summary.high > 0 ? `<span class="chip" style="background:${severityBg.high};color:${severityColors.high}">${SEVERITY_ICONS.high} ${report.summary.high} High</span>` : ""}
    ${report.summary.medium > 0 ? `<span class="chip" style="background:${severityBg.medium};color:${severityColors.medium}">${SEVERITY_ICONS.medium} ${report.summary.medium} Medium</span>` : ""}
    ${report.summary.low > 0 ? `<span class="chip" style="background:${severityBg.low};color:${severityColors.low}">${SEVERITY_ICONS.low} ${report.summary.low} Low</span>` : ""}
    ${report.summary.info > 0 ? `<span class="chip" style="background:${severityBg.info};color:${severityColors.info}">${SEVERITY_ICONS.info} ${report.summary.info} Info</span>` : ""}
    ${report.partialScan ? '<span class="chip" style="background:#fffbeb;color:#d97706">Partial scan</span>' : ""}
    ${report.findings.length === 0 && !report.partialScan ? '<span class="chip" style="background:#f0fdf4;color:#22c55e">No findings</span>' : ""}
  </div>

  ${report.findings.length > 0 ? `
  <div class="card">
    <h2>Findings (${report.findings.length})</h2>
    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterFindings('all')">All</button>
      <button class="filter-btn" onclick="filterFindings('critical')">Critical</button>
      <button class="filter-btn" onclick="filterFindings('high')">High</button>
      <button class="filter-btn" onclick="filterFindings('medium')">Medium</button>
      <button class="filter-btn" onclick="filterFindings('low')">Low</button>
      <button class="filter-btn" onclick="filterFindings('info')">Info</button>
    </div>
    <table>
      <thead><tr><th>Severity</th><th>Rule</th><th>Description</th><th>File</th><th>Match</th></tr></thead>
      <tbody>${findingsHtml}</tbody>
    </table>
  </div>
  ` : ""}

  ${report.recommendations.length > 0 ? `
  <div class="card">
    <h2>Recommendations</h2>
    <ul>${recsHtml}</ul>
  </div>
  ` : ""}

  <footer>
    Generated by <a href="https://github.com/homeofe/supply-chain-guard">${escapeHtml(report.tool || "supply-chain-guard v6.0.7")}</a>
  </footer>
</div>
<script>
function filterFindings(severity){
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding').forEach(row=>{
    row.style.display=severity==='all'||row.dataset.severity===severity?'':'none';
  });
}
</script>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
