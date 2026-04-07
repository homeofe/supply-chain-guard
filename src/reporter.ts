/**
 * Output formatting for scan reports.
 * Supports text, JSON, markdown, and SARIF 2.1.0 output.
 */

import { randomUUID } from "node:crypto";
import type { Finding, ScanReport, Severity } from "./types.js";

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
  format: "text" | "json" | "markdown" | "sarif" | "sbom" | "html",
): string {
  switch (format) {
    case "json":
      return formatJson(report);
    case "markdown":
      return formatMarkdown(report);
    case "sarif":
      return formatSarif(report);
    case "sbom":
      return formatSbom(report);
    case "html":
      return formatHtml(report);
    case "text":
    default:
      return formatText(report);
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
  const VERSION = "5.1.1";
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
  lines.push("");

  // ── RISK SCORE ─────────────────────────────────────────────────────────────
  {
    const sc    = report.score;
    const scCol = scoreColor(sc);
    const level = report.riskLevel.toUpperCase();
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
    }
    if (report.sbomDocument) {
      lines.push(boxRow(`  ${DIM}SBOM${RESET}        CycloneDX 1.6  ·  ${report.sbomDocument.components.length} components`));
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

    if (totalFindings === 0) {
      lines.push(boxBlank());
      lines.push(boxRow(`  \x1b[32m${BOLD}✓  No findings — clean${RESET}`));
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
      lines.push(boxRow(`  ${indent}${trunc(f.description, avail)}`));
      if (f.file) {
        const loc = f.line ? `${f.file}:${f.line}` : f.file;
        lines.push(boxRow(`  ${indent}${DIM}${trunc(loc, avail)}${RESET}`));
      }
      if (f.match) {
        const matchTag = "match  ";
        lines.push(boxRow(`  ${indent}${DIM}${matchTag}${RESET}${trunc(f.match, avail - matchTag.length)}`));
      }
      const fixTag = "fix    ";
      lines.push(boxRow(`  ${indent}${DIM}${fixTag}${RESET}${trunc(f.recommendation, avail - fixTag.length)}`));

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
    const tbRow = (label: string, score: number) => {
      const col = trustColor(score);
      return boxRow(`  ${label.padEnd(14)}${col}${mkBar(score, 100, BAR_W)}${RESET}  ${col}${score}/100${RESET}`);
    };

    lines.push(boxTop("TRUST BREAKDOWN"));
    lines.push(tbRow("Publisher",    tb.publisherTrust.score));
    lines.push(tbRow("Code",         tb.codeQuality.score));
    lines.push(tbRow("Dependencies", tb.dependencyTrust.score));
    lines.push(tbRow("Release",      tb.releaseProcess.score));
    lines.push(boxDiv());
    lines.push(tbRow("Overall",      tb.overallScore));
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
      lines.push(boxRow(`  ${color}${BOLD}${label}${RESET}  ${BOLD}${trunc(incident.name, W - label.length - 20)}${RESET}  ${DIM}${conf}% confidence${RESET}`));
      lines.push(boxRow(`  ${DIM}${trunc(incident.narrative, W - 2)}${RESET}`));
      lines.push(boxRow(`  Indicators: ${DIM}${trunc(incident.indicators.join(", "), W - 14)}${RESET}`));
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
function formatMarkdown(report: ScanReport): string {
  const lines: string[] = [];

  // Header
  lines.push("## 🛡️ supply-chain-guard Scan Report");
  lines.push("");
  lines.push(`| Property | Value |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Target | \`${report.target}\` |`);
  lines.push(`| Type | ${report.scanType} |`);
  lines.push(`| Time | ${report.timestamp} |`);
  lines.push(`| Duration | ${report.durationMs}ms |`);
  lines.push(
    `| **Risk Score** | **${report.score}/100** (${report.riskLevel.toUpperCase()}) |`,
  );
  lines.push("");

  // Summary
  lines.push("### Summary");
  lines.push("");

  if (report.scanType === "directory" || report.scanType === "github") {
    lines.push(
      `Scanned ${report.summary.filesScanned} of ${report.summary.totalFiles} files.`,
    );
    lines.push("");
  }

  if (report.findings.length === 0) {
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
        `#### ${SEVERITY_ICONS[finding.severity]} [${finding.severity.toUpperCase()}] ${finding.description}`,
      );
      lines.push("");
      lines.push(`- **Rule:** \`${finding.rule}\``);
      if (finding.file) {
        const location = finding.line
          ? `${finding.file}:${finding.line}`
          : finding.file;
        lines.push(`- **File:** \`${location}\``);
      }
      if (finding.match) {
        lines.push(`- **Match:** \`${finding.match}\``);
      }
      lines.push(`- **Recommendation:** ${finding.recommendation}`);
      lines.push("");
    }
  }

  // Recommendations
  if (report.recommendations.length > 0) {
    lines.push("### Recommendations");
    lines.push("");
    for (const rec of report.recommendations) {
      lines.push(`- ${rec}`);
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

  for (const finding of report.findings) {
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

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0" as const,
    runs: [
      {
        tool: {
          driver: {
            name: "supply-chain-guard",
            version: "5.1.1",
            informationUri: "https://github.com/homeofe/supply-chain-guard",
            rules,
          },
        },
        results,
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
 * Format as CycloneDX 1.6 JSON SBOM.
 * Uses the sbomDocument generated from actual package.json/lockfile if available,
 * otherwise falls back to a findings-based SBOM.
 */
function formatSbom(report: ScanReport): string {
  // v4.9: use the proper CycloneDX 1.6 document if available
  if (report.sbomDocument) {
    // Attach scan findings as vulnerabilities to the real SBOM
    const withVulns = {
      ...report.sbomDocument,
      vulnerabilities: [
        ...(report.sbomDocument.vulnerabilities ?? []),
        ...report.findings
          .filter((f) => !f.suppressed)
          .map((finding, idx) => ({
            "bom-ref": `scg-finding-${idx}`,
            id: finding.rule,
            source: { name: "supply-chain-guard" },
            ratings: [{ severity: finding.severity, method: "other" }],
            description: finding.description,
            recommendation: finding.recommendation,
            affects: finding.file ? [{ ref: finding.file }] : [{ ref: "target" }],
          })),
      ],
    };
    return JSON.stringify(withVulns, null, 2);
  }

  // Fallback: findings-based SBOM (legacy, no lockfile present)
  const sbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: report.timestamp,
      tools: {
        components: [
          { type: "application", name: "supply-chain-guard", version: "5.1.0" },
        ],
      },
      component: {
        type: "application" as const,
        name: report.target,
        "bom-ref": "target",
      },
    },
    components: [] as unknown[],
    vulnerabilities: report.findings.map((finding, idx) => ({
      "bom-ref": `vuln-${idx}`,
      id: finding.rule,
      source: { name: "supply-chain-guard" },
      ratings: [{ severity: finding.severity, method: "other" }],
      description: finding.description,
      recommendation: finding.recommendation,
      affects: [{ ref: "target" }],
    })),
  };

  return JSON.stringify(sbom, null, 2);
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
    report.score === 0 ? "#22c55e"
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
    <h1>supply-chain-guard Scan Report</h1>
    <div class="meta">
      <span>Target: ${escapeHtml(report.target)}</span>
      <span>Type: ${report.scanType}</span>
      <span>Time: ${report.timestamp}</span>
      <span>Duration: ${report.durationMs}ms</span>
    </div>
  </header>

  <div class="score-card">
    <div>
      <div class="score-num">${report.score}</div>
      <div class="score-label">/ 100 Risk Score</div>
    </div>
    <div>
      <div class="score-level">${report.riskLevel}</div>
      <div class="score-label">${report.summary.filesScanned} files scanned of ${report.summary.totalFiles} total</div>
    </div>
  </div>

  <div class="summary">
    ${report.summary.critical > 0 ? `<span class="chip" style="background:${severityBg.critical};color:${severityColors.critical}">${SEVERITY_ICONS.critical} ${report.summary.critical} Critical</span>` : ""}
    ${report.summary.high > 0 ? `<span class="chip" style="background:${severityBg.high};color:${severityColors.high}">${SEVERITY_ICONS.high} ${report.summary.high} High</span>` : ""}
    ${report.summary.medium > 0 ? `<span class="chip" style="background:${severityBg.medium};color:${severityColors.medium}">${SEVERITY_ICONS.medium} ${report.summary.medium} Medium</span>` : ""}
    ${report.summary.low > 0 ? `<span class="chip" style="background:${severityBg.low};color:${severityColors.low}">${SEVERITY_ICONS.low} ${report.summary.low} Low</span>` : ""}
    ${report.summary.info > 0 ? `<span class="chip" style="background:${severityBg.info};color:${severityColors.info}">${SEVERITY_ICONS.info} ${report.summary.info} Info</span>` : ""}
    ${report.findings.length === 0 ? '<span class="chip" style="background:#f0fdf4;color:#22c55e">No findings</span>' : ""}
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
    Generated by <a href="https://github.com/homeofe/supply-chain-guard">supply-chain-guard</a> v5.1.1
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
