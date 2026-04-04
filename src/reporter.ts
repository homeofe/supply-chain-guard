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
 * Format as human-readable text with colors.
 */
function formatText(report: ScanReport): string {
  const lines: string[] = [];

  // Header
  lines.push("");
  lines.push(`${BOLD}  supply-chain-guard${RESET} scan report`);
  lines.push(`${DIM}  ${"─".repeat(50)}${RESET}`);
  lines.push(`  Target:    ${report.target}`);
  lines.push(`  Type:      ${report.scanType}`);
  lines.push(`  Time:      ${report.timestamp}`);
  lines.push(`  Duration:  ${report.durationMs}ms`);
  lines.push("");

  // Score
  const scoreColor =
    report.score === 0
      ? "\x1b[32m"
      : report.score <= 10
        ? "\x1b[36m"
        : report.score <= 30
          ? "\x1b[33m"
          : report.score <= 60
            ? "\x1b[31m"
            : "\x1b[91m";

  lines.push(
    `  Risk Score: ${scoreColor}${BOLD}${report.score}/100${RESET} (${report.riskLevel.toUpperCase()})`,
  );
  lines.push("");

  // Summary
  lines.push(`${BOLD}  Summary${RESET}`);
  lines.push(`${DIM}  ${"─".repeat(50)}${RESET}`);

  if (report.scanType === "directory" || report.scanType === "github") {
    lines.push(`  Files:     ${report.summary.filesScanned}/${report.summary.totalFiles} scanned`);
  }

  const counts = [
    report.summary.critical > 0
      ? `${SEVERITY_COLORS.critical}${report.summary.critical} critical${RESET}`
      : null,
    report.summary.high > 0
      ? `${SEVERITY_COLORS.high}${report.summary.high} high${RESET}`
      : null,
    report.summary.medium > 0
      ? `${SEVERITY_COLORS.medium}${report.summary.medium} medium${RESET}`
      : null,
    report.summary.low > 0
      ? `${SEVERITY_COLORS.low}${report.summary.low} low${RESET}`
      : null,
    report.summary.info > 0
      ? `${SEVERITY_COLORS.info}${report.summary.info} info${RESET}`
      : null,
  ].filter(Boolean);

  if (counts.length > 0) {
    lines.push(`  Findings:  ${counts.join(", ")}`);
  } else {
    lines.push(`  Findings:  \x1b[32mNone${RESET}`);
  }
  lines.push("");

  // Findings
  if (report.findings.length > 0) {
    lines.push(`${BOLD}  Findings${RESET}`);
    lines.push(`${DIM}  ${"─".repeat(50)}${RESET}`);

    // Sort by severity (critical first)
    const sorted = [...report.findings].sort(
      (a, b) => severityRank(b.severity) - severityRank(a.severity),
    );

    for (const finding of sorted) {
      lines.push("");
      lines.push(
        `  ${SEVERITY_ICONS[finding.severity]} ${SEVERITY_COLORS[finding.severity]}${BOLD}[${finding.severity.toUpperCase()}]${RESET} ${finding.description}`,
      );
      lines.push(`     Rule: ${finding.rule}`);
      if (finding.file) {
        const location = finding.line
          ? `${finding.file}:${finding.line}`
          : finding.file;
        lines.push(`     File: ${location}`);
      }
      if (finding.match) {
        lines.push(`     Match: ${DIM}${finding.match}${RESET}`);
      }
      lines.push(`     Fix: ${finding.recommendation}`);
    }
    lines.push("");
  }

  // Trust Breakdown (v4.2)
  if (report.trustBreakdown) {
    const tb = report.trustBreakdown;
    lines.push(`${BOLD}  Trust Breakdown${RESET}`);
    lines.push(`${DIM}  ${"─".repeat(50)}${RESET}`);
    const bar = (score: number) => {
      const filled = Math.round(score / 10);
      return "\u2588".repeat(filled) + "\u2591".repeat(10 - filled);
    };
    const color = (score: number) => score >= 80 ? "\x1b[32m" : score >= 50 ? "\x1b[33m" : "\x1b[31m";
    lines.push(`  Publisher:   ${color(tb.publisherTrust.score)}${bar(tb.publisherTrust.score)} ${tb.publisherTrust.score}/100${RESET}`);
    lines.push(`  Code:        ${color(tb.codeQuality.score)}${bar(tb.codeQuality.score)} ${tb.codeQuality.score}/100${RESET}`);
    lines.push(`  Deps:        ${color(tb.dependencyTrust.score)}${bar(tb.dependencyTrust.score)} ${tb.dependencyTrust.score}/100${RESET}`);
    lines.push(`  Release:     ${color(tb.releaseProcess.score)}${bar(tb.releaseProcess.score)} ${tb.releaseProcess.score}/100${RESET}`);
    lines.push(`  ${BOLD}Overall:     ${color(tb.overallScore)}${bar(tb.overallScore)} ${tb.overallScore}/100${RESET}`);
    lines.push("");
  }

  // Correlated Incidents (v4.2)
  if (report.incidents && report.incidents.length > 0) {
    lines.push(`${BOLD}  Correlated Incidents${RESET}`);
    lines.push(`${DIM}  ${"─".repeat(50)}${RESET}`);
    for (const incident of report.incidents) {
      const conf = Math.round(incident.confidence * 100);
      lines.push("");
      lines.push(`  ${SEVERITY_COLORS[incident.severity]}${BOLD}[${incident.severity.toUpperCase()}]${RESET} ${incident.name} (${conf}% confidence)`);
      lines.push(`  ${DIM}${incident.narrative}${RESET}`);
      lines.push(`  Indicators: ${incident.indicators.join(", ")}`);
    }
    lines.push("");
  }

  // Recommendations
  if (report.recommendations.length > 0) {
    lines.push(`${BOLD}  Recommendations${RESET}`);
    lines.push(`${DIM}  ${"─".repeat(50)}${RESET}`);
    for (const rec of report.recommendations) {
      lines.push(`  • ${rec}`);
    }
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
            version: "4.3.0",
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
 * Format as CycloneDX 1.5 JSON SBOM.
 */
function formatSbom(report: ScanReport): string {
  const sbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: report.timestamp,
      tools: {
        components: [
          {
            type: "application",
            name: "supply-chain-guard",
            version: "4.3.0",
          },
        ],
      },
      component: {
        type: "application" as const,
        name: report.target,
        "bom-ref": "target",
      },
    },
    components: [
      {
        type: "application",
        "bom-ref": "target",
        name: report.target,
      },
    ],
    vulnerabilities: report.findings.map((finding, idx) => ({
      "bom-ref": `vuln-${idx}`,
      id: finding.rule,
      source: { name: "supply-chain-guard" },
      ratings: [
        {
          severity: finding.severity,
          method: "other",
        },
      ],
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
    Generated by <a href="https://github.com/homeofe/supply-chain-guard">supply-chain-guard</a> v4.3.0
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
