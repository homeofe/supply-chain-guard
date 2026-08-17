#!/usr/bin/env node

/**
 * supply-chain-guard CLI
 *
 * Scan code repositories, npm packages, PyPI packages, VS Code extensions,
 * and project dependencies for supply-chain malware indicators.
 */

import { Command } from "commander";
import * as fs from "node:fs";
import { globalAgent as httpGlobalAgent } from "node:http";
import { globalAgent as httpsGlobalAgent } from "node:https";
import * as path from "node:path";
import { scan } from "./scanner.js";
import { scanNpmPackage } from "./npm-scanner.js";
import { scanPypiPackage } from "./pypi-scanner.js";
import { scanVscodeExtension } from "./vscode-scanner.js";
import { scanDependencyConfusion } from "./dependency-confusion.js";
import { analyzeGitHubTrust, parseGitHubUrl, scanReadmeLures } from "./github-trust-scanner.js";
import {
  monitorWallet,
  formatAlert,
  checkWallet,
  addToWatchlist,
  removeFromWatchlist,
  listWatchlist,
  monitorWatchlist,
} from "./solana-monitor.js";
import { formatReport, getFindingsExitCode, getReportExitCode } from "./reporter.js";
import type { ScanOptions, Severity } from "./types.js";

const program = new Command();

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function parseSeverityOption(
  value: string | undefined,
  flag: "--min-severity" | "--fail-on",
): Severity | undefined {
  if (value === undefined) return undefined;
  if (!Object.hasOwn(SEVERITY_RANK, value)) {
    throw new Error(
      `${flag} must be one of: critical, high, medium, low, info (received "${value}").`,
    );
  }
  return value as Severity;
}

function assertCompatibleSeverityThresholds(
  minSeverity: Severity | undefined,
  failOn: Severity | undefined,
): void {
  if (minSeverity === undefined) return;
  const effectiveFailOn = failOn ?? "high";
  if (SEVERITY_RANK[minSeverity] <= SEVERITY_RANK[effectiveFailOn]) return;

  const gate = failOn === undefined
    ? "the default high gate"
    : `--fail-on ${failOn}`;
  throw new Error(
    `--min-severity ${minSeverity} would hide findings required by ${gate}. ` +
      "Choose a minimum severity at or below the fail threshold.",
  );
}

function parseDefaultGatedMinSeverity(value: string | undefined): Severity | undefined {
  const minSeverity = parseSeverityOption(value, "--min-severity");
  assertCompatibleSeverityThresholds(minSeverity, undefined);
  return minSeverity;
}

function finishCliCommand(exitCode: number): void {
  // Forced process.exit() can truncate a report buffered to a pipe. Close the
  // scanners' pooled network sockets, set the eventual status, and let Node
  // drain stdout/stderr naturally.
  httpGlobalAgent.destroy();
  httpsGlobalAgent.destroy();
  process.exitCode = exitCode;
}

interface OutputPathOption {
  flag: string;
  value?: string;
}

function isMissingPathError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException).code;
  return code === "ENOENT" || code === "ENOTDIR";
}

function comparablePathKey(value: string): string {
  // Default Windows and macOS filesystems are case-insensitive. Conservatively
  // reject case-only writer aliases on Darwin as well; on a case-sensitive APFS
  // volume this can reject two distinct names, but can never permit overwrite.
  return process.platform === "win32" || process.platform === "darwin"
    ? value.toLowerCase()
    : value;
}

function canonicalizeMissingOutputPath(value: string): string {
  let cursor = value;
  const suffix: string[] = [];

  while (true) {
    try {
      const ancestor = fs.realpathSync.native(cursor);
      return path.resolve(ancestor, ...suffix.reverse());
    } catch (error) {
      if (!isMissingPathError(error)) throw error;
      const parent = path.dirname(cursor);
      if (parent === cursor) return path.resolve(value);
      suffix.push(path.basename(cursor));
      cursor = parent;
    }
  }
}

function canonicalOutputPath(value: string): { pathKey: string; inodeKey?: string } {
  let canonical = path.resolve(value);
  const seenSymlinks = new Set<string>();

  // realpath cannot resolve a dangling final symlink. Follow final-component
  // links explicitly so `target.json` and `alias.json -> target.json` collide
  // even before either writer creates the target.
  for (let depth = 0; depth <= 64; depth += 1) {
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(canonical);
    } catch (error) {
      if (!isMissingPathError(error)) throw error;
      canonical = canonicalizeMissingOutputPath(canonical);
      break;
    }

    if (!stat.isSymbolicLink()) {
      canonical = fs.realpathSync.native(canonical);
      break;
    }

    const symlinkKey = comparablePathKey(fs.realpathSync.native(path.dirname(canonical)) +
      path.sep + path.basename(canonical));
    if (seenSymlinks.has(symlinkKey) || depth === 64) {
      throw new Error("An output path contains a symbolic-link cycle.");
    }
    seenSymlinks.add(symlinkKey);

    const target = fs.readlinkSync(canonical);
    const physicalParent = fs.realpathSync.native(path.dirname(canonical));
    canonical = path.resolve(physicalParent, target);
  }

  const pathKey = comparablePathKey(canonical);
  try {
    const stat = fs.statSync(canonical, { bigint: true });
    return { pathKey, inodeKey: `${stat.dev}:${stat.ino}` };
  } catch (error) {
    if (!isMissingPathError(error)) throw error;
    return { pathKey };
  }
}

function assertDistinctOutputPaths(options: OutputPathOption[]): void {
  const seenPaths = new Map<string, string>();
  const seenInodes = new Map<string, string>();
  for (const option of options) {
    if (!option.value) continue;
    const { pathKey, inodeKey } = canonicalOutputPath(option.value);
    const previous = seenPaths.get(pathKey) ??
      (inodeKey === undefined ? undefined : seenInodes.get(inodeKey));
    if (previous !== undefined) {
      throw new Error(
        `${option.flag} must not target the same file as ${previous}.`,
      );
    }
    seenPaths.set(pathKey, option.flag);
    if (inodeKey !== undefined) seenInodes.set(inodeKey, option.flag);
  }
}

program
  .name("supply-chain-guard")
  .description(
    "Open-source supply-chain security scanner. Detects GlassWorm and similar malware campaigns in npm packages, PyPI packages, code repos, VS Code extensions, and project dependencies.",
  )
  .version("5.26.5");

// ── scan command ────────────────────────────────────────────────────

program
  .command("scan")
  .description("Scan a local directory or GitHub repo for malware indicators")
  .argument("<target>", "Local directory path or GitHub repo URL")
  .option("-f, --format <format>", "Output format: text, json, markdown, sarif, sbom, html, badge, gitlab, junit", "text")
  .option("-o, --output <file>", "Write the formatted report to a file instead of stdout")
  .option(
    "--json-output <file>",
    "Write a canonical JSON copy from the same scan (for CI format reconciliation)",
  )
  .option(
    "-s, --min-severity <severity>",
    "Minimum severity to report: critical, high, medium, low, info",
  )
  .option(
    "-e, --exclude <rules>",
    "Comma-separated list of rule IDs to exclude",
  )
  .option("-d, --depth <depth>", "Maximum directory depth", "20")
  .option(
    "--fail-on <severity>",
    "Exit non-zero only if findings at or above this severity: critical, high, medium, low, info",
  )
  .option("--baseline <file>", "Baseline file to diff against (only show new findings)")
  .option("--save-baseline <file>", "Save current findings as baseline for future diffs")
  .option("--since <commit>", "Only scan files changed since this commit (diff mode)")
  .option("--export-incident-md", "Export incident report as markdown to stdout")
  .option("--export-fixes", "Show fix suggestions for automatable findings")
  .option("--export-graph <format>", "Export attack graph (json or mermaid)")
  .option("--sbom-output <file>", "Write CycloneDX 1.6 SBOM to a separate file")
  .option("--no-history", "Do not write risk history to .scg-history/ in the scanned repo")
  .option("--check-registry", "Compare the local package.json version against the npm registry 'latest' dist-tag (requires network; off by default)")
  .action(
    async (
      target: string,
      opts: {
        format: string;
        output?: string;
        jsonOutput?: string;
        minSeverity?: string;
        exclude?: string;
        depth: string;
        failOn?: string;
        baseline?: string;
        saveBaseline?: string;
        since?: string;
        exportIncidentMd?: boolean;
        exportFixes?: boolean;
        exportGraph?: string;
        sbomOutput?: string;
        history: boolean;
        checkRegistry?: boolean;
      },
    ) => {
      try {
        const minSeverity = parseSeverityOption(opts.minSeverity, "--min-severity");
        const failOn = parseSeverityOption(opts.failOn, "--fail-on");
        assertCompatibleSeverityThresholds(minSeverity, failOn);
        assertDistinctOutputPaths([
          { flag: "--output", value: opts.output },
          { flag: "--json-output", value: opts.jsonOutput },
          { flag: "--save-baseline", value: opts.saveBaseline },
          { flag: "--sbom-output", value: opts.sbomOutput },
        ]);

        const options: ScanOptions = {
          target,
          format: opts.format as ScanOptions["format"],
          minSeverity,
          excludeRules: opts.exclude?.split(",").map((r) => r.trim()),
          maxDepth: parseInt(opts.depth, 10),
          baselineFile: opts.baseline,
          sinceCommit: opts.since,
          noHistory: opts.history === false,
          checkRegistry: opts.checkRegistry === true,
        };

        const report = await scan(options);

        // CI can request a canonical JSON copy from this exact in-memory report
        // while stdout uses another formatter. This avoids a second scan whose
        // network or filesystem state could produce a contradictory verdict.
        if (opts.jsonOutput) {
          const { writeFileSync } = await import("node:fs");
          writeFileSync(opts.jsonOutput, formatReport(report, "json"), "utf-8");
        }

        // Save baseline if requested
        if (opts.saveBaseline) {
          const { saveBaseline } = await import("./policy-engine.js");
          saveBaseline(report.findings, opts.saveBaseline);
          console.error(`Baseline saved to ${opts.saveBaseline} (${report.findings.length} findings)`);
        }

        // Export incident markdown if requested
        if (opts.exportIncidentMd) {
          const { exportIncidentMarkdown } = await import("./soc-exporter.js");
          console.log(exportIncidentMarkdown(report));
        } else {
          const formatted = formatReport(report, options.format);
          // --output writes the report to a file (mirrors --sbom-output); status
          // messages still go to stderr so the file stays pure report content.
          if (opts.output) {
            const { writeFileSync } = await import("node:fs");
            writeFileSync(opts.output, formatted, "utf-8");
            console.error(`Report written to ${opts.output} (${options.format})`);
          } else {
            console.log(formatted);
          }
        }

        // Export attack graph if requested
        if (opts.exportGraph && report.attackGraph) {
          if (opts.exportGraph === "mermaid") {
            const { exportGraphMermaid } = await import("./attack-graph.js");
            console.log(exportGraphMermaid(report.attackGraph));
          } else {
            console.log(JSON.stringify(report.attackGraph, null, 2));
          }
        }

        // Write SBOM to separate file if requested
        if (opts.sbomOutput && report.sbomDocument) {
          const { writeFileSync } = await import("node:fs");
          const sbomOutput = report.partialScan
            ? formatReport(report, "sbom")
            : JSON.stringify(report.sbomDocument, null, 2);
          writeFileSync(opts.sbomOutput, sbomOutput, "utf-8");
          console.error(`SBOM written to ${opts.sbomOutput} (CycloneDX 1.6, ${report.sbomDocument.components.length} components)`);
        }

        // Show fix suggestions if requested
        if (opts.exportFixes && report.fixSuggestions && report.fixSuggestions.length > 0) {
          console.error("\n  Fix Suggestions:");
          for (const fix of report.fixSuggestions) {
            console.error(`\n  File: ${fix.targetFile}`);
            if (fix.before) console.error(`  - ${fix.before}`);
            if (fix.after) console.error(`  + ${fix.after}`);
            console.error(`  ${fix.explanation}`);
          }
          console.error("");
        }

        // Preserve the report bytes even when the verdict is nonzero.
        finishCliCommand(getReportExitCode(report, failOn));
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n  Error: ${message}\n`);
        finishCliCommand(1);
      }
    },
  );

// ── npm command ─────────────────────────────────────────────────────

program
  .command("npm")
  .description("Scan an npm package for malware indicators (downloads without installing)")
  .argument("<package>", "npm package name (e.g., express, lodash)")
  .option("-f, --format <format>", "Output format: text, json, markdown, sarif", "text")
  .option(
    "-s, --min-severity <severity>",
    "Minimum severity to report",
  )
  .action(
    async (
      packageName: string,
      opts: { format: string; minSeverity?: string },
    ) => {
      try {
        const report = await scanNpmPackage(packageName, {
          target: packageName,
          format: opts.format as "text" | "json" | "markdown" | "sarif" | "sbom",
          minSeverity: parseDefaultGatedMinSeverity(opts.minSeverity),
        });

        console.log(formatReport(report, opts.format as "text" | "json" | "markdown" | "sarif" | "sbom"));

        const exitCode = getReportExitCode(report);
        finishCliCommand(exitCode);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n  Error: ${message}\n`);
        process.exit(1);
      }
    },
  );

// ── pypi command ────────────────────────────────────────────────────

program
  .command("pypi")
  .description("Scan a PyPI package for malware indicators (downloads without installing)")
  .argument("<package>", "PyPI package name (e.g., requests, flask)")
  .option("-f, --format <format>", "Output format: text, json, markdown, sarif", "text")
  .option(
    "-s, --min-severity <severity>",
    "Minimum severity to report",
  )
  .action(
    async (
      packageName: string,
      opts: { format: string; minSeverity?: string },
    ) => {
      try {
        const report = await scanPypiPackage(packageName, {
          target: packageName,
          format: opts.format as "text" | "json" | "markdown" | "sarif" | "sbom",
          minSeverity: parseDefaultGatedMinSeverity(opts.minSeverity),
        });

        console.log(formatReport(report, opts.format as "text" | "json" | "markdown" | "sarif" | "sbom"));

        const exitCode = getReportExitCode(report);
        finishCliCommand(exitCode);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n  Error: ${message}\n`);
        process.exit(1);
      }
    },
  );

// ── vscode command ──────────────────────────────────────────────────

program
  .command("vscode")
  .description("Scan a VS Code extension (.vsix file or marketplace ID) for malware indicators")
  .argument(
    "<target>",
    "Path to .vsix file or marketplace extension ID (e.g., publisher.extension-name)",
  )
  .option("-f, --format <format>", "Output format: text, json, markdown, sarif", "text")
  .option(
    "-s, --min-severity <severity>",
    "Minimum severity to report",
  )
  .option(
    "--registry <registry>",
    "Extension registry for ID targets: marketplace, openvsx",
    "marketplace",
  )
  .action(
    async (
      target: string,
      opts: { format: string; minSeverity?: string; registry: string },
    ) => {
      try {
        if (opts.registry !== "marketplace" && opts.registry !== "openvsx") {
          throw new Error(
            `Unknown registry "${opts.registry}". Expected "marketplace" or "openvsx".`,
          );
        }
        const report = await scanVscodeExtension({
          target,
          format: opts.format as "text" | "json" | "markdown" | "sarif" | "sbom",
          minSeverity: parseDefaultGatedMinSeverity(opts.minSeverity),
          registry: opts.registry as "marketplace" | "openvsx",
        });

        console.log(formatReport(report, opts.format as "text" | "json" | "markdown" | "sarif" | "sbom"));

        const exitCode = getReportExitCode(report);
        finishCliCommand(exitCode);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n  Error: ${message}\n`);
        process.exit(1);
      }
    },
  );

// ── confusion command ───────────────────────────────────────────────

program
  .command("confusion")
  .description("Detect dependency confusion risks in a project's package.json")
  .argument("<target>", "Path to project directory or package.json file")
  .option("-f, --format <format>", "Output format: text, json, markdown, sarif", "text")
  .option(
    "-s, --min-severity <severity>",
    "Minimum severity to report",
  )
  .option("--no-dev", "Exclude devDependencies from the check")
  .action(
    async (
      target: string,
      opts: { format: string; minSeverity?: string; dev: boolean },
    ) => {
      try {
        const report = await scanDependencyConfusion({
          target,
          format: opts.format as "text" | "json" | "markdown" | "sarif" | "sbom",
          minSeverity: parseDefaultGatedMinSeverity(opts.minSeverity),
          includeDevDeps: opts.dev,
        });

        console.log(formatReport(report, opts.format as "text" | "json" | "markdown" | "sarif" | "sbom"));

        const exitCode = getReportExitCode(report);
        finishCliCommand(exitCode);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n  Error: ${message}\n`);
        process.exit(1);
      }
    },
  );

// ── repo command ──────────────────────────────────────────────────

program
  .command("repo")
  .description("Analyze a GitHub repository for trust signals and malware indicators")
  .argument("<url>", "GitHub repository URL (e.g., https://github.com/owner/repo)")
  .option("-f, --format <format>", "Output format: text, json, markdown, sarif, sbom, html, badge, gitlab, junit", "text")
  .action(
    async (
      url: string,
      opts: { format: string },
    ) => {
      try {
        const parsed = parseGitHubUrl(url);
        if (!parsed) {
          throw new Error("Invalid GitHub URL. Expected: https://github.com/owner/repo");
        }

        // Run trust analysis
        const trustFindings = analyzeGitHubTrust(parsed.owner, parsed.repo);

        // Also run a full scan (clone + content analysis)
        const options: ScanOptions = {
          target: url,
          format: opts.format as ScanOptions["format"],
        };
        const report = await scan(options);

        // Merge trust findings (deduplicate)
        const existingRules = new Set(report.findings.map((f) => f.rule));
        for (const tf of trustFindings) {
          if (!existingRules.has(tf.rule)) {
            report.findings.push(tf);
          }
        }

        // Recalculate summary
        report.summary.critical = report.findings.filter((f) => f.severity === "critical").length;
        report.summary.high = report.findings.filter((f) => f.severity === "high").length;
        report.summary.medium = report.findings.filter((f) => f.severity === "medium").length;
        report.summary.low = report.findings.filter((f) => f.severity === "low").length;
        report.summary.info = report.findings.filter((f) => f.severity === "info").length;

        console.log(formatReport(report, opts.format as ScanOptions["format"]));

        const exitCode = getReportExitCode(report);
        finishCliCommand(exitCode);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n  Error: ${message}\n`);
        process.exit(1);
      }
    },
  );

// ── org command ───────────────────────────────────────────────────

program
  .command("org")
  .description("Scan all repositories in a GitHub organization")
  .argument("<org>", "GitHub organization name")
  .option("-f, --format <format>", "Output format: text, json", "text")
  .option("-l, --limit <count>", "Max repos to scan", "20")
  .action(
    async (
      org: string,
      opts: { format: string; limit: string },
    ) => {
      try {
        const { listOrgRepos, analyzeOrgFindings } = await import("./org-scanner.js");
        const repos = listOrgRepos(org, parseInt(opts.limit, 10));

        if (repos.length === 0) {
          console.error(`\n  No repos found for org "${org}". Is gh CLI authenticated?\n`);
          finishCliCommand(1);
          return;
        }

        console.error(`\n  Scanning ${repos.length} repos in ${org}...\n`);

        const repoFindings = new Map<string, import("./types.js").Finding[]>();
        let completedRepos = 0;
        let partialRepos = 0;
        let failedRepos = 0;
        let orgExitCode: 0 | 1 | 2 = 0;
        for (const repoUrl of repos) {
          try {
            const report = await scan({
              target: repoUrl,
              format: opts.format as ScanOptions["format"],
            });
            completedRepos++;
            if (report.partialScan) partialRepos++;
            const repoExitCode = getReportExitCode(report);
            if (repoExitCode > orgExitCode) orgExitCode = repoExitCode;
            repoFindings.set(repoUrl, report.findings);
            const critCount = report.findings.filter((f) => f.severity === "critical").length;
            const highCount = report.findings.filter((f) => f.severity === "high").length;
            if (critCount > 0 || highCount > 0) {
              console.error(`  ${repoUrl}: ${critCount} critical, ${highCount} high`);
            }
          } catch {
            failedRepos++;
            console.error(`  ${repoUrl}: scan failed`);
          }
        }

        const orgFindings = analyzeOrgFindings(repoFindings);
        const synthesizedExitCode = getFindingsExitCode(orgFindings);
        if (synthesizedExitCode > orgExitCode) orgExitCode = synthesizedExitCode;
        const partialScan = partialRepos > 0 || failedRepos > 0;
        if (opts.format === "json") {
          console.log(JSON.stringify({
            org,
            reposScanned: completedRepos,
            ...(partialScan ? { partialScan: true, partialRepos, failedRepos } : {}),
            findings: orgFindings,
          }, null, 2));
        } else {
          const repoCountLabel = partialScan
            ? `${completedRepos} of ${repos.length}`
            : `${repos.length}`;
          console.log(`\n  Organization: ${org} (${repoCountLabel} repos scanned)`);
          if (partialScan) {
            console.log(
              `  WARNING: Partial scan (${partialRepos} incomplete, ${failedRepos} failed). No clean organization verdict can be established.`,
            );
          }
          if (orgFindings.length === 0) {
            console.log("  No cross-repo patterns detected.\n");
          } else {
            for (const f of orgFindings) {
              console.log(`\n  [${f.severity.toUpperCase()}] ${f.description}`);
            }
            console.log("");
          }
        }

        finishCliCommand(orgExitCode !== 0 ? orgExitCode : partialScan ? 1 : 0);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n  Error: ${message}\n`);
        finishCliCommand(1);
      }
    },
  );

// ── monitor command ─────────────────────────────────────────────────

program
  .command("monitor")
  .description("Monitor a Solana wallet for C2 memo transactions")
  .argument("<address>", "Solana wallet address to monitor")
  .option("-i, --interval <seconds>", "Polling interval in seconds", "30")
  .option("-l, --limit <count>", "Max transactions per poll", "20")
  .option("-f, --format <format>", "Output format: text, json", "text")
  .option("--once", "Check once and exit (no continuous monitoring)")
  .action(
    async (
      address: string,
      opts: {
        interval: string;
        limit: string;
        format: string;
        once?: boolean;
      },
    ) => {
      try {
        if (opts.once) {
          // One-shot check
          const results = await checkWallet(
            address,
            parseInt(opts.limit, 10),
          );

          if (opts.format === "json") {
            console.log(JSON.stringify(results, null, 2));
          } else {
            if (results.length === 0) {
              console.log("\n  No memo transactions found.\n");
            } else {
              console.log(`\n  Found ${results.length} memo transaction(s):\n`);
              for (const tx of results) {
                console.log(`  Signature: ${tx.signature}`);
                console.log(`  Memos:     ${tx.memos.join(", ")}`);
                if (tx.blockTime) {
                  console.log(
                    `  Time:      ${new Date(tx.blockTime * 1000).toISOString()}`,
                  );
                }
                console.log("");
              }
            }
          }
          return;
        }

        // Continuous monitoring
        await monitorWallet(
          {
            address,
            interval: parseInt(opts.interval, 10),
            limit: parseInt(opts.limit, 10),
            format: opts.format as "text" | "json",
          },
          (alert) => {
            if (opts.format === "json") {
              console.log(JSON.stringify(alert, null, 2));
            } else {
              console.log(formatAlert(alert));
            }
          },
        );
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n  Error: ${message}\n`);
        process.exit(1);
      }
    },
  );

// -- watchlist command -------------------------------------------------------

const watchlist = program
  .command("watchlist")
  .description("Manage a persistent Solana C2 wallet watchlist");

watchlist
  .command("add")
  .description("Add a Solana wallet address to the watchlist")
  .argument("<address>", "Solana wallet address")
  .requiredOption("-n, --name <name>", "Human-readable label for this wallet")
  .action((address: string, opts: { name: string }) => {
    try {
      const entry = addToWatchlist(address, opts.name);
      console.log(`\n  Added to watchlist:`);
      console.log(`  Address: ${entry.address}`);
      console.log(`  Name:    ${entry.name}`);
      console.log(`  Added:   ${entry.addedAt}\n`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`\n  Error: ${message}\n`);
      process.exit(1);
    }
  });

watchlist
  .command("list")
  .description("List all wallets on the watchlist")
  .action(() => {
    const entries = listWatchlist();
    if (entries.length === 0) {
      console.log("\n  Watchlist is empty.\n");
      return;
    }
    console.log(`\n  Watchlist (${entries.length} wallet(s)):\n`);
    for (const entry of entries) {
      console.log(`  Name:    ${entry.name}`);
      console.log(`  Address: ${entry.address}`);
      console.log(`  Added:   ${entry.addedAt}`);
      console.log("");
    }
  });

watchlist
  .command("remove")
  .description("Remove a wallet from the watchlist")
  .argument("<address>", "Solana wallet address to remove")
  .action((address: string) => {
    try {
      removeFromWatchlist(address);
      console.log(`\n  Removed ${address} from watchlist.\n`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`\n  Error: ${message}\n`);
      process.exit(1);
    }
  });

watchlist
  .command("monitor")
  .description("Poll all watched wallets for new memo transactions")
  .option("-i, --interval <seconds>", "Polling interval in seconds", "30")
  .option("-l, --limit <count>", "Max transactions per poll per wallet", "20")
  .option("-w, --webhook <url>", "Webhook URL to POST alerts to")
  .action(
    async (opts: { interval: string; limit: string; webhook?: string }) => {
      try {
        await monitorWatchlist(
          {
            interval: parseInt(opts.interval, 10),
            limit: parseInt(opts.limit, 10),
            webhookUrl: opts.webhook,
          },
          (alert) => {
            console.log("");
            console.log("  ====================================");
            console.log("  !! WATCHLIST ALERT !!");
            console.log("  ====================================");
            console.log(`  Name:      ${alert.name}`);
            console.log(`  Address:   ${alert.address}`);
            console.log(`  TxID:      ${alert.txid}`);
            console.log(`  Memo:      ${alert.memo}`);
            console.log(`  Timestamp: ${alert.timestamp}`);
            console.log("  ====================================");
            console.log("");
          },
        );
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n  Error: ${message}\n`);
        process.exit(1);
      }
    },
  );

// -- feed command ------------------------------------------------------------

const feedCmd = program
  .command("feed")
  .description("Inspect and refresh the threat-intel IOC feed");

feedCmd
  .command("stats")
  .description("Show IOC entry counts by type and severity (offline)")
  .option("-f, --format <format>", "Output format: text, json", "text")
  .action(async (opts: { format: string }) => {
    try {
      const { getBundledFeed, loadThreatIntel } = await import("./threat-intel.js");
      const { feedStats } = await import("./feed.js");
      const bundled = getBundledFeed();
      const effective = loadThreatIntel();
      const stats = feedStats(effective);

      if (opts.format === "json") {
        console.log(
          JSON.stringify({ bundledEntries: bundled.length, ...stats }, null, 2),
        );
        return;
      }

      console.log(`\n  Threat-intel feed statistics:\n`);
      console.log(`  Bundled entries:   ${bundled.length}`);
      console.log(`  Effective entries: ${stats.total} (bundled + fresh cache)`);
      console.log(`\n  By type:`);
      for (const [type, count] of Object.entries(stats.byType)) {
        console.log(`    ${type.padEnd(10)} ${count}`);
      }
      console.log(`\n  By severity:`);
      for (const [severity, count] of Object.entries(stats.bySeverity)) {
        console.log(`    ${severity.padEnd(10)} ${count}`);
      }
      console.log("");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`\n  Error: ${message}\n`);
      process.exit(1);
    }
  });

feedCmd
  .command("refresh")
  .description(
    "Download the published IOC feed into the local cache for same-day protection (default source: the project's feed.json on GitHub main)",
  )
  .option("-u, --url <url>", "Feed URL to download instead of the default")
  .option("-c, --cache-dir <dir>", "Cache directory to write to (default: .scg-cache)")
  .action(async (opts: { url?: string; cacheDir?: string }) => {
    try {
      const { refreshFeed, DEFAULT_FEED_URL } = await import("./feed.js");
      const result = await refreshFeed(opts.url ?? DEFAULT_FEED_URL, opts.cacheDir);
      console.log(`\n  Threat feed refreshed: ${result.entryCount} entries cached.`);
      console.log(`  Cache file: ${result.cachePath}`);
      console.log(`  Scans in the next 24h automatically merge these entries.\n`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`\n  Error: ${message}\n`);
      process.exit(1);
    }
  });

feedCmd
  .command("osv")
  .description(
    "Export the feed's malicious-package IOCs as OSV records (osv.dev schema) for osv-scanner / ossf-malicious-packages consumption (offline)",
  )
  .option("-o, --out <file>", "Write the OSV JSON to a file instead of stdout")
  .action(async (opts: { out?: string }) => {
    try {
      const { getBundledFeed } = await import("./threat-intel.js");
      const { toOsvRecords } = await import("./osv-export.js");
      const records = toOsvRecords(getBundledFeed());
      const json = JSON.stringify(records, null, 2);
      if (opts.out) {
        const { writeFileSync } = await import("node:fs");
        writeFileSync(opts.out, json, "utf-8");
        console.error(`\n  Wrote ${records.length} OSV records to ${opts.out}\n`);
      } else {
        console.log(json);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`\n  Error: ${message}\n`);
      process.exit(1);
    }
  });

// ── mcp command ─────────────────────────────────────────────────────

program
  .command("mcp")
  .description("Start an MCP server exposing supply-chain-guard tools over stdio")
  .action(async () => {
    const { startMcpServer } = await import("./mcp-server.js");
    startMcpServer();
  });

// ── guard command ───────────────────────────────────────────────────

// Required so the guard command can pass the manager's own flags through
// untouched (passThroughOptions below); program-level options (-V/-h) keep
// working before the subcommand name, which is the only place they were
// ever recognized.
program.enablePositionalOptions();

program
  .command("guard")
  .description(
    "Run an install command through the offline IOC blocklist first; known-bad packages block the install (exit 2)",
  )
  .passThroughOptions()
  .argument("<manager>", "Package manager: npm, pnpm, yarn, bun")
  .argument("[managerArgs...]", "Arguments passed to the package manager unchanged")
  .option("--force", "Proceed despite findings (loud warning)")
  .option("--dry-run", "Check only; never invoke the package manager")
  .action(
    async (
      manager: string,
      managerArgs: string[],
      opts: { force?: boolean; dryRun?: boolean },
    ) => {
      try {
        const { runInstallGuard } = await import("./install-guard.js");
        const code = runInstallGuard(manager, managerArgs, {
          force: opts.force,
          dryRun: opts.dryRun,
        });
        finishCliCommand(code);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n  Error: ${message}\n`);
        finishCliCommand(1);
      }
    },
  );

// ── internal-hash command ───────────────────────────────────────────────

program
  .command("internal-hash")
  .description(
    "Print the sha256 digest of one or more internal terms for internalDisclosure.hashedTerms (the digest is safe to commit, the term is not)",
  )
  .argument("<terms...>", "Terms to hash: a hostname, an org/repo name, a path fragment")
  .action(async (terms: string[]) => {
    const { hashInternalTerm, INTERNAL_HASH_SALT_ENV } = await import(
      "./internal-disclosure.js"
    );
    // An optional salt, read from the environment rather than an argument so
    // it never reaches the shell history or the process list. It has to live
    // outside the repository to be worth anything: a salt stored next to the
    // digests is hashed by the same attacker who reads them.
    const salt = process.env[INTERNAL_HASH_SALT_ENV] ?? null;
    if (salt) {
      console.error(
        `  Salted with $${INTERNAL_HASH_SALT_ENV}. Set internalDisclosure.hashSalted: true so a scan without the salt is reported instead of silently matching nothing.`,
      );
    }
    // One digest per line, nothing else. The plaintext term is deliberately
    // NOT echoed: the output of this command is meant to be pasted into a
    // committed config file, and an echoed term would travel with it.
    for (const term of terms) {
      console.log(hashInternalTerm(term, salt));
    }
  });

program.parse();
