#!/usr/bin/env node

/**
 * supply-chain-guard CLI
 *
 * Scan code repositories, npm packages, PyPI packages, VS Code extensions,
 * and project dependencies for supply-chain malware indicators.
 */

import { Command } from "commander";
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
import { formatReport } from "./reporter.js";
import type { ScanOptions, Severity } from "./types.js";

const program = new Command();

program
  .name("supply-chain-guard")
  .description(
    "Open-source supply-chain security scanner. Detects GlassWorm and similar malware campaigns in npm packages, PyPI packages, code repos, VS Code extensions, and project dependencies.",
  )
  .version("4.6.0");

// ── scan command ────────────────────────────────────────────────────

program
  .command("scan")
  .description("Scan a local directory or GitHub repo for malware indicators")
  .argument("<target>", "Local directory path or GitHub repo URL")
  .option("-f, --format <format>", "Output format: text, json, markdown, sarif, sbom, html", "text")
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
  .action(
    async (
      target: string,
      opts: {
        format: string;
        minSeverity?: string;
        exclude?: string;
        depth: string;
        failOn?: string;
        baseline?: string;
        saveBaseline?: string;
        since?: string;
        exportIncidentMd?: boolean;
        exportFixes?: boolean;
      },
    ) => {
      try {
        const options: ScanOptions = {
          target,
          format: opts.format as ScanOptions["format"],
          minSeverity: opts.minSeverity as Severity | undefined,
          excludeRules: opts.exclude?.split(",").map((r) => r.trim()),
          maxDepth: parseInt(opts.depth, 10),
          baselineFile: opts.baseline,
          sinceCommit: opts.since,
        };

        const report = await scan(options);

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
          console.log(formatReport(report, options.format));
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

        // Exit code logic
        if (opts.failOn) {
          const severityOrder: Record<string, number> = {
            critical: 4, high: 3, medium: 2, low: 1, info: 0,
          };
          const threshold = severityOrder[opts.failOn] ?? 0;
          const hasFindings = report.findings.some(
            (f) => (severityOrder[f.severity] ?? 0) >= threshold,
          );
          if (hasFindings) {
            process.exit(1);
          }
        } else {
          if (report.summary.critical > 0) {
            process.exit(2);
          }
          if (report.summary.high > 0) {
            process.exit(1);
          }
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n  Error: ${message}\n`);
        process.exit(1);
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
          minSeverity: opts.minSeverity as Severity | undefined,
        });

        console.log(formatReport(report, opts.format as "text" | "json" | "markdown" | "sarif" | "sbom"));

        if (report.summary.critical > 0) {
          process.exit(2);
        }
        if (report.summary.high > 0) {
          process.exit(1);
        }
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
          minSeverity: opts.minSeverity as Severity | undefined,
        });

        console.log(formatReport(report, opts.format as "text" | "json" | "markdown" | "sarif" | "sbom"));

        if (report.summary.critical > 0) {
          process.exit(2);
        }
        if (report.summary.high > 0) {
          process.exit(1);
        }
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
  .action(
    async (
      target: string,
      opts: { format: string; minSeverity?: string },
    ) => {
      try {
        const report = await scanVscodeExtension({
          target,
          format: opts.format as "text" | "json" | "markdown" | "sarif" | "sbom",
          minSeverity: opts.minSeverity as Severity | undefined,
        });

        console.log(formatReport(report, opts.format as "text" | "json" | "markdown" | "sarif" | "sbom"));

        if (report.summary.critical > 0) {
          process.exit(2);
        }
        if (report.summary.high > 0) {
          process.exit(1);
        }
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
          minSeverity: opts.minSeverity as Severity | undefined,
          includeDevDeps: opts.dev,
        });

        console.log(formatReport(report, opts.format as "text" | "json" | "markdown" | "sarif" | "sbom"));

        if (report.summary.critical > 0) {
          process.exit(2);
        }
        if (report.summary.high > 0) {
          process.exit(1);
        }
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
  .option("-f, --format <format>", "Output format: text, json, markdown, sarif, sbom, html", "text")
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

        if (report.summary.critical > 0) {
          process.exit(2);
        }
        if (report.summary.high > 0) {
          process.exit(1);
        }
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
          process.exit(1);
        }

        console.error(`\n  Scanning ${repos.length} repos in ${org}...\n`);

        const repoFindings = new Map<string, import("./types.js").Finding[]>();
        for (const repoUrl of repos) {
          try {
            const report = await scan({
              target: repoUrl,
              format: opts.format as ScanOptions["format"],
            });
            repoFindings.set(repoUrl, report.findings);
            const critCount = report.findings.filter((f) => f.severity === "critical").length;
            const highCount = report.findings.filter((f) => f.severity === "high").length;
            if (critCount > 0 || highCount > 0) {
              console.error(`  ${repoUrl}: ${critCount} critical, ${highCount} high`);
            }
          } catch {
            console.error(`  ${repoUrl}: scan failed`);
          }
        }

        const orgFindings = analyzeOrgFindings(repoFindings);
        if (opts.format === "json") {
          console.log(JSON.stringify({ org, reposScanned: repos.length, findings: orgFindings }, null, 2));
        } else {
          console.log(`\n  Organization: ${org} (${repos.length} repos scanned)`);
          if (orgFindings.length === 0) {
            console.log("  No cross-repo patterns detected.\n");
          } else {
            for (const f of orgFindings) {
              console.log(`\n  [${f.severity.toUpperCase()}] ${f.description}`);
            }
            console.log("");
          }
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n  Error: ${message}\n`);
        process.exit(1);
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

program.parse();
