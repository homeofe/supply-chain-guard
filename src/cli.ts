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
  .version("1.0.0");

// ── scan command ────────────────────────────────────────────────────

program
  .command("scan")
  .description("Scan a local directory or GitHub repo for malware indicators")
  .argument("<target>", "Local directory path or GitHub repo URL")
  .option("-f, --format <format>", "Output format: text, json, markdown, sarif", "text")
  .option(
    "-s, --min-severity <severity>",
    "Minimum severity to report: critical, high, medium, low, info",
  )
  .option(
    "-e, --exclude <rules>",
    "Comma-separated list of rule IDs to exclude",
  )
  .option("-d, --depth <depth>", "Maximum directory depth", "20")
  .action(
    async (
      target: string,
      opts: {
        format: string;
        minSeverity?: string;
        exclude?: string;
        depth: string;
      },
    ) => {
      try {
        const options: ScanOptions = {
          target,
          format: opts.format as "text" | "json" | "markdown" | "sarif",
          minSeverity: opts.minSeverity as Severity | undefined,
          excludeRules: opts.exclude?.split(",").map((r) => r.trim()),
          maxDepth: parseInt(opts.depth, 10),
        };

        const report = await scan(options);
        console.log(formatReport(report, options.format));

        // Exit with non-zero if critical findings
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
          format: opts.format as "text" | "json" | "markdown" | "sarif",
          minSeverity: opts.minSeverity as Severity | undefined,
        });

        console.log(formatReport(report, opts.format as "text" | "json" | "markdown" | "sarif"));

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
          format: opts.format as "text" | "json" | "markdown" | "sarif",
          minSeverity: opts.minSeverity as Severity | undefined,
        });

        console.log(formatReport(report, opts.format as "text" | "json" | "markdown" | "sarif"));

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
          format: opts.format as "text" | "json" | "markdown" | "sarif",
          minSeverity: opts.minSeverity as Severity | undefined,
        });

        console.log(formatReport(report, opts.format as "text" | "json" | "markdown" | "sarif"));

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
          format: opts.format as "text" | "json" | "markdown" | "sarif",
          minSeverity: opts.minSeverity as Severity | undefined,
          includeDevDeps: opts.dev,
        });

        console.log(formatReport(report, opts.format as "text" | "json" | "markdown" | "sarif"));

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
