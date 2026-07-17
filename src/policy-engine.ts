/**
 * Policy engine (v4.4).
 *
 * Loads .supply-chain-guard.yml configuration, applies rule overrides,
 * suppressions, allowlists, and baseline diffing to reduce false positives
 * and make the scanner production-ready for CI pipelines.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, PolicyConfig, PolicyWarning, Severity } from "./types.js";

// ---------------------------------------------------------------------------
// Minimal glob matcher (no dependency; commander stays the only runtime dep)
// ---------------------------------------------------------------------------

/**
 * Match a forward-slash path against a minimal glob supporting `**` (any chars
 * including `/`), `*` (any chars within a path segment) and `?` (one non-`/`
 * char). Used for `ignore:` path globs and per-path `suppress` entries.
 * Anchored: the whole path must match.
 */
export function matchGlob(glob: string, filePath: string): boolean {
  const g = glob.replace(/\\/g, "/");
  const p = filePath.replace(/\\/g, "/");
  let re = "";
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === "*") {
      if (g[i + 1] === "*") {
        i++; // consume the second "*"
        if (g[i + 1] === "/") {
          // "**/" matches zero or more leading path segments, each ending in a
          // "/". So "**/x" matches "x" at the root and "a/b/x", but NOT "ax":
          // the segment boundary is required (was ".*" which over-matched
          // lookalike basenames like "notx" - v5.14.0 gate finding).
          re += "(?:.*/)?";
          i++; // consume the "/"
        } else {
          // bare "**" (end of glob or "**foo"): match across separators.
          re += ".*";
        }
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  try {
    return new RegExp(`^${re}$`).test(p);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

const CONFIG_FILENAMES = [
  ".supply-chain-guard.yml",
  ".supply-chain-guard.yaml",
  ".scg.yml",
  ".scg.yaml",
];

/**
 * Load policy config from the project directory.
 * Returns null if no config file found.
 */
export function loadPolicyConfig(dir: string): PolicyConfig | null {
  for (const filename of CONFIG_FILENAMES) {
    const configPath = path.join(dir, filename);
    if (!fs.existsSync(configPath)) continue;

    try {
      const content = fs.readFileSync(configPath, "utf-8");
      const config = parseYamlConfig(content);
      // Attach the config file name so warnings-turned-findings point at it
      if (config.warnings) {
        for (const warning of config.warnings) warning.file = filename;
      }
      return config;
    } catch {
      return null;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Config validation (v5.3, fail-closed)
// ---------------------------------------------------------------------------

/**
 * The complete structure the parser understands. Anything outside this map
 * is a typo or an unsupported key - and MUST be surfaced, because the parser
 * silently ignores unknown keys: a typo like "supress:" means the intended
 * suppressions are NOT applied and the config fails open.
 * policy-schema.json at the repo root mirrors this for editor validation.
 */
const KNOWN_SECTIONS: Record<string, string[]> = {
  rules: ["disable", "severityOverrides"],
  allowlist: ["packages", "domains", "githubOrgs"],
  suppress: [],
  baseline: ["file"],
  ignore: [],
};

/** Keys allowed inside a suppress entry */
const SUPPRESS_ENTRY_KEYS = new Set(["rule", "reason", "path"]);

/** Rule ids are SCREAMING_SNAKE_CASE (e.g. EVAL_ATOB, GHA_UNPINNED_ACTION) */
const RULE_ID_PATTERN = /^[A-Z][A-Z0-9_]*$/;

/**
 * Strip a single pair of surrounding quotes. Glob values that start with a
 * star must be quoted to be valid YAML (a leading star is an alias reference),
 * so a user quotes them; the naive parser would otherwise keep the quotes.
 */
function stripQuotes(value: string): string {
  const m = value.match(/^"(.*)"$/) ?? value.match(/^'(.*)'$/);
  return m ? m[1] : value;
}

/**
 * Simple YAML-like config parser (no dependency needed).
 * Supports the flat key-value structure of .supply-chain-guard.yml.
 *
 * Validation is strict: unknown sections/keys, suppressions without a
 * reason, and malformed rule ids are collected as warnings on the returned
 * config. applyPolicy() converts them into findings so a broken policy file
 * is loudly reported instead of silently failing open.
 */
function parseYamlConfig(content: string): PolicyConfig {
  const config: PolicyConfig = {};
  const warnings: PolicyWarning[] = [];
  const lines = content.split("\n");

  let currentSection = "";
  let currentSubSection = "";
  // Whether the current top-level section is one the parser understands.
  // Content inside an unknown section is not re-reported key by key.
  let sectionKnown = false;
  // Tracks per suppress entry whether an explicit non-empty reason was given
  // (the parser fills in a placeholder reason, so presence alone proves nothing).
  const reasonProvided: boolean[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/\r$/, "");
    if (line.trim().startsWith("#") || line.trim() === "") continue;

    const lineNo = i + 1;
    const indent = line.length - line.trimStart().length;
    const trimmed = line.trim();

    // Top-level sections
    if (indent === 0 && trimmed.endsWith(":")) {
      currentSection = trimmed.slice(0, -1);
      currentSubSection = "";
      sectionKnown = currentSection in KNOWN_SECTIONS;
      if (!sectionKnown) {
        warnings.push({
          rule: "POLICY_UNKNOWN_KEY",
          message: `unknown top-level section "${currentSection}" (known sections: ${Object.keys(KNOWN_SECTIONS).join(", ")})`,
          line: lineNo,
        });
      }
      continue;
    }

    // Top-level scalar keys are not supported (every top-level key opens a
    // section). Do not let them fall through into a stale section context.
    if (indent === 0 && trimmed.includes(":") && !trimmed.startsWith("-")) {
      warnings.push({
        rule: "POLICY_UNKNOWN_KEY",
        message: `top-level key "${trimmed.split(":")[0].trim()}" with an inline value is not supported (sections use block style, see policy-schema.json)`,
        line: lineNo,
      });
      currentSection = "";
      currentSubSection = "";
      sectionKnown = false;
      continue;
    }

    // Sub-sections
    if (indent === 2 && trimmed.endsWith(":")) {
      currentSubSection = trimmed.slice(0, -1);
      if (sectionKnown && !KNOWN_SECTIONS[currentSection].includes(currentSubSection)) {
        if (currentSection === "suppress" && currentSubSection === "- rule") {
          // "- rule:" with no value: an entry that suppresses nothing
          warnings.push({
            rule: "POLICY_MALFORMED_RULE_ID",
            message: `suppress entry has an empty rule value`,
            line: lineNo,
          });
        } else if (currentSection === "suppress") {
          warnings.push({
            rule: "POLICY_UNKNOWN_KEY",
            message: `unknown key "${currentSubSection}" in suppress section (suppress is a list of "- rule: <RULE_ID>" entries)`,
            line: lineNo,
          });
        } else {
          warnings.push({
            rule: "POLICY_UNKNOWN_KEY",
            message: `unknown key "${currentSubSection}" in section "${currentSection}" (known keys: ${KNOWN_SECTIONS[currentSection].join(", ")})`,
            line: lineNo,
          });
        }
      }
      continue;
    }

    // List items
    if (trimmed.startsWith("- ")) {
      const value = trimmed.slice(2).trim();

      if (currentSection === "rules" && currentSubSection === "disable") {
        config.rules ??= {};
        config.rules.disable ??= [];
        config.rules.disable.push(value);
      } else if (currentSection === "allowlist" && currentSubSection === "packages") {
        config.allowlist ??= {};
        config.allowlist.packages ??= [];
        config.allowlist.packages.push(value);
      } else if (currentSection === "allowlist" && currentSubSection === "domains") {
        config.allowlist ??= {};
        config.allowlist.domains ??= [];
        config.allowlist.domains.push(value);
      } else if (currentSection === "allowlist" && currentSubSection === "githubOrgs") {
        config.allowlist ??= {};
        config.allowlist.githubOrgs ??= [];
        config.allowlist.githubOrgs.push(value);
      } else if (currentSection === "ignore") {
        // Path globs whose matching files are skipped by the scanner walk.
        config.ignore ??= [];
        config.ignore.push(stripQuotes(value));
      } else if (currentSection === "suppress") {
        // Suppress entries need rule + reason on subsequent lines
        config.suppress ??= [];
        // Simple format: "- rule: RULE_NAME"
        if (value.startsWith("rule:")) {
          const ruleId = value.replace("rule:", "").trim();
          if (!RULE_ID_PATTERN.test(ruleId)) {
            warnings.push({
              rule: "POLICY_MALFORMED_RULE_ID",
              message: `suppress rule "${ruleId}" is not a SCREAMING_SNAKE_CASE rule id; the suppression will never match a real rule`,
              line: lineNo,
            });
          }
          config.suppress.push({
            rule: ruleId,
            reason: "suppressed by policy",
          });
          reasonProvided.push(false);
        } else {
          // "- reason: ..." first, a typo'd key, or a bare "- RULE_ID":
          // the parser drops the entry, so the suppression is NOT applied.
          const startKey = value.includes(":") ? value.split(":")[0].trim() : value;
          warnings.push({
            rule: "POLICY_UNKNOWN_KEY",
            message: `suppress entry starting with "${startKey}" is ignored; entries must start with "- rule: <RULE_ID>"`,
            line: lineNo,
          });
        }
      }
      continue;
    }

    // Key-value pairs
    if (trimmed.includes(":") && !trimmed.startsWith("-")) {
      const [key, ...rest] = trimmed.split(":");
      const k = key.trim();
      const val = rest.join(":").trim();

      if (currentSection === "rules" && currentSubSection === "severityOverrides") {
        config.rules ??= {};
        config.rules.severityOverrides ??= {};
        config.rules.severityOverrides[k] = val as Severity;
      } else if (currentSection === "baseline" && k === "file") {
        config.baseline ??= {};
        config.baseline.file = val;
      } else if (currentSection === "suppress" && SUPPRESS_ENTRY_KEYS.has(k)) {
        // Handle suppress reason/path on inline entries. ("rule:" continuation
        // lines are tolerated; entries are created by the "- rule:" item.)
        if (k === "reason" && config.suppress?.length) {
          config.suppress[config.suppress.length - 1].reason = val;
          if (val !== "") reasonProvided[config.suppress.length - 1] = true;
        } else if (k === "path" && config.suppress?.length && val !== "") {
          // Optional file glob: the rule is suppressed only under this path.
          config.suppress[config.suppress.length - 1].path = stripQuotes(val);
        }
      } else if (sectionKnown) {
        // Fail-closed: a key the parser silently drops means the intended
        // policy is NOT applied. Surface it instead of ignoring it.
        warnings.push({
          rule: "POLICY_UNKNOWN_KEY",
          message: currentSection === "suppress"
            ? `unknown key "${k}" in suppress entry (known keys: rule, reason)`
            : `unknown or misplaced key "${k}" in section "${currentSection}"`,
          line: lineNo,
        });
      }
    }
  }

  // Suppress entries without an explicit, non-empty reason lack an audit trail
  (config.suppress ?? []).forEach((entry, idx) => {
    if (!reasonProvided[idx]) {
      warnings.push({
        rule: "POLICY_SUPPRESSION_NO_REASON",
        message: `suppress entry for rule "${entry.rule}" has no reason; every suppression needs a documented justification`,
      });
    }
  });

  if (warnings.length > 0) config.warnings = warnings;
  return config;
}

// ---------------------------------------------------------------------------
// Policy application
// ---------------------------------------------------------------------------

/** Finding metadata for the policy validation rules (v5.3) */
const POLICY_WARNING_META: Record<
  PolicyWarning["rule"],
  { severity: Severity; confidence: number; description: string; recommendation: string }
> = {
  POLICY_UNKNOWN_KEY: {
    severity: "high",
    confidence: 0.9,
    description:
      "Policy config contains a key the parser does not understand. Unknown keys are silently ignored, so the intended policy (e.g. suppressions behind a typo like \"supress:\") is NOT applied - the config fails open.",
    recommendation:
      "Fix the key in .supply-chain-guard.yml. See policy-schema.json (referenced via a yaml-language-server comment) for the accepted structure.",
  },
  POLICY_SUPPRESSION_NO_REASON: {
    severity: "medium",
    confidence: 1.0,
    description:
      "Policy suppression has no reason. Suppressions without a documented justification cannot be audited and tend to outlive the tradeoff that motivated them.",
    recommendation:
      "Add a \"reason:\" line to every suppress entry in .supply-chain-guard.yml.",
  },
  POLICY_MALFORMED_RULE_ID: {
    severity: "medium",
    confidence: 0.9,
    description:
      "Policy references a rule id that is not SCREAMING_SNAKE_CASE. The reference can never match a real rule, so the intended suppression is NOT applied - the config fails open.",
    recommendation:
      "Use the exact rule id as reported by the scanner (e.g. EVAL_ATOB) in .supply-chain-guard.yml.",
  },
};

/**
 * Convert a parse-time policy warning into a reportable finding.
 */
function policyWarningToFinding(warning: PolicyWarning): Finding {
  const meta = POLICY_WARNING_META[warning.rule];
  return {
    rule: warning.rule,
    description: `${meta.description} Detail: ${warning.message}.`,
    severity: meta.severity,
    file: warning.file,
    line: warning.line,
    recommendation: meta.recommendation,
    confidence: meta.confidence,
    category: "config",
  };
}

/**
 * Apply policy to findings: disable rules, override severities,
 * suppress findings, apply allowlists.
 */
export function applyPolicy(
  findings: Finding[],
  policy: PolicyConfig,
): { findings: Finding[]; suppressedCount: number } {
  let suppressedCount = 0;
  const disabledRules = new Set(policy.rules?.disable ?? []);
  const severityOverrides = policy.rules?.severityOverrides ?? {};
  const suppressEntries = policy.suppress ?? [];
  const allowedPackages = new Set(policy.allowlist?.packages ?? []);
  const allowedDomains = policy.allowlist?.domains ?? [];

  const result: Finding[] = [];

  for (const finding of findings) {
    // Disabled rules: skip entirely
    if (disabledRules.has(finding.rule)) {
      suppressedCount++;
      continue;
    }

    // Suppressed rules: mark as suppressed info. A bare "- rule:" entry
    // suppresses globally; an entry that also carries a "path:" glob only
    // suppresses findings whose file matches that glob (backward compatible).
    const suppressMatch = suppressEntries.find(
      (s) =>
        s.rule === finding.rule &&
        (s.path === undefined ||
          matchGlob(s.path, (finding.file ?? "").replace(/\\/g, "/"))),
    );
    if (suppressMatch) {
      suppressedCount++;
      finding.suppressed = true;
      finding.severity = "info";
      finding.description = `[SUPPRESSED] ${finding.description}`;
      continue; // Don't include in output
    }

    // Allowlisted packages
    if (finding.rule === "TYPOSQUAT_LEVENSHTEIN" || finding.rule === "DEP_INTERNAL_NAME_PUBLIC") {
      const pkgMatch = finding.description.match(/"([^"]+)"/);
      if (pkgMatch && allowedPackages.has(pkgMatch[1])) {
        suppressedCount++;
        continue;
      }
    }

    // Allowlisted domains: drop threat-intel / known-C2-domain findings whose
    // matched value is a trusted domain (exact host or subdomain-of). These
    // findings carry the value in `match` or in the description text.
    if (
      allowedDomains.length > 0 &&
      (finding.rule === "THREAT_INTEL_MATCH" || finding.rule === "IOC_KNOWN_C2_DOMAIN")
    ) {
      const value = extractFindingDomain(finding);
      if (value && isDomainAllowlisted(value, allowedDomains)) {
        suppressedCount++;
        continue;
      }
    }

    // Severity overrides
    if (severityOverrides[finding.rule]) {
      finding.severity = severityOverrides[finding.rule];
    }

    result.push(finding);
  }

  // v5.3 fail-closed config validation: parse-time warnings become findings.
  // Appended AFTER the disable/suppress pass on purpose - a broken policy
  // file must not be able to silence its own diagnosis.
  for (const warning of policy.warnings ?? []) {
    result.push(policyWarningToFinding(warning));
  }

  return { findings: result, suppressedCount };
}

/**
 * Extract the matched host/indicator value from a domain-bearing finding.
 * Prefers the structured `match` field, falling back to the value embedded in
 * the description (THREAT_INTEL_MATCH quotes it; IOC_KNOWN_C2_DOMAIN puts it
 * after the colon).
 */
function extractFindingDomain(finding: Finding): string | undefined {
  if (finding.match) return finding.match.trim();
  if (finding.rule === "THREAT_INTEL_MATCH") {
    return finding.description.match(/"([^"]+)"/)?.[1];
  }
  if (finding.rule === "IOC_KNOWN_C2_DOMAIN") {
    return finding.description.match(/detected:\s*(\S+)/)?.[1];
  }
  return undefined;
}

/**
 * True when `value` is an allowlisted domain: an exact host match or a
 * subdomain of one of the allowlisted domains (e.g. "rti.example.com" is
 * covered by an allowlist entry of "example.com").
 */
function isDomainAllowlisted(value: string, allowed: string[]): boolean {
  const host = value.toLowerCase().replace(/\.$/, "");
  return allowed.some((d) => {
    const dl = d.toLowerCase().trim().replace(/\.$/, "");
    return dl !== "" && (host === dl || host.endsWith("." + dl));
  });
}

// ---------------------------------------------------------------------------
// Inline suppressions
// ---------------------------------------------------------------------------

/**
 * Drop findings marked with an inline suppression comment on the line directly
 * above them: `// scg-ignore-next-line RULE [reason]` (JS/TS) or
 * `# scg-ignore-next-line RULE` (Python/YAML/shell). Only a finding whose
 * file+line sits exactly one line below a matching directive is suppressed.
 *
 * Reads each referenced file at most once from `rootDir`. Findings without a
 * file+line, or whose source can no longer be read, pass through unchanged.
 */
export function applyInlineSuppressions(
  findings: Finding[],
  rootDir: string,
): { findings: Finding[]; suppressedCount: number } {
  const INLINE_RE = /(?:\/\/|#)\s*scg-ignore-next-line\s+([A-Za-z][A-Za-z0-9_]*)/;
  const fileCache = new Map<string, string[] | null>();

  const readLines = (rel: string): string[] | null => {
    if (fileCache.has(rel)) return fileCache.get(rel)!;
    let lines: string[] | null = null;
    try {
      lines = fs.readFileSync(path.join(rootDir, rel), "utf-8").split("\n");
    } catch {
      lines = null;
    }
    fileCache.set(rel, lines);
    return lines;
  };

  let suppressedCount = 0;
  const result: Finding[] = [];

  for (const finding of findings) {
    if (finding.file && finding.line && finding.line > 1) {
      const lines = readLines(finding.file.replace(/\\/g, "/"));
      // The finding is on line `finding.line` (1-based); the directive must be
      // on the line directly above it (0-based index finding.line - 2).
      const above = lines?.[finding.line - 2] ?? "";
      const m = INLINE_RE.exec(above);
      if (m && m[1] === finding.rule) {
        suppressedCount++;
        continue;
      }
    }
    result.push(finding);
  }

  return { findings: result, suppressedCount };
}

// ---------------------------------------------------------------------------
// Baseline system
// ---------------------------------------------------------------------------

interface BaselineEntry {
  rule: string;
  file?: string;
  line?: number;
  match?: string;
}

/**
 * Save current findings as baseline.
 */
export function saveBaseline(
  findings: Finding[],
  baselinePath: string,
): void {
  const entries: BaselineEntry[] = findings.map((f) => ({
    rule: f.rule,
    file: f.file,
    line: f.line,
    match: f.match,
  }));
  fs.writeFileSync(baselinePath, JSON.stringify(entries, null, 2), "utf-8");
}

/**
 * Load baseline and filter out known findings.
 * Returns only NEW findings not in the baseline.
 */
export function applyBaseline(
  findings: Finding[],
  baselinePath: string,
): { findings: Finding[]; suppressedCount: number } {
  if (!fs.existsSync(baselinePath)) {
    return { findings, suppressedCount: 0 };
  }

  let baseline: BaselineEntry[];
  try {
    baseline = JSON.parse(fs.readFileSync(baselinePath, "utf-8")) as BaselineEntry[];
  } catch {
    return { findings, suppressedCount: 0 };
  }

  const baselineSet = new Set(
    baseline.map((b) => `${b.rule}|${b.file ?? ""}|${b.line ?? ""}`),
  );

  let suppressedCount = 0;
  const result: Finding[] = [];

  for (const finding of findings) {
    const key = `${finding.rule}|${finding.file ?? ""}|${finding.line ?? ""}`;
    if (baselineSet.has(key)) {
      suppressedCount++;
    } else {
      result.push(finding);
    }
  }

  return { findings: result, suppressedCount };
}
