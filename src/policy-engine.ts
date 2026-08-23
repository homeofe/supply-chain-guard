/**
 * Policy engine (v4.4).
 *
 * Loads .supply-chain-guard.yml configuration, applies rule overrides,
 * suppressions, allowlists, and baseline diffing to reduce false positives
 * and make the scanner production-ready for CI pipelines.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type {
  Finding,
  PolicyConfig,
  PolicyEffect,
  PolicyEffectEntry,
  PolicyWarning,
  Severity,
} from "./types.js";

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
 *
 * TRUST BOUNDARY, stated here because the call site cannot state it: `dir` is
 * the directory being SCANNED. Policy and artifact are therefore the same
 * input, so on a pull_request event the config that governs the scan is the
 * one on the proposing branch. That is a deliberate, documented property (see
 * the "Where policy is read from" section of README.md and the `policy-source`
 * note in action.yml), not an oversight, and changing it is an owner decision
 * tracked in https://github.com/homeofe/supply-chain-guard/issues/168.
 *
 * What is NOT deliberate, and what this module now prevents, is the change
 * being SILENT: every narrowing the config performs is recorded by
 * describePolicyEffect() and rendered in every output format, and a narrowing
 * declared without a written reason is reported as a finding.
 */
export function loadPolicyConfig(dir: string): PolicyConfig | null {
  for (const filename of CONFIG_FILENAMES) {
    const configPath = path.join(dir, filename);
    if (!fs.existsSync(configPath)) continue;

    try {
      const content = fs.readFileSync(configPath, "utf-8");
      const config = parseYamlConfig(content);
      config.sourceFile = filename;
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
  internalDisclosure: ["hashedTerms", "patterns", "externalFile", "hashSalted"],
};

/** A committed `hashedTerms` entry: sha256 hex, with an optional `sha256:` prefix. */
const HASHED_TERM_PATTERN = /^(?:sha256:)?[0-9a-f]{64}$/i;

/** Keys allowed inside a suppress entry */
const SUPPRESS_ENTRY_KEYS = new Set(["rule", "reason", "path"]);

/**
 * Filled in for a suppress entry until a real `reason:` line overwrites it.
 * Named rather than inlined because describePolicyEffect() has to tell a
 * placeholder apart from a written justification: reporting this string to a
 * reader as the reason a finding vanished would be worse than reporting none.
 */
const SUPPRESS_PLACEHOLDER_REASON = "suppressed by policy";

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
      // `ignore:` takes globs, not sub-keys. A mapping key with an empty value
      // ("dist/**:") is the reason-carrying form written without its reason, so
      // record the glob and report the missing justification rather than
      // reporting an "unknown key" the user never intended to write.
      if (currentSection === "ignore") {
        const glob = stripQuotes(trimmed.slice(0, -1));
        config.ignore ??= [];
        config.ignore.push(glob);
        currentSubSection = "";
        continue;
      }
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
      } else if (
        currentSection === "internalDisclosure" &&
        currentSubSection === "hashedTerms"
      ) {
        // sha256 digests of internal terms. A malformed digest can never match
        // anything, so the deny-list would silently do nothing: report it.
        const term = stripQuotes(value);
        config.internalDisclosure ??= {};
        config.internalDisclosure.hashedTerms ??= [];
        config.internalDisclosure.hashedTerms.push(term);
        if (!HASHED_TERM_PATTERN.test(term)) {
          warnings.push({
            rule: "POLICY_INVALID_INTERNAL_TERM",
            message: `hashedTerms entry "${term.slice(0, 24)}" is not a sha256 digest (64 hex characters, optionally prefixed with "sha256:"); it can never match, so the deny-list entry does nothing`,
            line: lineNo,
          });
        }
      } else if (
        currentSection === "internalDisclosure" &&
        currentSubSection === "patterns"
      ) {
        const entry = stripQuotes(value);
        config.internalDisclosure ??= {};
        config.internalDisclosure.patterns ??= [];
        config.internalDisclosure.patterns.push(entry);
        const asRegex = /^\/(.+)\/([gimsuy]*)$/.exec(entry);
        if (asRegex) {
          try {
            new RegExp(asRegex[1], asRegex[2].replace(/g/g, ""));
          } catch {
            warnings.push({
              rule: "POLICY_INVALID_INTERNAL_TERM",
              message: `patterns entry "${entry.slice(0, 40)}" is not a valid regular expression; it is ignored, so the deny-list entry does nothing`,
              line: lineNo,
            });
          }
        } else if (entry.length < 3) {
          warnings.push({
            rule: "POLICY_INVALID_INTERNAL_TERM",
            message: `patterns entry "${entry}" is shorter than 3 characters; it is ignored because a literal that short matches almost every file`,
            line: lineNo,
          });
        }
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
            // Placeholder, flagged as such: a consumer that publishes the
            // reason (the SBOM VEX statements) must be able to tell this apart
            // from words the user actually wrote. Cleared by the "reason:" line
            // below when one follows. The text itself comes from the shared
            // constant, not a second literal copy: two spellings of the same
            // placeholder is how one of them quietly stops matching.
            reason: SUPPRESS_PLACEHOLDER_REASON,
            reasonPlaceholder: true,
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
      } else if (currentSection === "internalDisclosure" && k === "externalFile") {
        // Path to the UNPUBLISHED pattern file. The path itself is harmless;
        // its contents are what must never be committed.
        config.internalDisclosure ??= {};
        config.internalDisclosure.externalFile = stripQuotes(val);
      } else if (currentSection === "internalDisclosure" && k === "hashSalted") {
        // The digests above were generated with SCG_INTERNAL_HASH_SALT. Saying
        // so is what lets a missing salt be reported rather than look clean.
        config.internalDisclosure ??= {};
        config.internalDisclosure.hashSalted = /^(?:true|yes|1)$/i.test(stripQuotes(val));
      } else if (currentSection === "rules" && currentSubSection === "disable") {
        // Mapping form: `EVAL_ATOB: why this rule is off`. The list form
        // (`- EVAL_ATOB`) stays supported and is handled with the other list
        // items above; this branch is what lets a disable carry the same audit
        // trail `suppress` has required since v5.3.
        config.rules ??= {};
        config.rules.disable ??= [];
        config.rules.disable.push(k);
        const reason = stripQuotes(val);
        if (reason !== "") {
          config.rules.disableReasons ??= {};
          config.rules.disableReasons[k] = reason;
        }
      } else if (currentSection === "ignore" && currentSubSection === "") {
        // Mapping form: `"dist/**": why these files are not scanned`.
        const glob = stripQuotes(k);
        config.ignore ??= [];
        config.ignore.push(glob);
        const reason = stripQuotes(val);
        if (reason !== "") {
          config.ignoreReasons ??= {};
          config.ignoreReasons[glob] = reason;
        }
      } else if (currentSection === "suppress" && SUPPRESS_ENTRY_KEYS.has(k)) {
        // Handle suppress reason/path on inline entries. ("rule:" continuation
        // lines are tolerated; entries are created by the "- rule:" item.)
        if (k === "reason" && config.suppress?.length) {
          config.suppress[config.suppress.length - 1].reason = val;
          if (val !== "") {
            reasonProvided[config.suppress.length - 1] = true;
            config.suppress[config.suppress.length - 1].reasonPlaceholder = false;
          }
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

  // v5.29 (issue 168): `rules.disable` and `ignore` are held to the same audit
  // bar. Both remove findings from the report more completely than `suppress`
  // does - `disable` drops them before they are counted, `ignore` prunes the
  // files before any rule looks at them - so neither may be the one narrowing
  // that needs no written justification.
  for (const ruleId of config.rules?.disable ?? []) {
    if (!config.rules?.disableReasons?.[ruleId]) {
      warnings.push({
        rule: "POLICY_DISABLE_NO_REASON",
        message: `rules.disable entry "${ruleId}" has no reason; write it as "${ruleId}: <why>" so the disabled rule carries an audit trail`,
      });
    }
  }
  for (const glob of config.ignore ?? []) {
    if (!config.ignoreReasons?.[glob]) {
      warnings.push({
        rule: "POLICY_IGNORE_NO_REASON",
        message: `ignore entry "${glob}" has no reason; write it as "${glob}: <why>" so the unscanned path carries an audit trail`,
      });
    }
  }

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
  POLICY_DISABLE_NO_REASON: {
    severity: "medium",
    confidence: 1.0,
    description:
      "A rule is disabled with no documented reason. rules.disable removes that rule's findings from the report entirely - more completely than a suppression, which is at least recorded as suppressed - so an undocumented entry is an unaudited decision to stop looking, and it outlives whoever made it.",
    recommendation:
      "Write the entry as \"RULE_ID: <why>\" under rules.disable in .supply-chain-guard.yml. The bare list form (\"- RULE_ID\") still works and still disables the rule; it just cannot be audited.",
  },
  POLICY_IGNORE_NO_REASON: {
    severity: "medium",
    confidence: 1.0,
    description:
      "A path is excluded from the scan with no documented reason. ignore: prunes matching files before any rule opens them, so nothing about the excluded code reaches the report in any form - not a finding, not a suppression, not a count. An undocumented exclusion is the quietest way a scan can be narrowed.",
    recommendation:
      "Write the entry as \"<glob>: <why>\" under ignore: in .supply-chain-guard.yml. The bare list form (\"- <glob>\") still works and still excludes the path; it just cannot be audited.",
  },
  POLICY_MALFORMED_RULE_ID: {
    severity: "medium",
    confidence: 0.9,
    description:
      "Policy references a rule id that is not SCREAMING_SNAKE_CASE. The reference can never match a real rule, so the intended suppression is NOT applied - the config fails open.",
    recommendation:
      "Use the exact rule id as reported by the scanner (e.g. EVAL_ATOB) in .supply-chain-guard.yml.",
  },
  POLICY_INVALID_INTERNAL_TERM: {
    severity: "medium",
    confidence: 1.0,
    description:
      "An internalDisclosure deny-list entry cannot be compiled. The entry is ignored, so a term the project marked as internal is NOT being looked for - the config fails open in the one place where silence looks exactly like safety.",
    recommendation:
      "Generate hashed entries with \"supply-chain-guard internal-hash <term>\" and keep regex entries in the /pattern/flags form. See the Internal Disclosure section of the README.",
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
 * Describe what a loaded policy config removes from a scan (v5.29, issue 168).
 *
 * Returns undefined when the config narrows nothing, so a policy block present
 * in a report always means something was turned off, and its absence is not an
 * ambiguous "either nothing was disabled or nobody rendered it".
 *
 * Reasons come out only when they were actually written. A suppress entry the
 * parser filled with SUPPRESS_PLACEHOLDER_REASON reports no reason at all,
 * because presenting the placeholder as a justification would make an
 * unaudited suppression read as an audited one.
 */
export function describePolicyEffect(policy: PolicyConfig): PolicyEffect | undefined {
  const entry = (id: string, reason: string | undefined): PolicyEffectEntry =>
    reason !== undefined && reason !== "" ? { id, reason } : { id };

  const disabledRules = (policy.rules?.disable ?? []).map((id) =>
    entry(id, policy.rules?.disableReasons?.[id]),
  );
  const ignoredGlobs = (policy.ignore ?? []).map((glob) =>
    entry(glob, policy.ignoreReasons?.[glob]),
  );
  const suppressedRules = (policy.suppress ?? []).map((s) =>
    entry(s.rule, s.reason === SUPPRESS_PLACEHOLDER_REASON ? undefined : s.reason),
  );

  if (
    disabledRules.length === 0 &&
    ignoredGlobs.length === 0 &&
    suppressedRules.length === 0
  ) {
    return undefined;
  }

  return {
    configFile: policy.sourceFile ?? CONFIG_FILENAMES[0],
    disabledRules,
    ignoredGlobs,
    suppressedRules,
  };
}

/**
 * Apply policy to findings: disable rules, override severities,
 * suppress findings, apply allowlists.
 *
 * `suppressedFindings` (v5.29) carries the findings a `suppress:` entry
 * removed, so a consumer that has to describe the suppression can still see it.
 * They are deliberately NOT in the returned `findings`: everything downstream
 * of this function treats that array as the report, and a suppressed finding
 * leaking back into it is the v5.4.2 bug class. The array holds only
 * `suppress:`-matched findings, not the ones removed by `rules.disable`,
 * allowlists or the baseline, because only a `suppress:` entry carries a
 * documented reason to publish.
 */
export function applyPolicy(
  findings: Finding[],
  policy: PolicyConfig,
): { findings: Finding[]; suppressedCount: number; suppressedFindings: Finding[] } {
  let suppressedCount = 0;
  const suppressedFindings: Finding[] = [];
  const disabledRules = new Set(policy.rules?.disable ?? []);
  const severityOverrides = policy.rules?.severityOverrides ?? {};
  const suppressEntries = policy.suppress ?? [];
  const allowedPackages = new Set(policy.allowlist?.packages ?? []);
  const allowedDomains = policy.allowlist?.domains ?? [];
  const allowedOrgs = new Set(
    (policy.allowlist?.githubOrgs ?? [])
      .map((o) => o.trim().toLowerCase())
      .filter((o) => o !== ""),
  );

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
      // Quote the reason only when the user wrote one. The parser fills in a
      // placeholder so later code always has a string, so `reason` being
      // non-empty proves nothing on its own.
      const declaredReason = suppressMatch.reasonPlaceholder
        ? ""
        : (suppressMatch.reason ?? "").trim();
      if (declaredReason !== "") finding.suppressionReason = declaredReason;
      suppressedFindings.push(finding);
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

    // TYPOSQUAT_SIMILAR_TO_DEP names TWO packages, and either may be the one the
    // user considers legitimate, so allowlisting either side suppresses the pair.
    // Without this the rule had no per-package escape at all: a project depending
    // on both vue and vuex could only silence it by disabling the rule outright.
    if (finding.rule === "TYPOSQUAT_SIMILAR_TO_DEP") {
      const named = [...finding.description.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
      if (named.some((pkg) => allowedPackages.has(pkg))) {
        suppressedCount++;
        continue;
      }
    }

    // Allowlisted domains also answer the host-shaped internal-disclosure
    // rules: a project that has decided a given domain may appear in its
    // repository has answered INTERNAL_HOSTNAME / INTERNAL_SERVICE_ENDPOINT /
    // INTERNAL_GIT_REMOTE for that host. Note the tradeoff, which the README
    // spells out: naming the domain here publishes it. The leak-free
    // alternative is a path-scoped `suppress` entry, which names no host.
    if (allowedDomains.length > 0 && HOST_ATTRIBUTED_INTERNAL_RULES.has(finding.rule)) {
      const host = extractFindingHost(finding);
      if (host && isDomainAllowlisted(host, allowedDomains)) {
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

    // Allowlisted GitHub orgs: drop OWNERSHIP-trust findings whose action is
    // owned by a trusted org. Only these two rules are attributable to an
    // owner, and both already carry the `owner/repo@ref` reference in `match`.
    // Pinning hygiene and known-malicious-SHA rules are deliberately NOT
    // covered: trusting an org says who publishes the code, not that any
    // version of it is safe.
    if (allowedOrgs.size > 0 && ORG_ATTRIBUTED_RULES.has(finding.rule)) {
      const owner = extractFindingActionOwner(finding);
      if (owner && allowedOrgs.has(owner.toLowerCase())) {
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

  return { findings: result, suppressedCount, suppressedFindings };
}

/**
 * Findings that name a GitHub owner and are about TRUST IN THAT OWNER, so an
 * `allowlist.githubOrgs` entry can legitimately answer them (v5.18). Before
 * this, the key was parsed, documented and schema-validated but never read by
 * applyPolicy() - the same silent no-op that v5.3's fail-closed philosophy
 * exists to prevent (and that `allowlist.domains` was fixed for in v5.13).
 */
const ORG_ATTRIBUTED_RULES = new Set(["GHA_THIRD_PARTY_ACTION", "GHA_TAG_NOT_SHA"]);

/**
 * Internal-disclosure findings whose match names a HOST, so an
 * `allowlist.domains` entry can legitimately answer them. The address and
 * developer-path rules are deliberately absent: an allowlist of domains says
 * nothing about whether a private address or a home directory belongs in a
 * published repository.
 */
const HOST_ATTRIBUTED_INTERNAL_RULES = new Set([
  "INTERNAL_HOSTNAME",
  "INTERNAL_SERVICE_ENDPOINT",
  "INTERNAL_GIT_REMOTE",
]);

/**
 * Extract the host from an internal-disclosure finding. The `match` holds the
 * raw matched text: a bare hostname, a URL, or an scp-style git remote.
 */
function extractFindingHost(finding: Finding): string | undefined {
  const raw = finding.match?.trim();
  if (!raw) return undefined;

  // scp-style remote: a user, an "@", the host, a colon, then the path
  const scp = /^[\w.%+-]+@([A-Za-z0-9.-]+):/.exec(raw);
  if (scp) return scp[1];

  // URL (any scheme), with optional userinfo and port
  const url = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/(?:[^@/\s]+@)?([A-Za-z0-9.-]+)/.exec(raw);
  if (url) return url[1];

  // Bare hostname
  return /^[A-Za-z0-9.-]+$/.test(raw) ? raw : undefined;
}

/**
 * Extract the GitHub owner from an action-reference finding. Both rules put the
 * full `owner/repo@ref` in `match`; the description is the fallback.
 */
function extractFindingActionOwner(finding: Finding): string | undefined {
  const ref = finding.match?.trim() ?? finding.description.match(/"([^"]+\/[^"]+)"/)?.[1];
  if (!ref) return undefined;
  const owner = ref.split("/")[0]?.trim();
  return owner && /^[A-Za-z0-9][A-Za-z0-9-]*$/.test(owner) ? owner : undefined;
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
