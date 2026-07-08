/**
 * Zero-dependency structural parser for GitHub Actions workflow files (v5.7).
 *
 * The legacy github-actions-scanner.ts matches regexes line-by-line and never
 * understands a workflow's STRUCTURE - which trigger fires it, what permissions
 * its token carries, or which step checks out / uploads / downloads what. That
 * blindness is exactly why the "Cordyceps" class of composition attacks
 * (novee.security, 2026) stays green on single-file scanners: no individual
 * line is wrong, the danger is in how the pieces connect.
 *
 * This parser extracts just enough structure to reason about triggers and data
 * flow, WITHOUT taking on a full YAML dependency (which would itself add
 * supply-chain surface to a supply-chain tool). It is intentionally scoped to
 * the shapes real workflows use: `on:` (scalar / flow-list / block), top-level
 * and per-job `permissions:`, and `jobs -> steps` with each step's
 * `uses` / `run` / `with.ref` / `with.script` / `with.name`.
 */

export interface WfPermissions {
  /** true when a `permissions:` key is present at this scope */
  declared: boolean;
  /** `permissions: write-all` */
  writeAll: boolean;
  /** `permissions: read-all` or `permissions: {}` */
  readAll: boolean;
  /** individual scope -> access level, e.g. { contents: "write", "id-token": "write" } */
  scopes: Record<string, string>;
}

export interface WfStep {
  /** 1-based line of the step's first line */
  line: number;
  uses?: string;
  run?: string;
  withRef?: string;
  withScript?: string;
  withName?: string;
  /** agent prompt text from with.prompt / direct_prompt / override_prompt / user_prompt (joined) */
  withPrompt?: string;
  /** token handed to the step via with.github_token / gh_token / token */
  withToken?: string;
  /** step-level `env:` map (raw values, expressions preserved) */
  env?: Record<string, string>;
}

export interface WfJob {
  id: string;
  line: number;
  permissions: WfPermissions;
  steps: WfStep[];
}

export interface WorkflowAst {
  /** the workflow's display name (`name:`), used to match `workflow_run.workflows` */
  name?: string;
  /** event names under `on:` (e.g. ["pull_request_target", "workflow_run"]) */
  triggers: string[];
  /** names listed under `on.workflow_run.workflows` (the producer workflows) */
  workflowRunWorkflows: string[];
  /** top-level token permissions */
  permissions: WfPermissions;
  jobs: WfJob[];
}

// ---------------------------------------------------------------------------
// Low-level line helpers
// ---------------------------------------------------------------------------

function indentOf(line: string): number {
  let n = 0;
  while (n < line.length && line[n] === " ") n++;
  return n;
}

/**
 * Strip a trailing YAML comment. A `#` that starts a comment must be at the
 * start of the line or preceded by whitespace, and must not be inside a quoted
 * string. (Mirrors the scanner's stripYamlComment.)
 */
function stripComment(line: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let j = 0; j < line.length; j++) {
    const ch = line[j];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === "#" && !inSingle && !inDouble) {
      if (j === 0 || /\s/.test(line[j - 1]!)) return line.slice(0, j);
    }
  }
  return line;
}

function stripQuotes(v: string): string {
  const t = v.trim();
  if ((t.startsWith('"') && t.endsWith('"') && t.length >= 2) ||
      (t.startsWith("'") && t.endsWith("'") && t.length >= 2)) {
    return t.slice(1, -1);
  }
  return t;
}

// A block scalar header: `key: |` / `key: >` with optional chomping (`+`/`-`)
// and/or an explicit indentation indicator digit (`|2`, `>4`, `|2+`, `|+2`).
const BLOCK_SCALAR_RE = /:\s*[|>][0-9+-]*\s*$/;

/**
 * Mark every line that is the body of a block scalar (`key: |` / `key: >`), so
 * structural scans do not mis-read arbitrary shell/JS text (which may contain
 * `- ` or `#` or `key:` shapes) as YAML structure.
 */
function computeBlockInner(lines: string[]): boolean[] {
  const inner = new Array<boolean>(lines.length).fill(false);
  let i = 0;
  while (i < lines.length) {
    const raw = lines[i]!;
    const s = stripComment(raw);
    if (s.trim() === "") { i++; continue; }
    if (BLOCK_SCALAR_RE.test(s)) {
      const base = indentOf(raw);
      let j = i + 1;
      while (j < lines.length) {
        if (lines[j]!.trim() === "") { inner[j] = true; j++; continue; }
        if (indentOf(lines[j]!) > base) { inner[j] = true; j++; }
        else break;
      }
      i = j;
    } else {
      i++;
    }
  }
  return inner;
}

/** Parse a `key: value` (or `key:`) shape. Returns null when there is no key. */
function parseKeyValue(text: string): { key: string; value: string | null } | null {
  const m = /^([^\s:][^:]*):(?:\s+(.*))?$/.exec(text);
  if (!m) return null;
  const value = m[2] !== undefined && m[2] !== "" ? m[2].trim() : null;
  // Strip quotes so a quoted key (`"on":`, dodging YAML 1.1 boolean coercion)
  // compares equal to its bare form everywhere downstream.
  return { key: stripQuotes(m[1]!.trim()), value };
}

/** Parse a `[a, b, c]` flow list into trimmed, unquoted items. */
function parseFlowList(value: string): string[] {
  const t = value.trim();
  if (!t.startsWith("[")) return [];
  const inner = t.replace(/^\[/, "").replace(/\]$/, "");
  if (inner.trim() === "") return [];
  return inner.split(",").map((s) => stripQuotes(s)).filter((s) => s !== "");
}

/**
 * Parse the TOP-LEVEL keys of a flow map like `{ issues: { types: [opened] },
 * pull_request: null }` into `["issues", "pull_request"]`. Respects nested
 * braces/brackets so a nested config value is not mistaken for a key. Used for
 * the compact `on: { ... }` trigger form (and gh-aw frontmatter).
 */
function parseFlowMapKeys(value: string): string[] {
  const t = value.trim();
  if (!t.startsWith("{")) return [];
  const inner = t.slice(1, t.endsWith("}") ? -1 : undefined);
  const segments: string[] = [];
  let seg = "";
  let depth = 0;
  for (const ch of inner) {
    if (ch === "{" || ch === "[") depth++;
    else if (ch === "}" || ch === "]") depth--;
    if (ch === "," && depth === 0) { segments.push(seg); seg = ""; }
    else seg += ch;
  }
  if (seg.trim() !== "") segments.push(seg);

  const keys: string[] = [];
  for (const s of segments) {
    const colon = s.indexOf(":");
    const key = stripQuotes((colon === -1 ? s : s.slice(0, colon)).trim());
    if (key) keys.push(key);
  }
  return keys;
}

/**
 * Collect the body line indices of a block: all lines after headerIndex whose
 * indent is greater than headerIndent, stopping at the first line (ignoring
 * blanks) whose indent is <= headerIndent.
 */
function blockBody(lines: string[], headerIndex: number, headerIndent: number): number[] {
  const body: number[] = [];
  for (let j = headerIndex + 1; j < lines.length; j++) {
    // Blank OR comment-only lines are transparent: they neither belong to the
    // block nor terminate it. (A misindented comment must not corrupt the
    // block's child-indent inference or truncate its body.)
    if (stripComment(lines[j]!).trim() === "") continue;
    if (indentOf(lines[j]!) > headerIndent) body.push(j);
    else break;
  }
  return body;
}

function emptyPermissions(): WfPermissions {
  return { declared: false, writeAll: false, readAll: false, scopes: {} };
}

/**
 * Parse a `permissions:` header line plus its (possible) block body.
 * `headerValue` is whatever followed `permissions:` on the same line.
 */
function parsePermissions(
  lines: string[],
  headerIndex: number,
  headerIndent: number,
  headerValue: string | null,
): WfPermissions {
  const perms = emptyPermissions();
  perms.declared = true;

  if (headerValue) {
    // Strip a leading YAML anchor (`permissions: &perms write-all`).
    const v = headerValue.trim().replace(/^&\S+\s*/, "");
    if (v === "") {
      // header was only an anchor: fall through to read the block body below
    } else if (v === "write-all") {
      perms.writeAll = true;
      return perms;
    } else if (v === "read-all" || v === "{}") {
      perms.readAll = true;
      return perms;
    } else if (v.startsWith("{")) {
      // Inline flow map: { contents: write, id-token: write }
      const innerMap = v.replace(/^\{/, "").replace(/\}$/, "");
      for (const pair of innerMap.split(",")) {
        const idx = pair.indexOf(":");
        if (idx === -1) continue;
        const key = stripQuotes(pair.slice(0, idx).trim());
        const val = stripQuotes(pair.slice(idx + 1).trim());
        if (key && val) perms.scopes[key] = val;
      }
      return perms;
    } else {
      // Unrecognized inline scalar/alias (e.g. *anchor): declared, scopes unknown.
      return perms;
    }
  }

  for (const j of blockBody(lines, headerIndex, headerIndent)) {
    const kv = parseKeyValue(stripComment(lines[j]!).trim());
    if (kv && kv.value) perms.scopes[kv.key] = stripQuotes(kv.value);
  }
  return perms;
}

// ---------------------------------------------------------------------------
// Section parsers
// ---------------------------------------------------------------------------

function parseOn(
  lines: string[],
  headerIndex: number,
  headerValue: string | null,
): { triggers: string[]; workflowRunWorkflows: string[] } {
  const triggers: string[] = [];
  const workflowRunWorkflows: string[] = [];

  if (headerValue) {
    const v = headerValue.trim();
    if (v.startsWith("[")) {
      triggers.push(...parseFlowList(v));
    } else if (v.startsWith("{")) {
      triggers.push(...parseFlowMapKeys(v));
    } else {
      triggers.push(v);
    }
    return { triggers, workflowRunWorkflows };
  }

  // Block form: children at the shallowest child indent are trigger names.
  // (blockBody already excludes comments, so the min is over real keys.)
  const body = blockBody(lines, headerIndex, indentOf(lines[headerIndex]!));
  if (body.length === 0) return { triggers, workflowRunWorkflows };
  const childIndent = Math.min(...body.map((j) => indentOf(lines[j]!)));

  for (const j of body) {
    if (indentOf(lines[j]!) !== childIndent) continue;
    const kv = parseKeyValue(stripComment(lines[j]!).trim());
    if (!kv) continue;
    triggers.push(kv.key);
    if (kv.key === "workflow_run") {
      workflowRunWorkflows.push(...parseWorkflowRunWorkflows(lines, j, childIndent));
    }
  }
  return { triggers, workflowRunWorkflows };
}

function parseWorkflowRunWorkflows(
  lines: string[],
  workflowRunIndex: number,
  workflowRunIndent: number,
): string[] {
  const result: string[] = [];
  const body = blockBody(lines, workflowRunIndex, workflowRunIndent);
  for (let k = 0; k < body.length; k++) {
    const j = body[k]!;
    const kv = parseKeyValue(stripComment(lines[j]!).trim());
    if (kv && kv.key === "workflows") {
      if (kv.value) {
        result.push(...parseFlowList(kv.value));
      } else {
        // block list: subsequent `- name` items indented under `workflows:`
        for (const jj of blockBody(lines, j, indentOf(lines[j]!))) {
          const t = stripComment(lines[jj]!).trim();
          if (t.startsWith("- ")) result.push(stripQuotes(t.slice(2)));
        }
      }
      break;
    }
  }
  return result;
}

function parseJobs(lines: string[], jobsIndex: number, inner: boolean[]): WfJob[] {
  const jobs: WfJob[] = [];
  const jobsIndent = indentOf(lines[jobsIndex]!);
  const body = blockBody(lines, jobsIndex, jobsIndent);
  if (body.length === 0) return jobs;

  // Job ids are the shallowest keys inside the jobs block.
  const jobIndent = Math.min(...body.filter((j) => !inner[j]).map((j) => indentOf(lines[j]!)));

  for (let idx = 0; idx < body.length; idx++) {
    const j = body[idx]!;
    if (inner[j]) continue;
    if (indentOf(lines[j]!) !== jobIndent) continue;
    const kv = parseKeyValue(stripComment(lines[j]!).trim());
    if (!kv) continue;

    jobs.push(parseJob(lines, j, jobIndent, kv.key, inner));
  }
  return jobs;
}

function parseJob(
  lines: string[],
  jobIndex: number,
  jobIndent: number,
  jobId: string,
  inner: boolean[],
): WfJob {
  const job: WfJob = {
    id: jobId,
    line: jobIndex + 1,
    permissions: emptyPermissions(),
    steps: [],
  };

  const body = blockBody(lines, jobIndex, jobIndent);
  const jobChildIndent = body.length
    ? Math.min(...body.filter((j) => !inner[j]).map((j) => indentOf(lines[j]!)))
    : jobIndent + 2;

  for (const j of body) {
    if (inner[j]) continue;
    if (indentOf(lines[j]!) !== jobChildIndent) continue;
    const kv = parseKeyValue(stripComment(lines[j]!).trim());
    if (!kv) continue;

    if (kv.key === "permissions") {
      job.permissions = parsePermissions(lines, j, jobChildIndent, kv.value);
    } else if (kv.key === "steps") {
      job.steps = parseSteps(lines, j, jobChildIndent, inner);
    }
  }
  return job;
}

function parseSteps(
  lines: string[],
  stepsIndex: number,
  stepsIndent: number,
  inner: boolean[],
): WfStep[] {
  const steps: WfStep[] = [];
  const body = blockBody(lines, stepsIndex, stepsIndent);
  if (body.length === 0) return steps;

  // Step boundaries are the list markers at the shallowest indent. A bare
  // dash on its own line (`-`) is a valid step start too, not just `- key:`.
  const isDashLine = (j: number): boolean => {
    const t = stripComment(lines[j]!).trim();
    return t === "-" || t.startsWith("- ");
  };
  const dashLines = body.filter((j) => !inner[j] && isDashLine(j));
  if (dashLines.length === 0) return steps;
  const stepIndent = Math.min(...dashLines.map((j) => indentOf(lines[j]!)));

  const starts = dashLines.filter((j) => indentOf(lines[j]!) === stepIndent);
  for (let s = 0; s < starts.length; s++) {
    const start = starts[s]!;
    const end = s + 1 < starts.length ? starts[s + 1]! : (body[body.length - 1]! + 1);
    steps.push(parseStep(lines, start, end, stepIndent, inner));
  }
  return steps;
}

function parseStep(
  lines: string[],
  startIndex: number,
  endIndex: number,
  stepIndent: number,
  inner: boolean[],
): WfStep {
  const step: WfStep = { line: startIndex + 1 };

  const assign = (key: string, value: string | null, lineIdx: number, keyIndent: number) => {
    if (key === "uses" && value) step.uses = stripQuotes(value);
    else if (key === "run") step.run = readScalarOrBlock(lines, lineIdx, keyIndent, value);
    else if (key === "with") parseWith(lines, lineIdx, keyIndent, inner, step);
    else if (key === "env") step.env = parseEnvBlock(lines, lineIdx, keyIndent, inner);
  };

  // The first line is `- <key>: <value>`, or a bare `-` with the mapping keys
  // on the following indented lines. Determine the step's mapping indent.
  const firstTrimmed = stripComment(lines[startIndex]!).trim();
  const afterDash = firstTrimmed.replace(/^-\s*/, "");
  let mapIndent: number;
  if (afterDash === "") {
    // Bare dash: the mapping indent is the indent of the first child line.
    mapIndent = -1;
    for (let j = startIndex + 1; j < endIndex; j++) {
      if (inner[j]) continue;
      if (stripComment(lines[j]!).trim() === "") continue;
      mapIndent = indentOf(lines[j]!);
      break;
    }
    if (mapIndent < 0) return step;
  } else {
    mapIndent = stepIndent + (firstTrimmed.length - afterDash.length);
    const firstKv = parseKeyValue(afterDash);
    if (firstKv) assign(firstKv.key, firstKv.value, startIndex, mapIndent);
  }

  // Remaining lines of the step: sibling keys of the step map are at mapIndent.
  for (let j = startIndex + 1; j < endIndex; j++) {
    if (inner[j]) continue;
    if (stripComment(lines[j]!).trim() === "") continue;
    if (indentOf(lines[j]!) !== mapIndent) continue;
    const kv = parseKeyValue(stripComment(lines[j]!).trim());
    if (kv) assign(kv.key, kv.value, j, mapIndent);
  }
  return step;
}

function parseWith(
  lines: string[],
  withIndex: number,
  withIndent: number,
  inner: boolean[],
  step: WfStep,
): void {
  const body = blockBody(lines, withIndex, withIndent);
  if (body.length === 0) return;
  const withChildIndent = Math.min(
    ...body.filter((j) => !inner[j]).map((j) => indentOf(lines[j]!)),
  );
  for (const j of body) {
    if (inner[j]) continue;
    if (indentOf(lines[j]!) !== withChildIndent) continue;
    const kv = parseKeyValue(stripComment(lines[j]!).trim());
    if (!kv) continue;
    if (kv.key === "ref" && kv.value) step.withRef = stripQuotes(kv.value);
    else if (kv.key === "name" && kv.value) step.withName = stripQuotes(kv.value);
    else if (kv.key === "script") step.withScript = readScalarOrBlock(lines, j, withChildIndent, kv.value);
    else if (
      (kv.key === "prompt" || kv.key === "direct_prompt" ||
       kv.key === "override_prompt" || kv.key === "user_prompt") && kv.value !== null
    ) {
      const val = readScalarOrBlock(lines, j, withChildIndent, kv.value);
      step.withPrompt = step.withPrompt ? `${step.withPrompt}\n${val}` : val;
    } else if (
      (kv.key === "github_token" || kv.key === "gh_token" || kv.key === "token") && kv.value
    ) {
      step.withToken = stripQuotes(kv.value);
    }
  }
}

/**
 * Parse a step-level `env:` block into a name -> raw-value map. Expression
 * syntax (`${{ secrets.X }}`) is preserved verbatim so downstream rules can
 * reason about which secret a token comes from.
 */
function parseEnvBlock(
  lines: string[],
  envIndex: number,
  envIndent: number,
  inner: boolean[],
): Record<string, string> {
  const env: Record<string, string> = {};
  const body = blockBody(lines, envIndex, envIndent);
  if (body.length === 0) return env;
  const childIndent = Math.min(
    ...body.filter((j) => !inner[j]).map((j) => indentOf(lines[j]!)),
  );
  for (const j of body) {
    if (inner[j]) continue;
    if (indentOf(lines[j]!) !== childIndent) continue;
    const kv = parseKeyValue(stripComment(lines[j]!).trim());
    if (kv && kv.value !== null) env[kv.key] = stripQuotes(kv.value);
  }
  return env;
}

/**
 * Read a value that may be inline (`key: value`) or a block scalar
 * (`key: |` followed by an indented body). Block bodies are joined with "\n".
 */
function readScalarOrBlock(
  lines: string[],
  keyIndex: number,
  keyIndent: number,
  inlineValue: string | null,
): string {
  if (inlineValue && !/^[|>][0-9+-]*$/.test(inlineValue.trim())) {
    return stripQuotes(inlineValue);
  }
  const body: string[] = [];
  for (let j = keyIndex + 1; j < lines.length; j++) {
    if (lines[j]!.trim() === "") { body.push(""); continue; }
    if (indentOf(lines[j]!) > keyIndent) body.push(lines[j]!.trim());
    else break;
  }
  return body.join("\n").trim();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export function parseWorkflow(content: string): WorkflowAst {
  const lines = content.replace(/\r/g, "").split("\n");
  const inner = computeBlockInner(lines);

  const ast: WorkflowAst = {
    triggers: [],
    workflowRunWorkflows: [],
    permissions: emptyPermissions(),
    jobs: [],
  };

  for (let i = 0; i < lines.length; i++) {
    if (inner[i]) continue;
    if (lines[i]!.trim() === "") continue;
    if (indentOf(lines[i]!) !== 0) continue;
    const kv = parseKeyValue(stripComment(lines[i]!).trim());
    if (!kv) continue;

    switch (kv.key) {
      case "name":
        if (kv.value) ast.name = stripQuotes(kv.value);
        break;
      case "on": {
        const { triggers, workflowRunWorkflows } = parseOn(lines, i, kv.value);
        ast.triggers = triggers;
        ast.workflowRunWorkflows = workflowRunWorkflows;
        break;
      }
      case "permissions":
        ast.permissions = parsePermissions(lines, i, 0, kv.value);
        break;
      case "jobs":
        ast.jobs = parseJobs(lines, i, inner);
        break;
    }
  }

  return ast;
}
