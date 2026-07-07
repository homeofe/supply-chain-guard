/**
 * Cross-workflow trust-boundary analysis (v5.7) - the core "Cordyceps" detection.
 *
 * Every other GitHub Actions check in this tool looks at ONE file at a time.
 * That is structurally blind to the composition attack novee.security described
 * in 2026: a low-privilege, PR-triggered PRODUCER workflow uploads an artifact
 * (whose contents an anonymous contributor controls), and a privileged,
 * `workflow_run`-triggered CONSUMER workflow downloads - and often executes -
 * that artifact WITH secrets and a read/write GITHUB_TOKEN in scope. Neither
 * file is individually wrong; the vulnerability lives in how they connect.
 *
 * This pass models the producer -> consumer graph across all workflow files and
 * flags that trust-boundary crossing.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";
import { parseWorkflow, type WorkflowAst, type WfStep } from "./workflow-ast.js";

/** Triggers an anonymous contributor can fire, populating artifact contents. */
const UNTRUSTED_PRODUCER_TRIGGERS = ["pull_request", "pull_request_target"];

/**
 * A consumer step that RETRIEVES an artifact - not only via actions/download-artifact,
 * but also the `gh` CLI or actions/github-script, which is how cross-run downloads
 * (workflow_run) are commonly done. Missing these = missing the exact attack class.
 */
const DOWNLOAD_RUN_RE = /\bgh\s+run\s+download\b|\bgh\s+api\b[^\n]*artifacts|\bdownload-artifact\b/i;
const DOWNLOAD_SCRIPT_RE = /listWorkflowRunArtifacts|\.getArtifact\b|downloadArtifact/;

/**
 * A checked-in repo script or build wrapper - running one of THESE is not
 * "executing the downloaded artifact", so it must not inflate severity.
 */
const IN_REPO_EXEC_RE =
  /^(?:\.\/)?(?:scripts?|src|lib|test|tests|spec|\.github|bin|tools|ci)\/|^(?:\.\/)?(?:gradlew|mvnw)$/i;

/**
 * True if a run step executes downloaded content (not merely a checked-in repo
 * script, a build wrapper, or an interpreter flag). Conservative on purpose so
 * the common download-and-report pattern is not mislabelled as "executes it".
 */
function runExecutesDownloaded(run: string): boolean {
  const re = /\bchmod\s+\+x\b|\b(?:bash|sh|zsh|node|python[0-9.]*|ruby|perl)\s+(\S+)|(?:^|\s)(\.\/\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(run)) !== null) {
    const target = (m[1] || m[2] || "").replace(/^['"]|['"]$/g, "");
    if (target === "") return true;             // chmod +x <target>
    if (target.startsWith("-")) continue;       // interpreter flag (node -e, python -m)
    if (IN_REPO_EXEC_RE.test(target)) continue; // checked-in script / build wrapper
    return true;
  }
  return false;
}

interface WorkflowRecord {
  file: string;          // relative path, e.g. .github/workflows/ci.yml
  basename: string;      // e.g. ci.yml
  ast: WorkflowAst;
  uploadsArtifact: boolean;
  uploadNames: string[];
  downloadsArtifact: boolean;
  downloadNames: string[];
  executesDownloaded: boolean;
}

function stepIsUpload(s: WfStep): boolean {
  return !!s.uses && /upload-artifact/i.test(s.uses);
}
function stepIsDownload(s: WfStep): boolean {
  if (s.uses && /download-artifact/i.test(s.uses)) return true;
  if (s.run && DOWNLOAD_RUN_RE.test(s.run)) return true;
  if (s.withScript && DOWNLOAD_SCRIPT_RE.test(s.withScript)) return true;
  return false;
}

function buildRecord(file: string, basename: string, content: string): WorkflowRecord {
  const ast = parseWorkflow(content);
  const steps = ast.jobs.flatMap((j) => j.steps);

  const uploads = steps.filter(stepIsUpload);
  const downloads = steps.filter(stepIsDownload);
  const executesDownloaded = steps.some((s) => s.run != null && runExecutesDownloaded(s.run));

  return {
    file,
    basename,
    ast,
    uploadsArtifact: uploads.length > 0,
    uploadNames: uploads.map((s) => s.withName).filter((n): n is string => !!n),
    downloadsArtifact: downloads.length > 0,
    downloadNames: downloads.map((s) => s.withName).filter((n): n is string => !!n),
    executesDownloaded,
  };
}

function isUntrustedProducer(rec: WorkflowRecord): boolean {
  return rec.uploadsArtifact &&
    rec.ast.triggers.some((t) => UNTRUSTED_PRODUCER_TRIGGERS.includes(t));
}

/**
 * Given a workflow_run consumer, return the untrusted producers it chains from.
 * If the consumer names producers via `workflows:`, match on the producer's
 * display `name:`; otherwise (an unfiltered workflow_run) consider every
 * untrusted producer in the repo.
 */
function matchProducers(
  consumer: WorkflowRecord,
  producers: WorkflowRecord[],
): WorkflowRecord[] {
  const names = consumer.ast.workflowRunWorkflows;
  if (names.length === 0) return producers;
  return producers.filter((p) => p.ast.name != null && names.includes(p.ast.name));
}

/** Does the consumer download an artifact that a producer actually uploads? */
function artifactNamesOverlap(consumer: WorkflowRecord, producer: WorkflowRecord): boolean {
  // A nameless download pulls every artifact from the run, so it matches any upload.
  if (consumer.downloadNames.length === 0) return true;
  if (producer.uploadNames.length === 0) return true;
  return consumer.downloadNames.some((n) => producer.uploadNames.includes(n));
}

export function scanWorkflowGraph(dir: string): Finding[] {
  const findings: Finding[] = [];
  const workflowDir = path.join(dir, ".github", "workflows");
  if (!fs.existsSync(workflowDir)) return findings;

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(workflowDir, { withFileTypes: true });
  } catch {
    return findings;
  }

  const records: WorkflowRecord[] = [];
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const ext = path.extname(entry.name).toLowerCase();
    if (ext !== ".yml" && ext !== ".yaml") continue;
    const filePath = path.join(workflowDir, entry.name);
    const relativePath = path.join(".github", "workflows", entry.name);
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      records.push(buildRecord(relativePath, entry.name, content));
    } catch {
      // skip unreadable
    }
  }

  const producers = records.filter(isUntrustedProducer);
  if (producers.length === 0) return findings;

  const consumers = records.filter(
    (r) => r.ast.triggers.includes("workflow_run") && r.downloadsArtifact,
  );

  for (const consumer of consumers) {
    const matched = matchProducers(consumer, producers).filter((p) =>
      artifactNamesOverlap(consumer, p),
    );
    if (matched.length === 0) continue;

    const producerLabel = matched
      .map((p) => p.ast.name ?? p.basename)
      .join(", ");
    const critical = consumer.executesDownloaded;

    findings.push({
      rule: "GHA_CROSS_WORKFLOW_ARTIFACT_TRUST",
      description:
        `Privileged workflow "${consumer.basename}" (triggered by workflow_run) downloads an artifact ` +
        `produced by the untrusted PR workflow "${producerLabel}"` +
        (critical
          ? ` and runs downloaded content (a shell/interpreter step on a non-repo path) with secrets and a read/write token in scope. `
          : ` and consumes it with secrets and a read/write token in scope (residual risk: path traversal / zip-slip / trusting attacker data). `) +
        `An anonymous contributor controls that artifact's contents, so this is a cross-workflow ` +
        `privilege escalation (the Cordyceps composition pattern) that single-file scanners miss.`,
      severity: critical ? "critical" : "medium",
      file: consumer.file,
      confidence: critical ? 0.85 : 0.55,
      category: "supply-chain",
      recommendation:
        "Do not consume PR-produced artifacts in a privileged workflow_run workflow. Treat downloaded " +
        "artifacts as untrusted input: never execute them, and validate/scope their use. If you must relay " +
        "PR build output (e.g. to comment on a PR), do it without secrets and without running the content. " +
        "Add provenance (actions/attest-build-provenance) and pin the producing workflow.",
    });
  }

  return findings;
}
