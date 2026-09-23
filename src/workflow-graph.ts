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
import { parseWorkflow, type WorkflowAst, type WfJob, type WfStep } from "./workflow-ast.js";

/** Triggers an anonymous contributor can fire, populating artifact contents. */
const UNTRUSTED_PRODUCER_TRIGGERS = ["pull_request", "pull_request_target"];

/**
 * A consumer step that RETRIEVES an artifact - not only via actions/download-artifact,
 * but also the `gh` CLI or actions/github-script, which is how cross-run downloads
 * (workflow_run) are commonly done. Missing these = missing the exact attack class.
 */
const DOWNLOAD_RUN_RE = /\bgh\s+run\s+download\b|\bgh\s+api\b[^\n]*artifacts|\bdownload-artifact\b/i;
// listWorkflowRunArtifacts alone only returns metadata, so it is not a
// download; fetching the archive URL it returns is.
const DOWNLOAD_SCRIPT_RE = /\.getArtifact\b|downloadArtifact|archive_download_url/;

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

/**
 * ONE download step. Findings are tracked per step, not per job: a job may
 * download several artifacts, and only some of them come from an untrusted
 * producer. Anchoring every finding on the job's FIRST download would put the
 * `scg-ignore-next-line` target on the wrong line, so a directive above an
 * unrelated first download would suppress a later, genuinely risky one - and a
 * directive above the matched download would do nothing.
 */
interface DownloadStep {
  /** 1-based line of this download step - anchors the Finding so
   *  scg-ignore-next-line lands on the step that actually matched. */
  line: number;
  /** artifact name this step pulls, or null for a nameless download (which
   *  pulls every artifact in the run and therefore matches any upload). */
  name: string | null;
}

/**
 * A single job's artifact posture, scoped to THAT job's own steps only.
 * Severity must not leak across unrelated jobs: a job with a different trigger
 * context and a different trust boundary executing a shell script has no
 * bearing on whether the artifact THIS job downloads is then executed.
 *
 * `uploadNames` and `needs` are carried because scoping alone is not enough:
 * an artifact can be RELAYED. A consumer job may download the PR-produced
 * artifact, re-upload it under a fresh name, and a dependent job may then
 * download and execute that relay. Scoping without following the relay would
 * turn the old file-wide false positive into a silent false negative, which is
 * the more expensive direction for a security rule.
 */
interface JobPosture {
  id: string;
  needs: string[];
  downloads: DownloadStep[];
  hasUpload: boolean;
  uploadNames: string[];
  executesDownloaded: boolean;
}

interface WorkflowRecord {
  file: string;          // relative path, e.g. .github/workflows/ci.yml
  basename: string;      // e.g. ci.yml
  ast: WorkflowAst;
  uploadsArtifact: boolean;
  uploadNames: string[];
  jobs: JobPosture[];
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

function buildJobPosture(job: WfJob): JobPosture {
  const jobUploads = job.steps.filter(stepIsUpload);
  return {
    id: job.id,
    needs: job.needs,
    downloads: job.steps.filter(stepIsDownload).map((s) => ({
      line: s.line,
      name: s.withName ?? null,
    })),
    hasUpload: jobUploads.length > 0,
    uploadNames: jobUploads.map((s) => s.withName).filter((n): n is string => !!n),
    executesDownloaded: job.steps.some((s) => s.run != null && runExecutesDownloaded(s.run)),
  };
}

function buildRecord(file: string, basename: string, content: string): WorkflowRecord {
  const ast = parseWorkflow(content);
  const uploads = ast.jobs.flatMap((j) => j.steps).filter(stepIsUpload);

  return {
    file,
    basename,
    ast,
    uploadsArtifact: uploads.length > 0,
    uploadNames: uploads.map((s) => s.withName).filter((n): n is string => !!n),
    jobs: ast.jobs.map(buildJobPosture),
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

/**
 * Does one download step pull an artifact from this set of upload names?
 *
 * Both open cases are deliberately permissive, because the cost of missing a
 * real chain is higher than the cost of one over-broad medium finding:
 *   - a nameless download pulls EVERY artifact in the run, so it matches anything;
 *   - an upload whose name we could not resolve could be any name.
 */
function downloadMatchesUploads(name: string | null, uploadNames: string[]): boolean {
  if (name === null) return true;
  if (uploadNames.length === 0) return true;
  return uploadNames.includes(name);
}

/**
 * Jobs reachable from `startId` by following `needs` edges FORWARD, i.e. every
 * job that runs after it and can therefore consume what it uploaded. Includes
 * the start job itself.
 */
function dependentClosure(jobs: JobPosture[], startId: string): Set<string> {
  const seen = new Set<string>([startId]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const j of jobs) {
      if (seen.has(j.id)) continue;
      if (j.needs.some((n) => seen.has(n))) {
        seen.add(j.id);
        grew = true;
      }
    }
  }
  return seen;
}

/**
 * Starting from the job that downloads the untrusted artifact, does anything in
 * the relay chain execute it?
 *
 * The chain is followed one hop at a time: a tainted job that uploads passes the
 * taint to any DEPENDENT job downloading a name it uploaded. Only dependent jobs
 * are followed, because a job that does not wait for the upload cannot reliably
 * consume it, and only jobs actually carrying the artifact are tainted - which is
 * what keeps an unrelated job's `chmod +x` from escalating anything.
 */
function chainExecutesDownloaded(jobs: JobPosture[], seedJobId: string): boolean {
  const byId = new Map(jobs.map((j) => [j.id, j]));
  const tainted = new Set<string>([seedJobId]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const id of [...tainted]) {
      const src = byId.get(id);
      if (!src?.hasUpload) continue;
      const downstream = dependentClosure(jobs, id);
      for (const j of jobs) {
        if (tainted.has(j.id)) continue;
        if (j.id === id || !downstream.has(j.id)) continue;
        if (j.downloads.some((d) => downloadMatchesUploads(d.name, src.uploadNames))) {
          tainted.add(j.id);
          grew = true;
        }
      }
    }
  }
  for (const id of tainted) {
    if (byId.get(id)?.executesDownloaded) return true;
  }
  return false;
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
    (r) => r.ast.triggers.includes("workflow_run") && r.jobs.some((j) => j.downloads.length > 0),
  );

  for (const consumer of consumers) {
    const producersForConsumer = matchProducers(consumer, producers);
    if (producersForConsumer.length === 0) continue;

    for (const job of consumer.jobs) {
      for (const dl of job.downloads) {
        const matched = producersForConsumer.filter((p) =>
          downloadMatchesUploads(dl.name, p.uploadNames),
        );
        if (matched.length === 0) continue;

        const producerLabel = matched
          .map((p) => p.ast.name ?? p.basename)
          .join(", ");
        // Critical when the artifact is executed anywhere in its relay chain,
        // not only in the job that downloaded it.
        const critical = chainExecutesDownloaded(consumer.jobs, job.id);

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
          line: dl.line,
          confidence: critical ? 0.85 : 0.55,
          category: "supply-chain",
          recommendation:
            "Do not consume PR-produced artifacts in a privileged workflow_run workflow. Treat downloaded " +
            "artifacts as untrusted input: never execute them, and validate/scope their use. If you must relay " +
            "PR build output (e.g. to comment on a PR), do it without secrets and without running the content. " +
            "This check reads only the triggers, the artifact names and the steps that retrieve and run the artifact.",
        });
      }
    }
  }

  return findings;
}
