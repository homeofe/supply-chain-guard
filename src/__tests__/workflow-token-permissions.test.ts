import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

// OpenSSF Scorecard's Token-Permissions check scored 0 on 2026-09-25 because
// docker.yml granted packages: write at the workflow level, where every job,
// including any added later, inherits it. The grant now sits on the two jobs
// that push. These tests keep every workflow's top level read-only, and keep
// the release job attaching the signed provenance it now fetches.

const root = path.resolve(__dirname, "..", "..");
const workflowsDir = path.join(root, ".github", "workflows");
const workflows = fs
  .readdirSync(workflowsDir)
  .filter((f) => /\.ya?ml$/.test(f))
  .map((f) => [f, fs.readFileSync(path.join(workflowsDir, f), "utf8")] as const);

/** The top-level `permissions:` value: a scalar, or the indented block under it. */
function topLevelPermissions(yaml: string): string[] | null {
  const lines = yaml.split(/\r?\n/);
  const at = lines.findIndex((l) => /^permissions:/.test(l));
  if (at === -1) return null;
  const inline = lines[at].replace(/^permissions:\s*/, "").replace(/\s+#.*$/, "").trim();
  if (inline) return [inline];
  const block: string[] = [];
  for (const line of lines.slice(at + 1)) {
    if (/^\s*#/.test(line) || line.trim() === "") continue;
    if (!/^\s/.test(line)) break;
    block.push(line.replace(/\s+#.*$/, "").trim());
  }
  return block;
}

describe("workflow token permissions", () => {
  it("finds the workflows (control: the scan is not vacuous)", () => {
    expect(workflows.map(([f]) => f)).toEqual(expect.arrayContaining(["ci.yml", "docker.yml", "scorecard.yml", "codeql.yml"]));
  });

  for (const [file, yaml] of workflows) {
    it(`${file} declares top-level permissions and grants no write there`, () => {
      const perms = topLevelPermissions(yaml);
      expect(perms, `${file} has no top-level permissions, so GITHUB_TOKEN gets the repository default`).not.toBeNull();
      expect(perms!.length).toBeGreaterThan(0);
      for (const p of perms!) {
        expect(p, `${file}: top-level "${p}"`).not.toMatch(/write/);
      }
    });
  }

  it("docker.yml still grants packages: write to the jobs that push (the grant moved, it was not lost)", () => {
    const yaml = workflows.find(([f]) => f === "docker.yml")![1];
    const grants = yaml.split(/\r?\n/).filter((l) => /^ {6}packages: write\s*$/.test(l));
    expect(grants).toHaveLength(2);
  });
});

describe("the release job attaches the signed provenance", () => {
  const ci = workflows.find(([f]) => f === "ci.yml")![1];
  const lines = ci.split(/\r?\n/);
  const start = lines.findIndex((l) => /^ {2}release:\s*$/.test(l));
  const end = lines.findIndex((l, i) => i > start && /^ {2}[a-z][a-z0-9_-]*:\s*$/.test(l));
  const job = lines
    .slice(start, end)
    .filter((l) => !/^\s*#/.test(l))
    .join("\n");

  it("fetches the tarball and bundle before it creates the release, and uploads both", () => {
    expect(start).toBeGreaterThan(-1);
    const fetchAt = job.indexOf("node scripts/release-provenance.mjs");
    const createAt = job.indexOf("gh release create");
    expect(fetchAt).toBeGreaterThan(-1);
    expect(createAt).toBeGreaterThan(fetchAt);
    const create = job.slice(createAt);
    expect(create).toContain('"release-assets/supply-chain-guard-${VERSION}.tgz"');
    expect(create).toContain('"release-assets/supply-chain-guard-${VERSION}.tgz.sigstore.json"');
  });
});
