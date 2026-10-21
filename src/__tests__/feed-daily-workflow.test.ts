import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawnSync } from "node:child_process";

// The daily feed channel publishes signed threat data without a release
// (docs/daily-feed-channel-design.md). These cases hold the workflow to the
// properties the design relies on: the job that installs and runs dependencies
// never sees the signing key; the job that signs installs nothing and re-checks
// the feed itself; only the deploy job may write Pages; every action is pinned;
// a failed step never publishes; and a separate workflow watches the age.

const ROOT = path.resolve(__dirname, "..", "..");
const read = (rel: string) => fs.readFileSync(path.join(ROOT, rel), "utf8").replace(/\r\n/g, "\n");
const code = (text: string) =>
  text
    .split("\n")
    .filter((l) => !/^\s*#/.test(l))
    .join("\n");

/** The jobs of a workflow, by id: the text from `  <id>:` to the next job header. */
function jobs(text: string): Record<string, string> {
  const body = text.slice(text.indexOf("\njobs:\n") + "\njobs:\n".length);
  const out: Record<string, string> = {};
  const headers = [...body.matchAll(/^ {2}([a-z0-9_-]+):$/gm)];
  headers.forEach((m, i) => {
    out[m[1]] = body.slice(m.index!, i + 1 < headers.length ? headers[i + 1].index : undefined);
  });
  return out;
}

/** Positions of the needles in the haystack, which must all exist and ascend. */
function inOrder(haystack: string, needles: string[]) {
  const at = needles.map((n) => haystack.indexOf(n));
  expect(at.every((i) => i >= 0), JSON.stringify(Object.fromEntries(needles.map((n, i) => [n, at[i]])))).toBe(true);
  expect([...at].sort((a, b) => a - b)).toEqual(at);
}

const workflow = code(read(".github/workflows/feed-daily.yml"));
const daily = jobs(workflow);

describe("the daily feed workflow", () => {
  it("builds, then signs, then deploys", () => {
    expect(Object.keys(daily).sort()).toEqual(["build", "deploy", "sign"]);
    expect(daily.sign).toMatch(/^ {4}needs: build$/m);
    expect(daily.deploy).toMatch(/^ {4}needs: sign$/m);
  });

  it("only the deploy job holds pages and id-token write", () => {
    const top = workflow.slice(0, workflow.indexOf("\njobs:\n"));
    expect(top).toMatch(/^permissions:\n {2}contents: read$/m);
    for (const job of ["build", "sign"]) {
      expect(daily[job], job).toMatch(/^ {4}permissions:\n {6}contents: read$/m);
      expect(daily[job], job).not.toMatch(/pages: write|id-token: write/);
    }
    expect(daily.deploy).toMatch(/^ {6}pages: write$/m);
    expect(daily.deploy).toMatch(/^ {6}id-token: write$/m);
  });

  it("the job that runs dependencies never sees the signing key", () => {
    expect(daily.build).not.toMatch(/environment:/);
    expect(daily.build).not.toContain("FEED_SIGNING_KEY");
    expect(daily.build).toContain("npm ci --ignore-scripts");
  });

  it("the signing job installs nothing and holds the key in exactly one step", () => {
    expect(daily.sign).toMatch(/^ {4}environment: feed-publish$/m);
    expect(daily.sign).not.toMatch(/npm ci|npm install|npm run|npx |cache:/);
    expect(workflow.match(/secrets\.FEED_SIGNING_KEY/g)).toHaveLength(1);
    const step = daily.sign.slice(daily.sign.lastIndexOf("\n      - ", daily.sign.indexOf("secrets.FEED_SIGNING_KEY")));
    expect(step.slice(0, step.indexOf("\n      - ", 1) === -1 ? undefined : step.indexOf("\n      - ", 1))).toContain(
      "scripts/sign-feed.mjs",
    );
  });

  it("both jobs work on the same main commit and the same release tag", () => {
    expect(daily.build).toMatch(/^ {4}if: github\.ref == 'refs\/heads\/main'$/m);
    expect(daily.build).toMatch(/ref: \$\{\{ github\.sha \}\}/);
    expect(daily.sign).toMatch(/ref: \$\{\{ needs\.build\.outputs\.sha \}\}/);
    expect(daily.sign).toContain("needs.build.outputs.tag");
  });

  it("every action is pinned by a 40-hex sha with its tag", () => {
    const uses = [...workflow.matchAll(/^\s*(?:- )?uses: (\S+)(.*)$/gm)];
    expect(uses.length).toBeGreaterThanOrEqual(7);
    for (const [, ref, rest] of uses) {
      expect(ref, ref).toMatch(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/);
      expect(rest, ref).toMatch(/# v\d+\.\d+\.\d+/);
    }
  });

  it("builds and checks, then the signing job re-checks before it signs", () => {
    inOrder(daily.build, [
      "scripts/import-threat-feed.mjs --dry-run --json",
      "scripts/build-daily-feed.mjs",
      "parseFeedDocument",
      "actions/upload-artifact@",
    ]);
    inOrder(daily.sign, [
      "actions/download-artifact@",
      "scripts/build-daily-feed.mjs --verify",
      "scripts/sign-feed.mjs",
      "actions/upload-pages-artifact@",
    ]);
  });

  // Only dist/feed.js is needed, for the parser check. The repository gates
  // run on every push to main already; coupling the daily feed to all of them
  // would let any unrelated gate stop the channel.
  it("the build job compiles with tsc alone, not the full prebuild gates", () => {
    expect(daily.build).toContain("npx --no-install tsc");
    expect(daily.build).not.toContain("npm run build");
  });

  it("never lets a failed step continue towards a deploy", () => {
    expect(workflow).not.toMatch(/continue-on-error/);
    expect(workflow).not.toMatch(/\|\|\s*true/);
    for (const job of ["build", "sign"]) {
      expect(daily[job], job).not.toMatch(/^ {8}if:/m);
    }
  });
});

describe("the release job and the freshness check", () => {
  it("the release job signs inside the same environment", () => {
    const release = jobs(code(read(".github/workflows/ci.yml"))).release;
    expect(release).toContain("secrets.FEED_SIGNING_KEY");
    expect(release).toMatch(/^ {4}environment: feed-publish$/m);
  });

  it("the reconcile workflow checks channel freshness at 30 hours", () => {
    const reconcile = code(read(".github/workflows/feed-reconcile.yml"));
    expect(reconcile).toContain("https://homeofe.github.io/supply-chain-guard/feed/feed.json");
    expect(reconcile).toContain("30 * 3600 * 1000");
    expect(reconcile).toContain("vars.FEED_CHANNEL_LIVE");
  });

  it("arms the freshness check only on the exact value true, and refuses a future date", () => {
    const reconcile = code(read(".github/workflows/feed-reconcile.yml"));
    expect(reconcile).toContain(`process.env.CHANNEL_LIVE === "true"`);
    expect(reconcile).not.toContain("Boolean(process.env.CHANNEL_LIVE)");
    expect(reconcile).toMatch(/generatedAt[^\n]*in the future/);
  });
});

// Reading a script as text cannot tell whether Bash will even parse it: an
// apostrophe inside `node -e '...'` ends the quoted script early, and the
// freshness step died with "syntax error near unexpected token" on its first
// armed run (2026-10-21). Every `run: |` block of every workflow goes
// through `bash -n`, and every inline `node -e '...'` body through
// `node --check`.
const hasBash = process.platform !== "win32" && spawnSync("bash", ["--version"], { stdio: "ignore" }).status === 0;

/** The literal `run: |` blocks of a workflow, dedented, with their step names. */
function runBlocks(text: string): Array<{ step: string; script: string }> {
  const lines = text.split("\n");
  const out: Array<{ step: string; script: string }> = [];
  let step = "?";
  for (let i = 0; i < lines.length; i++) {
    const name = /^\s*- name: (.+)$/.exec(lines[i]);
    if (name) step = name[1];
    const run = /^(\s*)run: \|$/.exec(lines[i]);
    if (!run) continue;
    const indent = run[1].length;
    const body: string[] = [];
    while (i + 1 < lines.length && (lines[i + 1].trim() === "" || lines[i + 1].length - lines[i + 1].trimStart().length > indent)) {
      body.push(lines[++i]);
    }
    const cut = Math.min(...body.filter((l) => l.trim() !== "").map((l) => l.length - l.trimStart().length));
    out.push({ step, script: body.map((l) => l.slice(cut)).join("\n") + "\n" });
  }
  return out;
}

describe("every workflow's run scripts parse", () => {
  const workflows = fs.readdirSync(path.join(ROOT, ".github", "workflows")).filter((f) => /\.ya?ml$/.test(f));
  it("finds the workflows", () => expect(workflows.length).toBeGreaterThanOrEqual(9));
  for (const file of workflows.map((f) => `.github/workflows/${f}`)) {
    const blocks = runBlocks(read(file));
    for (const { step, script } of blocks) {
      it.skipIf(!hasBash)(`${file}: "${step}" passes bash -n and node --check`, () => {
        const temp = fs.mkdtempSync(path.join(os.tmpdir(), "scg-run-syntax-"));
        try {
          const sh = path.join(temp, "step.sh");
          fs.writeFileSync(sh, script, "utf8");
          const bash = spawnSync("bash", ["-n", sh], { encoding: "utf8" });
          expect(bash.stderr, step).toBe("");
          expect(bash.status, step).toBe(0);
          const inline = /node -e '\n([\s\S]*?)\n'/.exec(script);
          if (inline) {
            const js = path.join(temp, "step.js");
            fs.writeFileSync(js, inline[1], "utf8");
            const node = spawnSync(process.execPath, ["--check", js], { encoding: "utf8" });
            expect(node.stderr, step).toBe("");
            expect(node.status, step).toBe(0);
          }
        } finally {
          fs.rmSync(temp, { recursive: true, force: true });
        }
      });
    }
  }
});
