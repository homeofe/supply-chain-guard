import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";

// The daily feed channel publishes signed threat data without a release
// (docs/daily-feed-channel-design.md). These cases hold the workflow to the
// properties the design relies on: the signing key and the Pages write
// permission live in different jobs, every action is pinned, a failed build
// never deploys, and a separate workflow watches the published feed's age.

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

const workflow = code(read(".github/workflows/feed-daily.yml"));
const daily = jobs(workflow);

describe("the daily feed workflow", () => {
  it("has a build job and a deploy job that needs it", () => {
    expect(Object.keys(daily).sort()).toEqual(["build", "deploy"]);
    expect(daily.deploy).toMatch(/^ {4}needs: build$/m);
  });

  it("only the deploy job holds pages and id-token write", () => {
    const top = workflow.slice(0, workflow.indexOf("\njobs:\n"));
    expect(top).toMatch(/^permissions:\n {2}contents: read$/m);
    expect(daily.build).toMatch(/^ {4}permissions:\n {6}contents: read$/m);
    expect(daily.build).not.toMatch(/pages: write|id-token: write/);
    expect(daily.deploy).toMatch(/^ {6}pages: write$/m);
    expect(daily.deploy).toMatch(/^ {6}id-token: write$/m);
  });

  it("the signing key is read only inside the feed-publish environment", () => {
    expect(daily.build).toMatch(/^ {4}environment: feed-publish$/m);
    expect(daily.build).toContain("secrets.FEED_SIGNING_KEY");
    expect(daily.deploy).not.toContain("FEED_SIGNING_KEY");
  });

  it("every action is pinned by a 40-hex sha with its tag", () => {
    const uses = [...workflow.matchAll(/^\s*(?:- )?uses: (\S+)(.*)$/gm)];
    expect(uses.length).toBeGreaterThanOrEqual(4);
    for (const [, ref, rest] of uses) {
      expect(ref, ref).toMatch(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/);
      expect(rest, ref).toMatch(/# v\d+\.\d+\.\d+/);
    }
  });

  it("builds from main, checks the invariant, validates, then signs, in that order", () => {
    const steps = [
      "scripts/import-threat-feed.mjs --dry-run --json",
      "scripts/build-daily-feed.mjs",
      "parseFeedDocument",
      "scripts/sign-feed.mjs",
      "actions/upload-pages-artifact@",
    ].map((s) => daily.build.indexOf(s));
    expect(steps.every((i) => i > 0), JSON.stringify(steps)).toBe(true);
    expect([...steps].sort((a, b) => a - b)).toEqual(steps);
    expect(daily.build).toMatch(/ref: main/);
  });

  it("never lets a failed step continue to the upload", () => {
    expect(workflow).not.toMatch(/continue-on-error:\s*true/);
    expect(workflow).not.toMatch(/\|\|\s*true/);
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
});
