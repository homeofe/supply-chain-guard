import { describe, it, expect } from "vitest";
import { parseWorkflow } from "../workflow-ast.js";

/**
 * Tests for the zero-dependency structural workflow parser.
 *
 * Content is built with array.join("\n") (never template literals) so the
 * `${{ ... }}` GitHub expression syntax is not mis-parsed as JS interpolation.
 */

describe("workflow-ast parseWorkflow", () => {
  it("parses a scalar trigger, top-level permissions, and steps", () => {
    const wf = [
      "name: CI",
      "on: push",
      "permissions:",
      "  contents: read",
      "jobs:",
      "  build:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "      - run: npm test",
    ].join("\n");

    const ast = parseWorkflow(wf);

    expect(ast.name).toBe("CI");
    expect(ast.triggers).toEqual(["push"]);
    expect(ast.permissions.declared).toBe(true);
    expect(ast.permissions.scopes.contents).toBe("read");
    expect(ast.jobs).toHaveLength(1);
    expect(ast.jobs[0].id).toBe("build");
    expect(ast.jobs[0].steps).toHaveLength(2);
    expect(ast.jobs[0].steps[0].uses).toBe("actions/checkout@v4");
    expect(ast.jobs[0].steps[1].run).toBe("npm test");
  });

  it("parses a flow-list trigger", () => {
    const wf = ["on: [push, pull_request]", "jobs:", "  a:", "    steps:", "      - run: echo hi"].join("\n");
    const ast = parseWorkflow(wf);
    expect(ast.triggers).toEqual(["push", "pull_request"]);
  });

  it("parses block-form triggers including pull_request_target and workflow_run.workflows (flow list)", () => {
    const wf = [
      "on:",
      "  pull_request_target:",
      "    types: [opened, synchronize]",
      "  workflow_run:",
      '    workflows: ["CI", "Build"]',
      "    types: [completed]",
      "jobs:",
      "  x:",
      "    steps:",
      "      - run: echo hi",
    ].join("\n");

    const ast = parseWorkflow(wf);
    expect(ast.triggers).toContain("pull_request_target");
    expect(ast.triggers).toContain("workflow_run");
    expect(ast.workflowRunWorkflows).toEqual(["CI", "Build"]);
  });

  it("parses workflow_run.workflows as a block list", () => {
    const wf = [
      "on:",
      "  workflow_run:",
      "    workflows:",
      "      - CI",
      "      - Deploy",
      "    types: [completed]",
      "jobs:",
      "  x:",
      "    steps:",
      "      - run: echo hi",
    ].join("\n");

    const ast = parseWorkflow(wf);
    expect(ast.workflowRunWorkflows).toEqual(["CI", "Deploy"]);
  });

  it("captures a checkout step's with.ref (PR head)", () => {
    const wf = [
      "on: pull_request_target",
      "jobs:",
      "  build:",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
      "      - run: npm ci",
    ].join("\n");

    const ast = parseWorkflow(wf);
    const step = ast.jobs[0].steps[0];
    expect(step.uses).toBe("actions/checkout@v4");
    expect(step.withRef).toBe("${{ github.event.pull_request.head.sha }}");
  });

  it("captures a github-script step's with.script block scalar", () => {
    const wf = [
      "on: issue_comment",
      "jobs:",
      "  c:",
      "    steps:",
      "      - uses: actions/github-script@v7",
      "        with:",
      "          script: |",
      "            const title = context.payload.issue.title",
      "            console.log('${{ github.event.comment.body }}')",
      "      - run: echo done",
    ].join("\n");

    const ast = parseWorkflow(wf);
    const step = ast.jobs[0].steps[0];
    expect(step.uses).toBe("actions/github-script@v7");
    expect(step.withScript).toContain("github.event.comment.body");
    // the block scalar body must not leak into a separate phantom step
    expect(ast.jobs[0].steps).toHaveLength(2);
    expect(ast.jobs[0].steps[1].run).toBe("echo done");
  });

  it("captures upload/download artifact names", () => {
    const wf = [
      "on: pull_request",
      "jobs:",
      "  build:",
      "    steps:",
      "      - uses: actions/upload-artifact@v4",
      "        with:",
      "          name: build-output",
      "          path: dist/",
    ].join("\n");

    const ast = parseWorkflow(wf);
    const step = ast.jobs[0].steps[0];
    expect(step.uses).toBe("actions/upload-artifact@v4");
    expect(step.withName).toBe("build-output");
  });

  it("detects permissions: write-all", () => {
    const wf = ["on: push", "permissions: write-all", "jobs:", "  a:", "    steps:", "      - run: echo hi"].join("\n");
    const ast = parseWorkflow(wf);
    expect(ast.permissions.declared).toBe(true);
    expect(ast.permissions.writeAll).toBe(true);
  });

  it("reports permissions not declared when absent", () => {
    const wf = ["on: push", "jobs:", "  a:", "    steps:", "      - run: echo hi"].join("\n");
    const ast = parseWorkflow(wf);
    expect(ast.permissions.declared).toBe(false);
    expect(ast.permissions.writeAll).toBe(false);
  });

  it("captures a multi-line run block scalar joined", () => {
    const wf = [
      "on: workflow_run",
      "jobs:",
      "  deploy:",
      "    steps:",
      "      - run: |",
      "          echo start",
      "          bash ./artifact/build.sh",
    ].join("\n");

    const ast = parseWorkflow(wf);
    const step = ast.jobs[0].steps[0];
    expect(step.run).toContain("echo start");
    expect(step.run).toContain("bash ./artifact/build.sh");
  });

  it("parses per-job permissions", () => {
    const wf = [
      "on: push",
      "jobs:",
      "  build:",
      "    permissions:",
      "      contents: write",
      "      id-token: write",
      "    steps:",
      "      - run: echo hi",
    ].join("\n");

    const ast = parseWorkflow(wf);
    expect(ast.jobs[0].permissions.declared).toBe(true);
    expect(ast.jobs[0].permissions.scopes["id-token"]).toBe("write");
    expect(ast.jobs[0].permissions.scopes.contents).toBe("write");
  });
});

describe("workflow-ast parser robustness (v5.7 review fixes)", () => {
  it("recognises a bare '-' step marker (dash alone on its line)", () => {
    const wf = [
      "on: pull_request_target",
      "jobs:",
      "  build:",
      "    steps:",
      "      -",
      "        uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
      "      - run: npm ci",
    ].join("\n");

    const ast = parseWorkflow(wf);
    expect(ast.jobs[0].steps).toHaveLength(2);
    expect(ast.jobs[0].steps[0].uses).toBe("actions/checkout@v4");
    expect(ast.jobs[0].steps[0].withRef).toBe("${{ github.event.pull_request.head.sha }}");
    expect(ast.jobs[0].steps[1].run).toBe("npm ci");
  });

  it("keeps triggers when a misindented comment precedes the trigger key under on:", () => {
    const wf = [
      "on:",
      "    # run on fork PRs",
      "  pull_request_target:",
      "jobs:",
      "  x:",
      "    steps:",
      "      - run: echo hi",
    ].join("\n");
    const ast = parseWorkflow(wf);
    expect(ast.triggers).toContain("pull_request_target");
  });

  it("keeps a job's steps when a shallow comment sits above the child keys", () => {
    const wf = [
      "on: pull_request_target",
      "jobs:",
      "  build:",
      "   # a comment at indent 3",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
    ].join("\n");
    const ast = parseWorkflow(wf);
    expect(ast.jobs[0].steps).toHaveLength(1);
    expect(ast.jobs[0].steps[0].withRef).toBe("${{ github.event.pull_request.head.sha }}");
  });

  it("parses a quoted top-level key (\"on\":)", () => {
    const wf = [
      '"on": pull_request_target',
      "jobs:",
      "  build:",
      "    steps:",
      "      - run: echo hi",
    ].join("\n");
    const ast = parseWorkflow(wf);
    expect(ast.triggers).toContain("pull_request_target");
  });

  it("parses an inline flow-map permissions value", () => {
    const wf = [
      "on: push",
      "permissions: { contents: write, id-token: write }",
      "jobs:",
      "  a:",
      "    steps:",
      "      - run: echo hi",
    ].join("\n");
    const ast = parseWorkflow(wf);
    expect(ast.permissions.declared).toBe(true);
    expect(ast.permissions.scopes.contents).toBe("write");
    expect(ast.permissions.scopes["id-token"]).toBe("write");
  });

  it("detects write-all even behind a YAML anchor", () => {
    const wf = [
      "on: push",
      "permissions: &perms write-all",
      "jobs:",
      "  a:",
      "    steps:",
      "      - run: echo hi",
    ].join("\n");
    const ast = parseWorkflow(wf);
    expect(ast.permissions.writeAll).toBe(true);
  });

  it("handles a block scalar with an explicit indentation indicator (run: |2)", () => {
    const wf = [
      "on: workflow_run",
      "jobs:",
      "  deploy:",
      "    steps:",
      "      - run: |2",
      "          echo start",
      "          bash ./artifact/build.sh",
      "      - uses: actions/checkout@v4",
    ].join("\n");
    const ast = parseWorkflow(wf);
    // the block body must not leak into a phantom step
    expect(ast.jobs[0].steps).toHaveLength(2);
    expect(ast.jobs[0].steps[0].run).toContain("bash ./artifact/build.sh");
    expect(ast.jobs[0].steps[1].uses).toBe("actions/checkout@v4");
  });
});
