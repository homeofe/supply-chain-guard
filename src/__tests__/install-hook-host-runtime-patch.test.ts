import { describe, it, expect } from "vitest";
import { analyzeInstallHooks } from "../install-hook-scanner.js";

/**
 * INSTALL_HOOK_HOST_RUNTIME_PATCH (v5.7, Unreleased).
 *
 * A distinct risk class: an npm install hook that patches or mutates a HOST
 * AGENT RUNTIME (OpenClaw, Hermes, Claude Code, ...) during installation -
 * rewriting another installed package's code so the plugin can hook into it.
 * Modelled on the real TencentDB-Agent-Memory postinstall.
 *
 * The rule must be NARROW: it fires only on the combination of a host-runtime
 * target AND a code-mutation action, never on ordinary build hooks.
 */
describe("INSTALL_HOOK_HOST_RUNTIME_PATCH", () => {
  const rule = (findings: { rule: string }[]) =>
    findings.find((f) => f.rule === "INSTALL_HOOK_HOST_RUNTIME_PATCH");

  it("flags the TencentDB-Agent-Memory style postinstall (patches OpenClaw after-tool-call)", () => {
    const findings = analyzeInstallHooks(
      { postinstall: "bash scripts/openclaw-after-tool-call-messages.patch.sh 2>/dev/null || true" },
      "package.json",
    );
    const f = rule(findings);
    expect(f).toBeDefined();
    expect(f?.severity).toBe("high");
  });

  it("flags an inline sed patch of a host runtime under node_modules", () => {
    const findings = analyzeInstallHooks(
      { postinstall: "sed -i 's/return hookEvent/return {...hookEvent, messages}/' node_modules/openclaw/dist/dispatch-tool.js" },
      "package.json",
    );
    expect(rule(findings)).toBeDefined();
  });

  it("flags a node script that injects into the Hermes runtime", () => {
    const findings = analyzeInstallHooks(
      { postinstall: "node scripts/inject-hermes-after-tool-call.js" },
      "package.json",
    );
    expect(rule(findings)).toBeDefined();
  });

  // ── Negative cases: ordinary build hooks must NOT fire ──────────────────────

  it("does NOT flag a normal node build script", () => {
    const findings = analyzeInstallHooks({ postinstall: "node scripts/build.js" }, "package.json");
    expect(rule(findings)).toBeUndefined();
  });

  it("does NOT flag npm run build", () => {
    const findings = analyzeInstallHooks({ postinstall: "npm run build" }, "package.json");
    expect(rule(findings)).toBeUndefined();
  });

  it("does NOT flag tsc", () => {
    const findings = analyzeInstallHooks({ postinstall: "tsc" }, "package.json");
    expect(rule(findings)).toBeUndefined();
  });

  it("does NOT flag patch-package (patches own deps, no agent runtime target)", () => {
    const findings = analyzeInstallHooks({ postinstall: "patch-package" }, "package.json");
    expect(rule(findings)).toBeUndefined();
  });

  it("does NOT flag patch-package combined with husky hook setup", () => {
    const findings = analyzeInstallHooks(
      { postinstall: "patch-package && husky install" },
      "package.json",
    );
    expect(rule(findings)).toBeUndefined();
  });

  it("does NOT flag node-gyp rebuild", () => {
    const findings = analyzeInstallHooks({ install: "node-gyp rebuild" }, "package.json");
    expect(rule(findings)).toBeUndefined();
  });

  it("does NOT flag a build that writes to its own dist/ dir", () => {
    const findings = analyzeInstallHooks(
      { postinstall: "node esbuild.js > dist/index.js" },
      "package.json",
    );
    expect(rule(findings)).toBeUndefined();
  });
});
