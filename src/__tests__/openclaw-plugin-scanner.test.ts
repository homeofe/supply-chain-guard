import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { scanOpenClawPlugin } from "../openclaw-plugin-scanner.js";

/**
 * OpenClaw plugin manifest posture checks (v5.7, Unreleased).
 *
 * openclaw.plugin.json is a rare, OpenClaw-specific artifact, so these findings
 * never fire on ordinary packages. They surface the data-handling posture of an
 * agent-memory plugin (startup activation, default-on conversation capture,
 * external LLM/embedding egress, cloud vector-DB backend, telemetry) as
 * informational/medium context - not as vulnerabilities.
 */
function writeManifest(dir: string, obj: unknown) {
  fs.writeFileSync(path.join(dir, "openclaw.plugin.json"), JSON.stringify(obj, null, 2));
}

describe("scanOpenClawPlugin", () => {
  let tempDir: string;
  beforeEach(() => { tempDir = fs.mkdtempSync(path.join("/tmp", "scg-ocplugin-")); });
  afterEach(() => { fs.rmSync(tempDir, { recursive: true, force: true }); });

  it("returns no findings when there is no openclaw.plugin.json", () => {
    expect(scanOpenClawPlugin(tempDir)).toHaveLength(0);
  });

  it("surfaces the full data-handling posture of a TencentDB-style memory plugin", () => {
    writeManifest(tempDir, {
      id: "memory-tencentdb",
      activation: { onStartup: true },
      configSchema: {
        properties: {
          storeBackend: { enum: ["sqlite", "tcvdb"], default: "sqlite" },
          capture: { properties: { enabled: { type: "boolean", default: true } } },
          extraction: { properties: { enabled: { type: "boolean", default: true } } },
          llm: { properties: { enabled: { default: false }, baseUrl: { default: "https://api.openai.com/v1" } } },
          embedding: { properties: { provider: { default: "none" }, baseUrl: {} } },
          tcvdb: { properties: { url: {}, apiKey: {} } },
          report: { properties: { enabled: { default: false } } },
        },
      },
    });

    const rules = scanOpenClawPlugin(tempDir).map((f) => f.rule);
    expect(rules).toContain("OPENCLAW_PLUGIN_STARTUP_ACTIVATION");
    expect(rules).toContain("OPENCLAW_PLUGIN_AUTOCAPTURE");
    expect(rules).toContain("OPENCLAW_PLUGIN_EXTERNAL_LLM");
    expect(rules).toContain("OPENCLAW_PLUGIN_CLOUD_BACKEND");
    expect(rules).toContain("OPENCLAW_PLUGIN_TELEMETRY");
  });

  it("marks auto-capture and external-LLM as at least medium severity", () => {
    writeManifest(tempDir, {
      id: "m",
      activation: { onStartup: true },
      configSchema: {
        properties: {
          capture: { properties: { enabled: { default: true } } },
          llm: { properties: { baseUrl: { default: "https://api.openai.com/v1" } } },
        },
      },
    });
    const findings = scanOpenClawPlugin(tempDir);
    const capture = findings.find((f) => f.rule === "OPENCLAW_PLUGIN_AUTOCAPTURE");
    const llm = findings.find((f) => f.rule === "OPENCLAW_PLUGIN_EXTERNAL_LLM");
    expect(capture?.severity).toBe("medium");
    expect(llm?.severity).toBe("medium");
  });

  it("does NOT flag auto-capture or external-LLM for a minimal, capture-off manifest", () => {
    writeManifest(tempDir, {
      id: "m",
      activation: { onStartup: false },
      configSchema: {
        properties: {
          capture: { properties: { enabled: { default: false } } },
        },
      },
    });
    const rules = scanOpenClawPlugin(tempDir).map((f) => f.rule);
    expect(rules).not.toContain("OPENCLAW_PLUGIN_AUTOCAPTURE");
    expect(rules).not.toContain("OPENCLAW_PLUGIN_EXTERNAL_LLM");
    expect(rules).not.toContain("OPENCLAW_PLUGIN_STARTUP_ACTIVATION");
  });

  it("does not throw on malformed JSON", () => {
    fs.writeFileSync(path.join(tempDir, "openclaw.plugin.json"), "{ not valid json ");
    expect(() => scanOpenClawPlugin(tempDir)).not.toThrow();
    expect(scanOpenClawPlugin(tempDir)).toHaveLength(0);
  });
});
