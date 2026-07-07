/**
 * OpenClaw plugin manifest scanner (v5.7, Unreleased).
 *
 * openclaw.plugin.json declares how an OpenClaw plugin activates and what it is
 * allowed to do. For an agent-memory plugin, that posture is security-relevant:
 * does it auto-capture conversations, can it ship them to an external LLM /
 * embedding API, does it store memory in a cloud vector DB, does it report
 * telemetry? These are surfaced as informational/medium CONTEXT (not
 * vulnerabilities). The manifest is a rare, OpenClaw-specific file, so these
 * checks never fire on ordinary npm packages.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding } from "./types.js";

function asObj(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : undefined;
}

/** Default value declared for configSchema.properties.<section>.properties.enabled */
function sectionDefaultEnabled(
  props: Record<string, unknown>,
  section: string,
): boolean {
  const enabled = asObj(asObj(asObj(props[section])?.properties)?.enabled);
  return enabled?.default === true;
}

/** True if configSchema.properties.<section>.properties.<field> is declared. */
function sectionHasField(
  props: Record<string, unknown>,
  section: string,
  field: string,
): boolean {
  return !!asObj(asObj(asObj(props[section])?.properties)?.[field]);
}

const CLOUD_BACKEND_RE = /tcvdb|cloud|remote|pinecone|qdrant|weaviate|milvus|zilliz/i;

export function scanOpenClawPlugin(dir: string): Finding[] {
  const findings: Finding[] = [];
  const manifestPath = path.join(dir, "openclaw.plugin.json");
  if (!fs.existsSync(manifestPath)) return findings;

  let manifest: Record<string, unknown> | undefined;
  try {
    manifest = asObj(JSON.parse(fs.readFileSync(manifestPath, "utf-8")));
  } catch {
    return findings; // malformed JSON: nothing to say
  }
  if (!manifest) return findings;

  const rel = "openclaw.plugin.json";
  const props = asObj(asObj(manifest.configSchema)?.properties) ?? {};

  // Startup activation: the plugin runs automatically when the host boots.
  if (asObj(manifest.activation)?.onStartup === true) {
    findings.push({
      rule: "OPENCLAW_PLUGIN_STARTUP_ACTIVATION",
      description: "OpenClaw plugin activates automatically on host startup (activation.onStartup=true). It runs without an explicit user action each session.",
      severity: "info",
      file: rel,
      confidence: 0.9,
      category: "config",
      recommendation: "Confirm this plugin should run on every startup. Startup activation means its capture/recall hooks are always live.",
    });
  }

  // Default-on conversation capture / extraction: collects conversation content
  // by default without the user opting in.
  const captureOn =
    sectionDefaultEnabled(props, "capture") ||
    sectionDefaultEnabled(props, "extraction");
  if (captureOn) {
    findings.push({
      rule: "OPENCLAW_PLUGIN_AUTOCAPTURE",
      description: "OpenClaw memory plugin auto-captures/extracts conversation content by default (capture/extraction enabled:true). Conversations are recorded and profiled unless the user disables it.",
      severity: "medium",
      file: rel,
      confidence: 0.8,
      category: "config",
      recommendation: "Review what is captured and where it is stored. Default-on conversation capture in an agent memory plugin is a privacy and data-exfiltration surface; consider requiring explicit opt-in.",
    });
  }

  // External LLM / embedding egress: the plugin can send content to a
  // third-party OpenAI-compatible endpoint.
  const externalLlm =
    sectionHasField(props, "llm", "baseUrl") ||
    sectionHasField(props, "embedding", "baseUrl") ||
    sectionHasField(props, "embedding", "provider");
  if (externalLlm) {
    findings.push({
      rule: "OPENCLAW_PLUGIN_EXTERNAL_LLM",
      description: "OpenClaw plugin can route conversation content to an external LLM/embedding API (a configurable baseUrl/provider). Captured memory may leave the host to a third-party endpoint.",
      severity: "medium",
      file: rel,
      confidence: 0.75,
      category: "config",
      recommendation: "Verify which endpoint conversation data is sent to and pin/allowlist it. Combined with default-on capture, this is a conversation-exfiltration path.",
    });
  }

  // Cloud vector-DB backend: memory can be stored off-device.
  const storeEnum = asObj(props.storeBackend)?.enum;
  const cloudBackend =
    (Array.isArray(storeEnum) && storeEnum.some((v) => typeof v === "string" && CLOUD_BACKEND_RE.test(v))) ||
    Object.keys(props).some((k) => CLOUD_BACKEND_RE.test(k));
  if (cloudBackend) {
    findings.push({
      rule: "OPENCLAW_PLUGIN_CLOUD_BACKEND",
      description: "OpenClaw plugin supports storing memory in a cloud vector database (e.g. tcvdb). Captured conversation memory can be persisted off-device.",
      severity: "info",
      file: rel,
      confidence: 0.8,
      category: "config",
      recommendation: "Confirm the storage backend. A cloud vector-DB backend means conversation-derived data can leave the local machine.",
    });
  }

  // Telemetry / metrics reporting.
  if (asObj(props.report) || asObj(props.telemetry)) {
    findings.push({
      rule: "OPENCLAW_PLUGIN_TELEMETRY",
      description: "OpenClaw plugin exposes a metrics/telemetry reporting option. Review whether reporting is local-only or can egress.",
      severity: "info",
      file: rel,
      confidence: 0.6,
      category: "config",
      recommendation: "Confirm telemetry stays local (or is disabled). Verify no usage data leaves the host.",
    });
  }

  return findings;
}
