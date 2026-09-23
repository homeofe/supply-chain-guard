import { describe, it, expect } from "vitest";
import {
  extractExtensionReferences,
  isExtensionReferenceFile,
  matchExtensionIOC,
  scanExtensionReferences,
} from "../extension-identity.js";
import type { FeedIOC } from "../threat-intel.js";

// Synthetic feed: pins the matcher's semantics independently of the bundle.
const FEED: FeedIOC[] = [
  { type: "package", value: "vscode:evilpub.stealer", severity: "critical", confidence: 0.9, family: "TestFamily" },
  { type: "package", value: "openvsx:hijacked.theme@2.0.1", severity: "critical", confidence: 1.0 },
  { type: "package", value: "vscode:Mixed.Case", severity: "high", confidence: 1.0 },
];

const hits = (content: string, file: string, feed: FeedIOC[] = FEED) =>
  scanExtensionReferences(content, file, feed).filter((f) => f.rule === "VSCODE_MALICIOUS_EXTENSION");

describe("isExtensionReferenceFile", () => {
  it("accepts workspace recommendations, devcontainer files and manifests", () => {
    expect(isExtensionReferenceFile(".vscode/extensions.json")).toBe(true);
    expect(isExtensionReferenceFile("app/.vscode/extensions.json")).toBe(true);
    expect(isExtensionReferenceFile(".devcontainer/devcontainer.json")).toBe(true);
    expect(isExtensionReferenceFile(".devcontainer.json")).toBe(true);
    expect(isExtensionReferenceFile("package.json")).toBe(true);
  });

  it("rejects an extensions.json outside a .vscode directory", () => {
    expect(isExtensionReferenceFile("config/extensions.json")).toBe(false);
    expect(isExtensionReferenceFile("tsconfig.json")).toBe(false);
  });
});

describe("matchExtensionIOC", () => {
  it("checks only the named registry when it is known", () => {
    expect(matchExtensionIOC("evilpub", "stealer", undefined, ["marketplace"], FEED)?.ioc.value).toBe("vscode:evilpub.stealer");
    expect(matchExtensionIOC("evilpub", "stealer", undefined, ["openvsx"], FEED)).toBeNull();
    expect(matchExtensionIOC("hijacked", "theme", "2.0.1", ["marketplace"], FEED)).toBeNull();
  });

  it("checks both registries when it is not", () => {
    const hit = matchExtensionIOC("hijacked", "theme", "2.0.1", ["marketplace", "openvsx"], FEED);
    expect(hit?.registry).toBe("openvsx");
  });

  it("matches case-insensitively on both sides, as the registries do", () => {
    expect(matchExtensionIOC("EVILPUB", "Stealer", undefined, ["marketplace"], FEED)).not.toBeNull();
    expect(matchExtensionIOC("mixed", "case", undefined, ["marketplace"], FEED)).not.toBeNull();
  });

  it("honours version pins", () => {
    expect(matchExtensionIOC("hijacked", "theme", "2.0.2", ["openvsx"], FEED)).toBeNull();
    expect(matchExtensionIOC("hijacked", "theme", undefined, ["openvsx"], FEED)).toBeNull();
  });
});

describe("extractExtensionReferences", () => {
  it("reads workspace recommendations (JSONC) and ignores unwantedRecommendations", () => {
    const content = [
      "{",
      "  // team defaults",
      '  "recommendations": ["dbaeumer.vscode-eslint", "evilpub.stealer",],',
      '  "unwantedRecommendations": ["hijacked.theme"]',
      "}",
    ].join("\n");
    expect(extractExtensionReferences(content, ".vscode/extensions.json")).toEqual([
      { publisher: "dbaeumer", name: "vscode-eslint", version: undefined },
      { publisher: "evilpub", name: "stealer", version: undefined },
    ]);
  });

  it("reads devcontainer extensions, both the current and the legacy location, with versions", () => {
    const content = [
      "{",
      '  "name": "dev", /* comment */',
      '  "customizations": { "vscode": { "extensions": ["hijacked.theme@2.0.1", "ms-python.python"] } },',
      '  "extensions": ["evilpub.stealer"]',
      "}",
    ].join("\n");
    expect(extractExtensionReferences(content, ".devcontainer/devcontainer.json")).toEqual([
      { publisher: "hijacked", name: "theme", version: "2.0.1" },
      { publisher: "ms-python", name: "python", version: undefined },
      { publisher: "evilpub", name: "stealer", version: undefined },
    ]);
  });

  it("reads an installed or packaged extension manifest", () => {
    const manifest = JSON.stringify({ name: "theme", publisher: "hijacked", version: "2.0.1", engines: { vscode: "^1.80.0" } });
    expect(extractExtensionReferences(manifest, "hijacked.theme-2.0.1/package.json")).toEqual([
      { publisher: "hijacked", name: "theme", version: "2.0.1" },
    ]);
  });

  // An ordinary npm package.json may carry a "publisher" key; without an
  // engines.vscode constraint it is not an extension and has no identity here.
  it("ignores a package.json that is not an extension manifest", () => {
    const pkg = JSON.stringify({ name: "stealer", publisher: "evilpub", version: "1.0.0" });
    expect(extractExtensionReferences(pkg, "package.json")).toEqual([]);
  });

  it("tolerates a UTF-8 BOM and rejects malformed IDs", () => {
    const content = "\uFEFF" + JSON.stringify({ recommendations: ["evilpub.stealer", "no-dot", "a.b.c", "../x.y", "evil pub.stealer"] });
    expect(extractExtensionReferences(content, ".vscode/extensions.json")).toEqual([
      { publisher: "evilpub", name: "stealer", version: undefined },
    ]);
  });

  it("returns nothing for unparseable content", () => {
    expect(extractExtensionReferences("{ not json", ".vscode/extensions.json")).toEqual([]);
  });
});

describe("scanExtensionReferences", () => {
  it("flags a recommended malicious extension", () => {
    const found = hits(JSON.stringify({ recommendations: ["evilpub.stealer"] }), ".vscode/extensions.json");
    expect(found).toHaveLength(1);
    expect(found[0]?.severity).toBe("critical");
    expect(found[0]?.category).toBe("malware");
    expect(found[0]?.match).toBe("evilpub.stealer");
    expect(found[0]?.description).toContain("TestFamily");
  });

  it("flags a devcontainer pin on the hijacked version only", () => {
    const at = (v: string) =>
      hits(JSON.stringify({ customizations: { vscode: { extensions: [`hijacked.theme@${v}`] } } }), ".devcontainer.json");
    expect(at("2.0.1")).toHaveLength(1);
    expect(at("2.0.2")).toHaveLength(0);
  });

  it("does not report a recommendation without a version against a version pin", () => {
    expect(hits(JSON.stringify({ recommendations: ["hijacked.theme"] }), ".vscode/extensions.json")).toEqual([]);
  });

  it("leaves a clean recommendations list alone", () => {
    const content = JSON.stringify({ recommendations: ["dbaeumer.vscode-eslint", "esbenp.prettier-vscode"] });
    expect(scanExtensionReferences(content, ".vscode/extensions.json", FEED)).toEqual([]);
  });

  // A recommendation carries no registry. An id known malicious only on Open VSX
  // may be a different publisher's extension on the Marketplace, so the hit is
  // reported at medium and says which editors it applies to.
  it("reports an Open VSX-only hit on a recommendation at medium, and a Marketplace hit at full severity", () => {
    const feed: FeedIOC[] = [
      { type: "package", value: "openvsx:ms-python.python", severity: "critical", confidence: 1.0 },
      { type: "package", value: "vscode:evilpub.stealer", severity: "critical", confidence: 1.0 },
    ];
    const found = hits(JSON.stringify({ recommendations: ["ms-python.python", "evilpub.stealer"] }), ".vscode/extensions.json", feed);
    expect(found.map((f) => `${f.match}:${f.severity}`)).toEqual(["ms-python.python:medium", "evilpub.stealer:critical"]);
    expect(found[0]?.description).toContain("Open VSX only");
  });
});
