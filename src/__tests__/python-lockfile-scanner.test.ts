import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  scanPythonLockfiles,
  scanPythonLockfileContent,
  scanPoetryLockContent,
  scanUvLockContent,
  scanPipfileLockContent,
  isPythonLockfile,
} from "../python-lockfile-scanner.js";
import { scan } from "../scanner.js";

// Real bundled known-bad PyPI version (LiteLLM PyPI compromise, ioc-blocklist).
// litellm@1.82.7 is compromised; a later version is clean.
const BAD_NAME = "litellm";
const BAD_VERSION = "1.82.7";
const CLEAN_VERSION = "1.83.0";
const PEP503_BAD_NAME = "guardrails-ai";
const PEP503_BAD_VERSION = "0.10.1";

describe("Python lockfile scanner", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-pylock-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should identify Python lockfiles", () => {
    expect(isPythonLockfile("poetry.lock")).toBe(true);
    expect(isPythonLockfile("uv.lock")).toBe(true);
    expect(isPythonLockfile("Pipfile.lock")).toBe(true);
    expect(isPythonLockfile("package-lock.json")).toBe(false);
    expect(isPythonLockfile("requirements.txt")).toBe(false);
  });

  it("preserves a version-pinned feed IOC across every PEP 503 spelling and lockfile format", () => {
    const cases = [
      ["poetry.lock", `[[package]]\nname = "guardrails_ai"\nversion = "${PEP503_BAD_VERSION}"\n`],
      ["uv.lock", `[[package]]\nname = "GUARDRAILS.AI"\nversion = "${PEP503_BAD_VERSION}"\n`],
      ["Pipfile.lock", JSON.stringify({ default: { GUARDRAILS_AI: { version: `==${PEP503_BAD_VERSION}` } } })],
    ] as const;

    for (const [filename, content] of cases) {
      const findings = scanPythonLockfileContent(filename, content, filename);
      expect(findings.some((finding) => finding.rule === "PYTHON_MALICIOUS_PACKAGE"), filename)
        .toBe(true);
    }
  });

  describe("poetry.lock scanning", () => {
    it("should flag a known-bad version", () => {
      const content = [
        "[[package]]",
        `name = "${BAD_NAME}"`,
        `version = "${BAD_VERSION}"`,
        'description = "LLM gateway"',
        "",
        "[[package]]",
        'name = "requests"',
        'version = "2.32.3"',
      ].join("\n");
      const findings = scanPoetryLockContent(content, "poetry.lock");
      const hit = findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(hit).toBeDefined();
      expect(hit?.severity).toBe("critical");
      expect(hit?.file).toBe("poetry.lock");
    });

    it("should not flag a clean poetry.lock (FP-safety)", () => {
      const content = [
        "[[package]]",
        'name = "requests"',
        'version = "2.32.3"',
        "",
        "[[package]]",
        `name = "${BAD_NAME}"`,
        `version = "${CLEAN_VERSION}"`,
        "",
        "[metadata]",
        'lock-version = "2.0"',
      ].join("\n");
      expect(scanPoetryLockContent(content, "poetry.lock")).toHaveLength(0);
    });
  });

  describe("uv.lock scanning", () => {
    it("should flag a known-bad version", () => {
      const content = [
        "[[package]]",
        `name = "${BAD_NAME}"`,
        `version = "${BAD_VERSION}"`,
      ].join("\n");
      const findings = scanUvLockContent(content, "uv.lock");
      expect(findings.some((f) => f.rule === "IOC_KNOWN_BAD_VERSION")).toBe(true);
    });

    it("should not flag a clean uv.lock (FP-safety)", () => {
      const content = [
        "[[package]]",
        'name = "flask"',
        'version = "3.0.3"',
      ].join("\n");
      expect(scanUvLockContent(content, "uv.lock")).toHaveLength(0);
    });
  });

  describe("Pipfile.lock scanning", () => {
    it("should flag a known-bad version (== operator stripped)", () => {
      const content = JSON.stringify({
        default: { [BAD_NAME]: { version: `==${BAD_VERSION}` } },
        develop: {},
      });
      const findings = scanPipfileLockContent(content, "Pipfile.lock");
      expect(findings.some((f) => f.rule === "IOC_KNOWN_BAD_VERSION")).toBe(true);
    });

    it("should flag a known-bad version in the develop section", () => {
      const content = JSON.stringify({
        default: {},
        develop: { [BAD_NAME]: { version: `==${BAD_VERSION}` } },
      });
      const findings = scanPipfileLockContent(content, "Pipfile.lock");
      expect(findings.some((f) => f.rule === "IOC_KNOWN_BAD_VERSION")).toBe(true);
    });

    it("should flag a known-bad version under a pipenv custom category group", () => {
      // Pipenv custom categories (docs/tests/ci/...) are top-level keys with the
      // same shape as default/develop. R2 gate finding: they were missed.
      const content = JSON.stringify({
        _meta: { hash: { sha256: "x" } },
        default: {},
        develop: {},
        docs: { [BAD_NAME]: { version: `==${BAD_VERSION}` } },
      });
      const findings = scanPipfileLockContent(content, "Pipfile.lock");
      expect(findings.some((f) => f.rule === "IOC_KNOWN_BAD_VERSION")).toBe(true);
    });

    it("should not treat _meta as a package map", () => {
      const content = JSON.stringify({
        _meta: { requires: { python_version: "3.12" }, sources: [] },
        default: { requests: { version: "==2.32.3" } },
      });
      expect(scanPipfileLockContent(content, "Pipfile.lock")).toHaveLength(0);
    });

    it("should not flag a clean Pipfile.lock (FP-safety)", () => {
      const content = JSON.stringify({
        default: {
          requests: { version: "==2.32.3" },
          [BAD_NAME]: { version: `==${CLEAN_VERSION}` },
        },
      });
      expect(scanPipfileLockContent(content, "Pipfile.lock")).toHaveLength(0);
    });

    it("should not crash on malformed Pipfile.lock", () => {
      expect(() => scanPipfileLockContent("{ not json", "Pipfile.lock")).not.toThrow();
      expect(scanPipfileLockContent("{ not json", "Pipfile.lock")).toHaveLength(0);
      expect(scanPipfileLockContent("null", "Pipfile.lock")).toHaveLength(0);
    });
  });

  describe("directory scanning", () => {
    it("should scan poetry.lock from a directory", () => {
      fs.writeFileSync(
        path.join(tmpDir, "poetry.lock"),
        `[[package]]\nname = "${BAD_NAME}"\nversion = "${BAD_VERSION}"\n`,
      );
      const findings = scanPythonLockfiles(tmpDir);
      expect(findings.some((f) => f.rule === "IOC_KNOWN_BAD_VERSION")).toBe(true);
    });

    it("should scan all three lockfile formats from a directory", () => {
      fs.writeFileSync(
        path.join(tmpDir, "poetry.lock"),
        `[[package]]\nname = "${BAD_NAME}"\nversion = "${BAD_VERSION}"\n`,
      );
      fs.writeFileSync(
        path.join(tmpDir, "uv.lock"),
        `[[package]]\nname = "${BAD_NAME}"\nversion = "${BAD_VERSION}"\n`,
      );
      fs.writeFileSync(
        path.join(tmpDir, "Pipfile.lock"),
        JSON.stringify({ default: { [BAD_NAME]: { version: `==${BAD_VERSION}` } } }),
      );
      const findings = scanPythonLockfiles(tmpDir);
      expect(findings.filter((f) => f.rule === "IOC_KNOWN_BAD_VERSION")).toHaveLength(3);
    });

    it("should return no findings for an empty directory", () => {
      expect(scanPythonLockfiles(tmpDir)).toHaveLength(0);
    });

    it("scans nested Python lockfiles but prunes vendor and target trees", async () => {
      for (const directory of ["services/api", "vendor/copied", "target/generated"]) {
        fs.mkdirSync(path.join(tmpDir, directory), { recursive: true });
        fs.writeFileSync(
          path.join(tmpDir, directory, "poetry.lock"),
          `[[package]]\nname = "${PEP503_BAD_NAME}"\nversion = "${PEP503_BAD_VERSION}"\n`,
        );
      }

      const report = await scan({ target: tmpDir, format: "text", noHistory: true });
      const hits = report.findings.filter(
        (finding) => finding.rule === "PYTHON_MALICIOUS_PACKAGE",
      );
      expect(hits).toHaveLength(1);
      expect(hits[0]?.file).toBe("services/api/poetry.lock");
      expect(hits[0]?.severity).toBe("critical");
      expect(report.partialScan).not.toBe(true);
    });
  });
});
