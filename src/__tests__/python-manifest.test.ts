/**
 * PyPI threat-feed matching in requirements files and pyproject.toml.
 *
 * Before 2026-09-23 only poetry.lock, uv.lock and Pipfile.lock were matched, so
 * the most common Python manifest, requirements.txt, and pyproject.toml scanned
 * clean even when they named a known-malicious package (measured with a real
 * scan; see STATUS.md).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { isPythonManifest, scanPythonManifestContent } from "../python-lockfile-scanner.js";
import { parseRequirementPins } from "../dependency-confusion.js";
import { scan } from "../scanner.js";
import { getBundledFeed, type FeedIOC } from "../threat-intel.js";

const FEED: FeedIOC[] = [
  { type: "package", value: "pypi:evil-pkg", severity: "critical", confidence: 0.9, family: "TestFamily" },
  { type: "package", value: "pypi:hijacked-lib@2.6.2", severity: "critical", confidence: 1.0 },
];

const rules = (content: string, file: string) =>
  scanPythonManifestContent(content, file, FEED).filter((f) => f.rule === "PYTHON_MALICIOUS_PACKAGE").map((f) => f.match);

describe("isPythonManifest", () => {
  it("accepts requirements files and pyproject.toml", () => {
    for (const f of ["requirements.txt", "requirements-dev.txt", "dev-requirements.txt", "requirements/base.txt",
      "constraints.txt", "app/pyproject.toml"]) {
      expect(isPythonManifest(f), f).toBe(true);
    }
  });

  it("rejects other text and TOML files", () => {
    for (const f of ["README.txt", "notes/requirements.md", "Cargo.toml", "setup.cfg", "LICENSE.txt"]) {
      expect(isPythonManifest(f), f).toBe(false);
    }
  });
});

describe("parseRequirementPins", () => {
  it("keeps exact == pins as versions and leaves ranges unknown", () => {
    const content = [
      "# comment",
      "hijacked-lib==2.6.2",
      "Evil_Pkg>=1.0",
      "other[extra]==1.0.0 ; python_version >= '3.9'",
      "ranged>=1.0,<2.0",
      "-r base.txt",
      "--index-url https://pypi.org/simple",
      "-e git+https://example.com/x.git#egg=editable_pkg",
      "hashed==3.0 --hash=sha256:abcd",
    ].join("\n");
    expect(parseRequirementPins(content)).toEqual([
      { name: "hijacked-lib", version: "2.6.2" },
      { name: "Evil_Pkg", version: undefined },
      { name: "other", version: "1.0.0" },
      { name: "ranged", version: undefined },
      { name: "editable_pkg", version: undefined },
      { name: "hashed", version: "3.0" },
    ]);
  });
});

describe("scanPythonManifestContent", () => {
  it("flags whole-package and pinned entries in requirements.txt", () => {
    expect(rules("evil-pkg\nhijacked-lib==2.6.2\n", "requirements.txt")).toEqual(["evil-pkg", "hijacked-lib@2.6.2"]);
  });

  it("normalises names the way PyPI does (PEP 503)", () => {
    expect(rules("Evil_Pkg>=1\n", "requirements.txt")).toEqual(["Evil_Pkg"]);
  });

  it("does not flag a different pinned version or a range against a pin", () => {
    expect(rules("hijacked-lib==2.6.3\nhijacked-lib>=2.6\n", "requirements.txt")).toEqual([]);
  });

  it("reads [project].dependencies and Poetry dependencies in pyproject.toml", () => {
    const pyproject = [
      "[project]",
      'name = "app"',
      "dependencies = [",
      '  "requests>=2",',
      '  "evil-pkg",',
      "]",
    ].join("\n");
    expect(rules(pyproject, "pyproject.toml")).toEqual(["evil-pkg"]);
  });

  it("leaves a clean manifest alone", () => {
    expect(scanPythonManifestContent("requests==2.32.3\nnumpy>=1.26\n", "requirements.txt", FEED)).toEqual([]);
  });
});

describe("through a real directory scan (bundled feed)", () => {
  let dir: string;
  beforeAll(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-pyman-")); });
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

  // A whole-package pypi: entry and a pinned one, taken from the live bundle.
  const bundled = getBundledFeed().filter((i) => i.type === "package" && i.value.startsWith("pypi:"));
  const bare = bundled.find((i) => i.value.lastIndexOf("@") <= 0)!.value.slice("pypi:".length);
  const pinnedValue = bundled.find((i) => i.value.lastIndexOf("@") > 0)!.value.slice("pypi:".length);

  it("reports a requirements.txt entry, nested one level down too", async () => {
    fs.mkdirSync(path.join(dir, "service"), { recursive: true });
    fs.writeFileSync(path.join(dir, "requirements.txt"), `${bare}\n`);
    fs.writeFileSync(path.join(dir, "service", "requirements.txt"), `${pinnedValue.replace("@", "==")}\n`);
    const report = await scan({ target: dir, format: "json", noHistory: true });
    const files = report.findings.filter((f) => f.rule === "PYTHON_MALICIOUS_PACKAGE").map((f) => f.file.replace(/\\/g, "/")).sort();
    expect(files).toEqual(["requirements.txt", "service/requirements.txt"]);
  });

  // vendor/ and target/ hold copies of installed dependencies; every sibling
  // manifest dispatch skips them, and so must this one.
  it("does not report vendored copies under vendor/ or target/", async () => {
    const vdir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-pyvendor-"));
    try {
      for (const sub of ["vendor/lib", "target"]) {
        fs.mkdirSync(path.join(vdir, sub), { recursive: true });
        fs.writeFileSync(path.join(vdir, sub, "requirements.txt"), `${bare}\n`);
      }
      const report = await scan({ target: vdir, format: "json", noHistory: true });
      expect(report.findings.filter((f) => f.rule === "PYTHON_MALICIOUS_PACKAGE")).toEqual([]);
    } finally {
      fs.rmSync(vdir, { recursive: true, force: true });
    }
  });
});
