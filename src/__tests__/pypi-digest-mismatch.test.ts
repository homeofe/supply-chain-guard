import { EventEmitter } from "node:events";
import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import { beforeEach, describe, expect, it, vi } from "vitest";

const httpsMock = vi.hoisted(() => ({
  get: vi.fn(),
}));

vi.mock("node:https", () => ({
  default: { get: httpsMock.get },
  get: httpsMock.get,
}));

vi.mock("../archive-extractor.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../archive-extractor.js")>()),
  extractZip: vi.fn(),
}));

import { extractZip } from "../archive-extractor.js";
import { scanPypiReleaseArtifacts, type PyPIReleaseFile } from "../pypi-scanner.js";
import { hasPartialScanFinding } from "../pattern-scanner.js";
import type { Finding } from "../types.js";

type ResponseLike = Readable & {
  statusCode: number;
  headers: Record<string, string>;
};

function respondWith(body: Buffer): ResponseLike {
  const response = Readable.from([body]) as ResponseLike;
  response.statusCode = 200;
  response.headers = {};
  return response;
}

describe("PyPI artifact digest mismatch", () => {
  beforeEach(() => {
    httpsMock.get.mockReset();
    vi.mocked(extractZip).mockReset();
  });

  it("reports a high ARTIFACT_DIGEST_MISMATCH and keeps the coverage finding", async () => {
    const served = Buffer.from("bytes served by a tampered mirror");
    const advertised = createHash("sha256").update("the published wheel").digest("hex");
    const artifacts: PyPIReleaseFile[] = [
      {
        filename: "demo-1.0-py3-none-any.whl",
        packagetype: "bdist_wheel",
        url: "https://files.pythonhosted.org/packages/aa/demo-1.0-py3-none-any.whl",
        size: served.length,
        digests: { sha256: advertised },
      },
    ];
    httpsMock.get.mockImplementation((_input: unknown, callback: (r: ResponseLike) => void) => {
      process.nextTick(() => callback(respondWith(served)));
      return new EventEmitter();
    });

    const findings: Finding[] = [];
    await scanPypiReleaseArtifacts(artifacts, findings);

    expect(extractZip).not.toHaveBeenCalled();
    const mismatch = findings.find((f) => f.rule === "ARTIFACT_DIGEST_MISMATCH");
    expect(mismatch?.severity).toBe("high");
    expect(findings.map((f) => f.rule)).toContain("PATH_SCAN_INCOMPLETE");
    expect(hasPartialScanFinding(findings)).toBe(true);
  });

  it("does not report a mismatch when the bytes match the advertised digest", async () => {
    const served = Buffer.from("genuine wheel bytes");
    const advertised = createHash("sha256").update(served).digest("hex");
    httpsMock.get.mockImplementation((_input: unknown, callback: (r: ResponseLike) => void) => {
      process.nextTick(() => callback(respondWith(served)));
      return new EventEmitter();
    });
    vi.mocked(extractZip).mockImplementation(() => ({ skippedLinks: [] }));

    const findings: Finding[] = [];
    await scanPypiReleaseArtifacts(
      [
        {
          filename: "demo-1.0-py3-none-any.whl",
          packagetype: "bdist_wheel",
          url: "https://files.pythonhosted.org/packages/aa/demo-1.0-py3-none-any.whl",
          size: served.length,
          digests: { sha256: advertised },
        },
      ],
      findings,
    );
    expect(findings.map((f) => f.rule)).not.toContain("ARTIFACT_DIGEST_MISMATCH");
  });
});
