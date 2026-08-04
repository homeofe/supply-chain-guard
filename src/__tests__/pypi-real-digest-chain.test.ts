import { EventEmitter } from "node:events";
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
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
import {
  scanPypiReleaseArtifacts,
  type PyPIReleaseFile,
} from "../pypi-scanner.js";
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

function requestedUrl(input: unknown): string {
  if (typeof input === "string") return input;
  const options = input as {
    protocol?: string;
    hostname?: string;
    port?: string;
    path?: string;
  };
  const port = options.port ? `:${options.port}` : "";
  return `${options.protocol ?? "https:"}//${options.hostname}${port}${options.path ?? "/"}`;
}

describe("PyPI real digest and alias retry chain", () => {
  beforeEach(() => {
    httpsMock.get.mockReset();
    vi.mocked(extractZip).mockReset();
  });

  it("retries an equivalent alias only after its downloaded bytes pass streaming SHA-256 verification", async () => {
    const tamperedBytes = Buffer.from("tampered wheel bytes");
    const verifiedBytes = Buffer.from("verified wheel bytes");
    const expectedSha256 = createHash("sha256")
      .update(verifiedBytes)
      .digest("hex");
    const firstUrl = "https://files.pythonhosted.org/packages/aa/shared.whl";
    const verifiedUrl = "https://files.pythonhosted.org/packages/bb/shared.whl";
    const artifacts: PyPIReleaseFile[] = [
      {
        filename: "tampered.whl",
        packagetype: "bdist_wheel",
        url: firstUrl,
        size: tamperedBytes.length,
        digests: { sha256: expectedSha256 },
      },
      {
        filename: "verified.whl",
        packagetype: "bdist_wheel",
        url: verifiedUrl,
        size: verifiedBytes.length,
        digests: { sha256: expectedSha256 },
      },
    ];
    const requestedUrls: string[] = [];

    httpsMock.get.mockImplementation(
      (
        input: unknown,
        callback: (response: ResponseLike) => void,
      ) => {
        const url = requestedUrl(input);
        requestedUrls.push(url);
        const request = new EventEmitter();
        const body = url === firstUrl ? tamperedBytes : verifiedBytes;
        process.nextTick(() => callback(respondWith(body)));
        return request;
      },
    );

    vi.mocked(extractZip).mockImplementation((archivePath, extractDir) => {
      // The extractor is reached only for the alias whose real on-disk bytes
      // passed downloadAndScanWheel's streaming SHA-256 check.
      expect(fs.readFileSync(archivePath)).toEqual(verifiedBytes);
      const packageDir = path.join(extractDir, "verified_package");
      fs.mkdirSync(packageDir, { recursive: true });
      fs.writeFileSync(
        path.join(packageDir, "payload.py"),
        'import os\nos.system("id")\n',
      );
    });

    const findings: Finding[] = [];
    const counts = await scanPypiReleaseArtifacts(artifacts, findings);

    // A digest mismatch is converted to PyPIArtifactAcquisitionError inside
    // the real downloader; otherwise the release-level alias retry rejects.
    expect(requestedUrls).toEqual([firstUrl, verifiedUrl]);
    expect(extractZip).toHaveBeenCalledOnce();
    expect(counts).toEqual({ totalFiles: 1, filesScanned: 1 });
    expect(findings.map((finding) => finding.rule)).toEqual([
      "PYPI_OS_SYSTEM",
    ]);
    expect(findings[0]).toEqual(expect.objectContaining({
      file: "artifacts/001-verified.whl/verified_package/payload.py",
    }));
    expect(findings).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ rule: "PATH_SCAN_INCOMPLETE" }),
    ]));
  });
});
