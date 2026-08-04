import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import { beforeEach, describe, expect, it, vi } from "vitest";

const httpsMock = vi.hoisted(() => ({ get: vi.fn() }));

vi.mock("node:https", () => ({
  default: { get: httpsMock.get },
  get: httpsMock.get,
}));

import { scanNpmPackage } from "../npm-scanner.js";
import { scanPypiPackage } from "../pypi-scanner.js";

type ResponseLike = Readable & {
  statusCode: number;
  headers: Record<string, string>;
};

interface ResponseSpec {
  status: number;
  body?: unknown;
  location?: string;
}

function mockResponses(specs: ResponseSpec[]): void {
  let index = 0;
  httpsMock.get.mockImplementation(
    (_options: unknown, callback: (response: ResponseLike) => void) => {
      const spec = specs[index++];
      if (spec === undefined) throw new Error("Unexpected outbound HTTPS request");
      const body = spec.body === undefined
        ? Buffer.alloc(0)
        : Buffer.from(JSON.stringify(spec.body));
      const response = Readable.from([body]) as ResponseLike;
      response.statusCode = spec.status;
      response.headers = spec.location === undefined
        ? {}
        : { location: spec.location };
      const request = new EventEmitter() as EventEmitter & {
        destroy: (error?: Error) => void;
        setTimeout: () => void;
      };
      request.setTimeout = vi.fn();
      request.destroy = (error?: Error) => {
        if (error) request.emit("error", error);
      };
      process.nextTick(() => callback(response));
      return request;
    },
  );
}

function npmMetadata(tarball: string): unknown {
  return {
    "dist-tags": { latest: "1.0.0" },
    versions: {
      "1.0.0": { dist: { tarball } },
    },
  };
}

function pypiMetadata(artifactUrl: string): unknown {
  return {
    info: {
      name: "host-policy-fixture",
      version: "1.0.0",
      home_page: "https://example.test/project",
    },
    urls: [{
      filename: "host_policy_fixture-1.0.0-py3-none-any.whl",
      url: artifactUrl,
      packagetype: "bdist_wheel",
      size: 1,
      digests: { sha256: "0".repeat(64) },
    }],
  };
}

describe("registry download host policies", () => {
  beforeEach(() => {
    httpsMock.get.mockReset();
  });

  it("rejects an npm metadata redirect before requesting the foreign host", async () => {
    mockResponses([{
      status: 302,
      location: "https://registry.npmjs.org.attacker.example/npm-metadata.json",
    }]);

    await expect(scanNpmPackage("host-policy-fixture", { format: "json" }))
      .rejects.toThrow(/non-official host/);
    expect(httpsMock.get).toHaveBeenCalledOnce();
  });

  it("rejects an npm tarball on a non-registry initial host", async () => {
    mockResponses([{
      status: 200,
      body: npmMetadata("https://registry.npmjs.org.attacker.example/package.tgz"),
    }]);

    await expect(scanNpmPackage("host-policy-fixture", { format: "json" }))
      .rejects.toThrow(/non-official host/);
    expect(httpsMock.get).toHaveBeenCalledOnce();
  });

  it("rejects an npm tarball redirect before requesting the foreign host", async () => {
    mockResponses([
      {
        status: 200,
        body: npmMetadata(
          "https://registry.npmjs.org/host-policy-fixture/-/host-policy-fixture-1.0.0.tgz",
        ),
      },
      {
        status: 302,
        location: "https://registry.npmjs.org.attacker.example/package.tgz",
      },
    ]);

    await expect(scanNpmPackage("host-policy-fixture", { format: "json" }))
      .rejects.toThrow(/non-official host/);
    expect(httpsMock.get).toHaveBeenCalledTimes(2);
  });

  it("rejects a PyPI artifact on a non-CDN initial host", async () => {
    mockResponses([{
      status: 200,
      body: pypiMetadata("https://files.pythonhosted.org.attacker.example/package.whl"),
    }]);

    const report = await scanPypiPackage("host-policy-fixture", { format: "json" });
    expect(report.partialScan).toBe(true);
    expect(report.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ rule: "PATH_SCAN_INCOMPLETE" }),
    ]));
    expect(httpsMock.get).toHaveBeenCalledOnce();
  });

  it("rejects a PyPI metadata redirect before requesting the foreign host", async () => {
    mockResponses([{
      status: 302,
      location: "https://pypi.org.attacker.example/pypi-metadata.json",
    }]);

    await expect(scanPypiPackage("host-policy-fixture", { format: "json" }))
      .rejects.toThrow(/non-official host/);
    expect(httpsMock.get).toHaveBeenCalledOnce();
  });

  it("rejects a PyPI artifact redirect before requesting the foreign host", async () => {
    mockResponses([
      {
        status: 200,
        body: pypiMetadata(
          "https://files.pythonhosted.org/packages/aa/host_policy_fixture-1.0.0-py3-none-any.whl",
        ),
      },
      {
        status: 302,
        location: "https://files.pythonhosted.org.attacker.example/package.whl",
      },
    ]);

    const report = await scanPypiPackage("host-policy-fixture", { format: "json" });
    expect(report.partialScan).toBe(true);
    expect(report.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ rule: "PATH_SCAN_INCOMPLETE" }),
    ]));
    expect(httpsMock.get).toHaveBeenCalledTimes(2);
  });
});
