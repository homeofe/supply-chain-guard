import { EventEmitter } from "node:events";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("node:https", () => {
  const mockGet = vi.fn();
  return {
    default: { get: mockGet },
    get: mockGet,
  };
});

import * as https from "node:https";
import { scanPypiPackage } from "../pypi-scanner.js";
import { formatReport, getReportExitCode } from "../reporter.js";

type ResponseLike = EventEmitter & { statusCode?: number };
type MockedGet = ReturnType<typeof vi.fn>;

function mockMetadataResponse(body: unknown): void {
  (https.get as unknown as MockedGet).mockImplementation(
    (_url: unknown, _options: unknown, callback: (response: ResponseLike) => void) => {
      const response = new EventEmitter() as ResponseLike;
      response.statusCode = 200;
      const request = new EventEmitter();

      process.nextTick(() => {
        callback(response);
        response.emit("data", Buffer.from(JSON.stringify(body)));
        response.emit("end");
      });

      return request;
    },
  );
}

beforeEach(() => {
  (https.get as unknown as MockedGet).mockReset();
});

describe("PyPI partial-scan verdict", () => {
  it("fails closed when package metadata exposes no scannable artifact", async () => {
    mockMetadataResponse({
      info: {
        name: "no-artifact-fixture",
        version: "1.0.0",
        home_page: "https://example.com/project",
        project_urls: { Source: "https://example.com/project/source" },
      },
      urls: [],
    });

    const report = await scanPypiPackage("no-artifact-fixture", {
      format: "json",
      minSeverity: "critical",
    });

    expect(report.findings).toHaveLength(0);
    expect(report.summary.info).toBe(0);
    expect(report.partialScan).toBe(true);
    expect(getReportExitCode(report)).toBe(1);

    const output = JSON.parse(formatReport(report, "json")) as {
      partialScan?: boolean;
      recommendations: string[];
    };
    expect(output.partialScan).toBe(true);
    expect(output.recommendations.join(" ")).toMatch(/scan incomplete/i);
    expect(output.recommendations.join(" ")).not.toMatch(/appears (clean|safe)/i);
  });
});
