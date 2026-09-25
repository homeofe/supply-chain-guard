/**
 * A pub manifest the pub scanner cannot read must not end the whole scan: the
 * other files are still scanned and the result says it is partial.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

vi.mock("../pub-scanner.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../pub-scanner.js")>()),
  scanPubContent: () => {
    throw new RangeError("Maximum call stack size exceeded");
  },
}));

import { scan } from "../scanner.js";

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-pub-fail-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("a pub manifest the pub scanner cannot read", () => {
  it("is reported as a partial scan, and the other files are still scanned", async () => {
    fs.writeFileSync(path.join(dir, "pubspec.yaml"), "name: app\ndependencies:\n  a: ^1.0.0\n");
    fs.writeFileSync(path.join(dir, "index.js"), "eval(atob(x));\n");
    const report = await scan({ target: dir, format: "json" });
    const incomplete = report.findings.filter((f) => f.rule === "PATH_SCAN_INCOMPLETE" && f.file === "pubspec.yaml");
    expect(incomplete).toHaveLength(1);
    expect(report.findings.some((f) => f.rule === "EVAL_ATOB" && f.file === "index.js")).toBe(true);
  });
});
