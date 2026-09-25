import { describe, it, expect, vi, beforeEach, afterAll } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// Record every outbound HTTPS request instead of making it. The README
// promises that `scan` on a local path makes zero network requests unless
// --check-registry is passed; until this was measured, every scan of a Python
// project sent each dependency name to pypi.org.
const requested: string[] = [];
vi.mock("node:https", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:https")>();
  const refuse = (url: unknown) => {
    requested.push(String(url));
    const req = { on: (event: string, cb: (e: Error) => void) => { if (event === "error") setImmediate(() => cb(new Error("offline test"))); return req; }, end: () => req, setTimeout: () => req, destroy: () => req };
    return req;
  };
  return { ...actual, default: { ...actual, get: refuse, request: refuse }, get: refuse, request: refuse };
});

const { scan } = await import("../scanner.js");

const root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-offline-"));
afterAll(() => fs.rmSync(root, { recursive: true, force: true }));

function project(name: string): string {
  const dir = path.join(root, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "requirements.txt"), "requests==2.31.0\nacme-internal-utils==1.0\npython-utils-helper\n");
  fs.writeFileSync(path.join(dir, "pyproject.toml"), '[project]\nname = "fx"\ndependencies = ["flask>=3"]\n');
  return dir;
}

describe("local scan network contract", () => {
  beforeEach(() => { requested.length = 0; });

  it("sends no dependency name anywhere by default, and keeps the offline checks", async () => {
    const report = await scan({ target: project("default"), format: "json", noHistory: true });
    expect(requested).toEqual([]);
    expect(report.findings.some((f) => f.rule === "DEP_HALLUCINATED_PACKAGE" && f.match === "python-utils-helper")).toBe(true);
  });

  it("queries PyPI only with --check-registry", async () => {
    await scan({ target: project("opt-in"), format: "json", noHistory: true, checkRegistry: true });
    expect(requested.some((u) => u.includes("pypi.org/pypi/requests/json"))).toBe(true);
  });
});
