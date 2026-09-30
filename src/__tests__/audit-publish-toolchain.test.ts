import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
// @ts-expect-error - plain ESM script without type declarations
import { evaluate } from "../../scripts/audit-publish-toolchain.mjs";

// The publish-preflight job audits the pinned npm through this script instead
// of plain `npm audit`, so that an advisory in a package npm BUNDLES (fixable
// only by a new npm release) can be accepted for a reviewed, dated window.
// These tests hold the other half of that bargain: everything else stays red.

const ROOT = path.resolve(__dirname, "..", "..");
const SCRIPT = path.join(ROOT, "scripts", "audit-publish-toolchain.mjs");
const TODAY = "2026-09-30";

type Advisory = { source: number; name: string; dependency: string; title: string; url: string; severity: string; range: string };
const adv = (id: string, pkg: string, severity: string): Advisory => ({
  source: 1,
  name: pkg,
  dependency: pkg,
  title: `advisory ${id}`,
  url: `https://github.com/advisories/${id}`,
  severity,
  range: "<9",
});

// Shape of `npm audit --json` (auditReportVersion 2) for npm 11.19.1, measured
// 2026-09-30, cut to the fields the script reads.
function report(extra: Record<string, Advisory[]> = {}) {
  const vulns: Record<string, { name: string; severity: string; via: (Advisory | string)[] }> = {
    "brace-expansion": {
      name: "brace-expansion",
      severity: "high",
      via: [
        adv("GHSA-q2hr-2g5m-vwhr", "brace-expansion", "moderate"),
        adv("GHSA-qhr7-859c-m2p7", "brace-expansion", "high"),
        adv("GHSA-6j4f-fj2g-mc7p", "brace-expansion", "high"),
      ],
    },
    "ip-address": {
      name: "ip-address",
      severity: "moderate",
      via: [adv("GHSA-rpw4-54j3-4h4q", "ip-address", "moderate")],
    },
    undici: {
      name: "undici",
      severity: "high",
      via: [adv("GHSA-r53p-7pc4-xj5r", "undici", "low"), adv("GHSA-rfgv-xxqx-mfg5", "undici", "high")],
    },
    minimatch: { name: "minimatch", severity: "high", via: ["brace-expansion"] },
  };
  for (const [pkg, advisories] of Object.entries(extra)) {
    vulns[pkg] = { name: pkg, severity: "high", via: advisories };
  }
  return { auditReportVersion: 2, vulnerabilities: vulns, metadata: {} };
}

const exception = (ghsa: string, pkg: string, expires = "2026-10-31") => ({
  ghsa,
  package: pkg,
  reason: "bundled in the pinned npm, not reachable from npm publish",
  expires,
});
const EXCEPTIONS = [
  exception("GHSA-qhr7-859c-m2p7", "brace-expansion"),
  exception("GHSA-6j4f-fj2g-mc7p", "brace-expansion"),
  exception("GHSA-rfgv-xxqx-mfg5", "undici"),
];
const run = (r: unknown, e: unknown, level = "high") => evaluate(r, e, { level, today: TODAY });

describe("audit-publish-toolchain", () => {
  it("passes the measured report when its three high advisories are excepted", () => {
    const { errors, excepted } = run(report(), EXCEPTIONS);
    expect(errors).toEqual([]);
    expect(excepted).toHaveLength(3);
  });

  it("fails on the same report with no exceptions, like plain npm audit", () => {
    const { errors } = run(report(), []);
    expect(errors).toHaveLength(3);
    expect(errors.join("\n")).toMatch(/GHSA-rfgv-xxqx-mfg5 is not excepted/);
  });

  it("fails on any unlisted advisory at the threshold, even in an excepted package", () => {
    const foreign = run(report({ tar: [adv("GHSA-xxxx-xxxx-xxxx", "tar", "high")] }), EXCEPTIONS);
    expect(foreign.errors).toEqual([expect.stringMatching(/^tar: high advisory GHSA-xxxx-xxxx-xxxx is not excepted/)]);

    const r = report();
    r.vulnerabilities.undici.via.push(adv("GHSA-2222-3333-4444", "undici", "critical"));
    expect(run(r, EXCEPTIONS).errors).toEqual([expect.stringMatching(/GHSA-2222-3333-4444 is not excepted/)]);
  });

  it("ignores advisories below the threshold without an exception", () => {
    const r = report({ semver: [adv("GHSA-5555-6666-7777", "semver", "moderate")] });
    expect(run(r, EXCEPTIONS).errors).toEqual([]);
    expect(run(r, EXCEPTIONS, "moderate").errors.length).toBeGreaterThan(0);
  });

  it("binds an exception to its package, not only to its id", () => {
    const moved = [...EXCEPTIONS.slice(0, 2), exception("GHSA-rfgv-xxqx-mfg5", "node-gyp")];
    const { errors } = run(report(), moved);
    expect(errors).toContain("undici: high advisory GHSA-rfgv-xxqx-mfg5 is not excepted: advisory GHSA-rfgv-xxqx-mfg5");
    expect(errors.join("\n")).toMatch(/GHSA-rfgv-xxqx-mfg5 for node-gyp matches nothing/);
  });

  it("fails on an expired exception, and accepts one expiring today", () => {
    const expired = [...EXCEPTIONS.slice(1), exception("GHSA-qhr7-859c-m2p7", "brace-expansion", "2026-09-29")];
    expect(run(report(), expired).errors).toEqual([expect.stringMatching(/expired on 2026-09-29/)]);
    const lastDay = [...EXCEPTIONS.slice(1), exception("GHSA-qhr7-859c-m2p7", "brace-expansion", TODAY)];
    expect(run(report(), lastDay).errors).toEqual([]);
  });

  it("fails on an exception the report no longer contains, so a pin bump empties the list", () => {
    const r = report();
    delete (r.vulnerabilities as Record<string, unknown>).undici;
    expect(run(r, EXCEPTIONS).errors).toEqual([expect.stringMatching(/GHSA-rfgv-xxqx-mfg5 for undici matches nothing/)]);
  });

  it("rejects malformed exceptions", () => {
    const bad = [...EXCEPTIONS, { ghsa: "CVE-2026-1", package: "x", reason: "short", expires: "soon" }];
    const text = run(report(), bad).errors.join("\n");
    expect(text).toMatch(/"ghsa" must be a GHSA id/);
    expect(text).toMatch(/"reason" must explain/);
    expect(text).toMatch(/"expires" must be a YYYY-MM-DD date/);
    expect(run(report(), [...EXCEPTIONS, EXCEPTIONS[0]]).errors.join("\n")).toMatch(/listed twice/);
  });

  it("fails closed on a report it cannot read", () => {
    for (const r of [null, "", {}, { error: { code: "ENOTFOUND" } }, { vulnerabilities: null }]) {
      expect(run(r, EXCEPTIONS).errors).toEqual([expect.stringMatching(/could not be read/)]);
    }
  });

  it("keeps the committed exceptions well-formed", () => {
    const committed = JSON.parse(
      fs.readFileSync(path.join(ROOT, ".github", "publish-toolchain", "audit-exceptions.json"), "utf8"),
    );
    expect(Array.isArray(committed)).toBe(true);
    // The structural checks, without the report-dependent ones.
    const { errors } = evaluate({ vulnerabilities: {} }, committed, { level: "high", today: "2000-01-01" });
    expect(errors.filter((e: string) => !/matches nothing/.test(e))).toEqual([]);
  });

  it("decides from the report, not from the exit status, when run as a command", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-audit-"));
    try {
      const file = path.join(dir, "report.json");
      const committed = JSON.parse(
        fs.readFileSync(path.join(ROOT, ".github", "publish-toolchain", "audit-exceptions.json"), "utf8"),
      ) as { ghsa: string; package: string }[];
      const r = { auditReportVersion: 2, vulnerabilities: {} as Record<string, unknown> };
      for (const e of committed) {
        const v = (r.vulnerabilities[e.package] ??= { name: e.package, severity: "high", via: [] }) as { via: Advisory[] };
        v.via.push(adv(e.ghsa, e.package, "high"));
      }
      fs.writeFileSync(file, JSON.stringify(r));
      const ok = execFileSync(process.execPath, [SCRIPT, "--audit-level=high", "--report", file, "--today", TODAY], {
        encoding: "utf8",
      });
      expect(ok).toMatch(/audit: OK/);

      (r.vulnerabilities as Record<string, unknown>).tar = { name: "tar", severity: "high", via: [adv("GHSA-xxxx-xxxx-xxxx", "tar", "high")] };
      fs.writeFileSync(file, JSON.stringify(r));
      let status = 0;
      let stderr = "";
      try {
        execFileSync(process.execPath, [SCRIPT, "--audit-level=high", "--report", file, "--today", TODAY], {
          encoding: "utf8",
          stdio: "pipe",
        });
      } catch (err) {
        status = (err as { status: number }).status;
        stderr = String((err as { stderr: string }).stderr);
      }
      expect(status).toBe(1);
      expect(stderr).toMatch(/FAIL tar: high advisory GHSA-xxxx-xxxx-xxxx/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
