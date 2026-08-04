/**
 * Regression tests for issue #54 (v5.12.0):
 *
 * A. Oversized scannable files are no longer skipped SILENTLY - every scan
 *    family (core, npm, PyPI; VSIX covered in vscode-scanner.test.ts because
 *    it needs the zip binary) emits a structured FILE_TOO_LARGE_SKIPPED
 *    finding (severity "info": never affects exit codes, filterable).
 *
 * B. Threat-intel indicator values are LITERALS, never regexes. Before the
 *    fix, a hostile/malformed remote feed value like "(" threw SyntaxError
 *    inside the per-file loop - swallowed by scanner.ts's per-file catch,
 *    silently disabling every downstream check while the scan exited green.
 *    A valid-but-catastrophic pattern ("(a+)+b") would have been .test()-ed
 *    against full file contents (ReDoS). Now: full metacharacter escaping,
 *    plus quarantine of invalid entries at every feed ingestion point.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { scan } from "../scanner.js";
import { scanExtractedNpmFiles } from "../npm-scanner.js";
import { scanExtractedFiles } from "../pypi-scanner.js";
import {
  checkThreatIntel,
  loadThreatIntel,
  updateThreatFeed,
  isValidFeedIOC,
  normalizeFeedIOC,
  type FeedIOC,
} from "../threat-intel.js";
import { parseFeedPayload } from "../feed.js";
import { MAX_FILE_SIZE } from "../patterns.js";
import type { Finding } from "../types.js";

function makeTempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/** Write a file one byte over the scan limit (content is never read). */
function writeOversized(dir: string, name: string): string {
  const p = path.join(dir, name);
  fs.writeFileSync(p, Buffer.alloc(MAX_FILE_SIZE + 1));
  return p;
}

describe("issue #54: FILE_TOO_LARGE_SKIPPED", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = makeTempDir("scg-issue54-");
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("core scan surfaces an oversized scannable file and still scans the rest", async () => {
    writeOversized(tempDir, "big.js");
    fs.writeFileSync(path.join(tempDir, "evil.js"), 'eval(atob("payload"));');

    const report = await scan({ target: tempDir, format: "text", noHistory: true });

    const skip = report.findings.find((f) => f.rule === "FILE_TOO_LARGE_SKIPPED");
    expect(skip).toBeDefined();
    expect(skip?.severity).toBe("info");
    expect(skip?.file).toBe("big.js");
    // The oversized file got no content findings (it was not read) ...
    expect(
      report.findings.some((f) => f.file === "big.js" && f.rule !== "FILE_TOO_LARGE_SKIPPED"),
    ).toBe(false);
    // ... and scanning of OTHER files was not degraded.
    expect(report.findings.some((f) => f.file === "evil.js")).toBe(true);
    // info severity: no exit-code impact (only critical/high gate exits).
    expect(report.summary.info).toBeGreaterThanOrEqual(1);
  });

  it("core scan does NOT flag an oversized NON-scannable file (extension gate first)", async () => {
    writeOversized(tempDir, "huge.bin");

    const report = await scan({ target: tempDir, format: "text", noHistory: true });

    expect(report.findings.some((f) => f.rule === "FILE_TOO_LARGE_SKIPPED")).toBe(false);
  });

  it("npm tarball walker surfaces an oversized file", () => {
    writeOversized(tempDir, "bundle.js");
    fs.writeFileSync(path.join(tempDir, "evil.js"), 'eval(atob("payload"));');
    const findings: Finding[] = [];

    scanExtractedNpmFiles(tempDir, findings);

    const skip = findings.find((f) => f.rule === "FILE_TOO_LARGE_SKIPPED");
    expect(skip).toBeDefined();
    expect(skip?.severity).toBe("info");
    expect(skip?.file).toBe("bundle.js");
    expect(findings.some((f) => f.file === "evil.js")).toBe(true);
  });

  it("pypi walker surfaces an oversized file (including .py)", () => {
    writeOversized(tempDir, "payload.py");
    const findings: Finding[] = [];

    scanExtractedFiles(tempDir, findings);

    const skip = findings.find((f) => f.rule === "FILE_TOO_LARGE_SKIPPED");
    expect(skip).toBeDefined();
    expect(skip?.file).toBe("payload.py");
  });
});

describe("issue #54: threat-intel indicator hardening", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = makeTempDir("scg-issue54-ti-");
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
    vi.unstubAllGlobals();
  });

  const hostileDomain: FeedIOC = {
    type: "domain",
    value: "(",
    severity: "critical",
    confidence: 0.9,
  };
  const legitDomain: FeedIOC = {
    type: "domain",
    value: "evil-c2.example",
    severity: "critical",
    confidence: 0.9,
  };

  it("checkThreatIntel survives a hostile domain value without losing other matches", () => {
    // Hostile entry FIRST so a throw would abort before the legit entry.
    const findings = checkThreatIntel(
      "callback to evil-c2.example here",
      "index.js",
      [hostileDomain, legitDomain],
    );

    expect(findings.some((f) => f.description.includes("evil-c2.example"))).toBe(true);
  });

  it("indicator values are literal: regex metacharacters do not alter matching", () => {
    const alternation: FeedIOC = {
      type: "domain",
      value: "evil|benign.example",
      severity: "high",
      confidence: 0.9,
    };
    // Pre-fix, the unescaped "|" made this regex match ANY content
    // containing "evil" OR "benign.example". Literal semantics must not.
    expect(checkThreatIntel("evil code here", "a.js", [alternation])).toHaveLength(0);
    expect(checkThreatIntel("benign.example is fine", "a.js", [alternation])).toHaveLength(0);
    // The exact literal still matches.
    expect(checkThreatIntel("hit evil|benign.example now", "a.js", [alternation])).toHaveLength(1);
  });

  it("a ReDoS-shaped value is treated as a literal (no catastrophic backtracking)", () => {
    const redos: FeedIOC = { type: "domain", value: "(a+)+b", severity: "high", confidence: 0.9 };
    const started = Date.now();
    const findings = checkThreatIntel("a".repeat(5000) + "c", "a.js", [redos]);
    expect(findings).toHaveLength(0);
    expect(checkThreatIntel("literal (a+)+b here", "a.js", [redos])).toHaveLength(1);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("loadThreatIntel quarantines invalid cached entries and keeps valid ones", () => {
    const entries = [
      legitDomain,
      { type: "regex", value: ".*", severity: "critical" }, // unknown type
      { type: "domain", value: "", severity: "critical" }, // empty value
      { type: "domain", value: "(", severity: "critical" }, // not a domain shape
      { type: "domain", value: "evil).example|", severity: "critical" }, // metachars
      { type: "hash", value: "not-a-hex-digest", severity: "critical" }, // bad shape
      { type: "domain", value: "x".repeat(3000), severity: "critical" }, // oversized
      { type: "domain", value: 42, severity: "critical" }, // non-string
      null,
    ];
    fs.writeFileSync(
      path.join(tempDir, "threat-feed.json"),
      JSON.stringify({ timestamp: new Date().toISOString(), entries }, null, 2),
    );

    const feed = loadThreatIntel(tempDir);

    expect(feed.some((i) => i.value === "evil-c2.example")).toBe(true);
    expect(feed.some((i) => i.type === "regex")).toBe(false);
    expect(feed.some((i) => i.value === "(" || i.value === "evil).example|" || i.value === "not-a-hex-digest")).toBe(false);
    expect(feed.some((i) => typeof i.value !== "string" || i.value.length === 0 || i.value.length > 2048)).toBe(false);
  });

  it("parseFeedPayload hard-rejects entries violating the indicator contract", () => {
    const badType = JSON.stringify({ schema: 1, entries: [{ type: "regex", value: ".*", severity: "high" }] });
    const oversized = JSON.stringify({ schema: 1, entries: [{ type: "domain", value: "x".repeat(3000), severity: "high" }] });
    const badShape = JSON.stringify({ schema: 1, entries: [{ type: "domain", value: "(", severity: "high" }] });

    expect(() => parseFeedPayload(badType)).toThrow(/invalid feed entry/);
    expect(() => parseFeedPayload(oversized)).toThrow(/invalid feed entry/);
    expect(() => parseFeedPayload(badShape)).toThrow(/invalid feed entry/);
  });

  it("updateThreatFeed filters invalid entries before writing the cache", async () => {
    vi.stubGlobal("fetch", async () => ({
      ok: true,
      json: async () => [legitDomain, { type: "regex", value: "(", severity: "critical" }],
    }));

    const result = await updateThreatFeed("https://github.com/homeofe/supply-chain-guard/raw/main/feed.json", tempDir);

    expect(result.added).toBe(1);
    const cached = JSON.parse(fs.readFileSync(path.join(tempDir, "threat-feed.json"), "utf-8"));
    expect(cached.entries).toHaveLength(1);
    expect(cached.entries[0].value).toBe("evil-c2.example");
  });

  it("isValidFeedIOC accepts every entry of the bundled feed (contract self-check)", () => {
    const bundled = loadThreatIntel(makeTempDir("scg-issue54-empty-"));
    expect(bundled.length).toBeGreaterThan(100);
    expect(bundled.every((e) => isValidFeedIOC(e))).toBe(true);
  });

  it("rejects degenerate ip/url flood values (v5.12.0 gate findings)", () => {
    // Substring-matched types need structural minimums, not just charsets:
    // an accepted "." or "e" would critical-match virtually every file.
    for (const value of [".", ":", "e", "cafe", "1.2.3", "1.2.3.4.5", "::", ":::", "..::", "a::"]) {
      expect(isValidFeedIOC({ type: "ip", value, severity: "critical" })).toBe(false);
    }
    for (const value of ["(", "/", "=", "a.b", "short"]) {
      expect(isValidFeedIOC({ type: "url", value, severity: "critical" })).toBe(false);
    }
    // Real indicators still pass (incl. bundled 0x wallet-address urls).
    expect(isValidFeedIOC({ type: "ip", value: "216.126.236.244", severity: "critical" })).toBe(true);
    expect(isValidFeedIOC({ type: "ip", value: "2001:db8::1", severity: "critical" })).toBe(true);
    expect(isValidFeedIOC({ type: "ip", value: "fe80::1", severity: "critical" })).toBe(true);
    expect(isValidFeedIOC({ type: "url", value: "0xc12c8d8f9706244eca0acf04e880f10ff4e52522", severity: "critical" })).toBe(true);
    expect(isValidFeedIOC({ type: "url", value: "216.126.225.243:8087/api/notify", severity: "critical" })).toBe(true);
  });

  it("rejects structurally implausible domain indicators", () => {
    for (const value of ["e.g", "a.1", "example.c", `${"a".repeat(64)}.example`]) {
      expect(isValidFeedIOC({ type: "domain", value, severity: "critical" }), value).toBe(false);
    }

    for (const value of ["a.co", "c2.example", "api.evil.xn--p1ai"]) {
      expect(isValidFeedIOC({ type: "domain", value, severity: "critical" }), value).toBe(true);
    }
  });

  it("matches domain IOCs only at hostname boundaries", () => {
    const domain: FeedIOC = {
      type: "domain",
      value: "example.com",
      severity: "critical",
      confidence: 0.9,
    };

    for (const content of [
      "example.com",
      'fetch("https://example.com/beacon")',
      'fetch("https://api.example.com/beacon")',
      'const host = "example.com.";',
    ]) {
      expect(checkThreatIntel(content, "payload.js", [domain]), content).toHaveLength(1);
    }

    for (const content of [
      'fetch("https://notexample.com/beacon")',
      'fetch("https://example.com.attacker.test/beacon")',
      'const packageName = "example.com-client";',
    ]) {
      expect(checkThreatIntel(content, "clean.js", [domain]), content).toHaveLength(0);
    }
  });

  it("rejects ordinary code tokens as url indicators", () => {
    // A charset+length floor is not enough. Every type:"url" entry is
    // substring-matched against whole file contents at its own severity, so a
    // value like "process.env" would flag every repository as critical. These
    // all passed the previous /^[\x21-\x7e]{8,}$/ shape.
    for (const value of [
      "require(", "function", "process.env", "module.exports", "console.log",
      "Object.keys", "Array.isArray", "JSON.stringify", "String.raw", "process.argv",
      "index.js", "README.md", "package.json", "tsconfig.json", "src/index.ts",
      "node_modules/.bin", "../../etc/passwd", "</script>", "0xdeadbeef",
      "application/json", "child_process", "import.meta", "path.resolve",
    ]) {
      expect(isValidFeedIOC({ type: "url", value, severity: "critical" }), value).toBe(false);
    }
  });

  it("accepts every url indicator shape a real campaign produces", () => {
    // Guards against over-tightening: rejecting a legitimate shape would make
    // parseFeedPayload throw on the whole document, silently disabling the
    // same-day protection channel for everyone.
    for (const value of [
      "https://evil-c2.example.com/beacon",
      "//cdn.evil.example/loader.js",
      "http://185.199.108.153/payload.sh",
      "evil.example.com:8443/gate.php",
      "216.126.225.243:8087",
      "http://evil.example.com?id=1",
      "https://user:pass@evil.example.com/x",
      "https://evil.xn--p1ai/loader.js",
      "steamcommunity.com/profiles/76561198721263282",
      "0xC12C8D8F9706244ECA0ACF04E880F10FF4E52522",
    ]) {
      expect(isValidFeedIOC({ type: "url", value, severity: "critical" }), value).toBe(true);
    }
  });

  it("the published feed.json still passes the current validator", () => {
    // The exact failure a stricter shape creates: parseFeedPayload rejects the
    // ENTIRE document on one invalid entry, and DEFAULT_FEED_URL is unversioned,
    // so an over-strict floor would break refresh for every installed client.
    const feedPath = fileURLToPath(new URL("../../feed.json", import.meta.url));
    const doc = JSON.parse(fs.readFileSync(feedPath, "utf-8")) as {
      iocs?: unknown[];
      entries?: unknown[];
    };
    const entries = (doc.iocs ?? doc.entries ?? []) as Array<{ type: string; value: string }>;
    expect(entries.length).toBeGreaterThan(100);
    const rejected = entries.filter((e) => !isValidFeedIOC(e));
    expect(
      rejected.map((e) => `${e.type}:${e.value}`),
      "published feed.json entries rejected by the validator",
    ).toEqual([]);
  });

  it("rejects unknown severity and malformed confidence (would break score math)", () => {
    expect(isValidFeedIOC({ type: "domain", value: "a.example", severity: "banana" })).toBe(false);
    expect(isValidFeedIOC({ type: "domain", value: "a.example", severity: "critical", confidence: "high" })).toBe(false);
    expect(isValidFeedIOC({ type: "domain", value: "a.example", severity: "critical", confidence: 7 })).toBe(false);
    expect(isValidFeedIOC({ type: "domain", value: "a.example", severity: "critical" })).toBe(true); // confidence optional
    expect(isValidFeedIOC({ type: "domain", value: "a.example", severity: "critical", confidence: 0.9 })).toBe(true);
    // Falsy/NaN traps: 0 is a valid number, NaN is not.
    expect(isValidFeedIOC({ type: "domain", value: "a.example", severity: "critical", confidence: 0 })).toBe(true);
    expect(isValidFeedIOC({ type: "domain", value: "a.example", severity: "critical", confidence: NaN })).toBe(false);
  });

  it("normalizes missing confidence before firstSeen decay", () => {
    const [normalized] = parseFeedPayload(JSON.stringify({
      schema: 1,
      entries: [{
        type: "domain",
        value: "missing-confidence.example",
        severity: "high",
        firstSeen: "2026-01-01",
        unexpected: { attackerControlled: true },
      }],
    }));

    expect(normalized.confidence).toBe(0.95);
    expect(normalized).not.toHaveProperty("unexpected");
    const findings = checkThreatIntel(
      "https://missing-confidence.example/payload",
      "payload.js",
      [normalized],
    );
    expect(findings).toHaveLength(1);
    expect(Number.isFinite(findings[0].confidence)).toBe(true);
    expect(findings[0].confidence).toBeGreaterThanOrEqual(0);
    expect(findings[0].confidence).toBeLessThanOrEqual(0.95);
  });

  it("does not let future firstSeen dates increase confidence", () => {
    const normalized = normalizeFeedIOC({
      type: "domain",
      value: "future.example",
      severity: "high",
      confidence: 0.95,
      firstSeen: "2999-01-01",
    });

    const findings = checkThreatIntel("future.example", "payload.js", [normalized]);
    expect(findings).toHaveLength(1);
    expect(findings[0].confidence).toBe(0.95);
  });

  it("rejects malformed feed dates and metadata", () => {
    const base = { type: "domain", value: "a.example", severity: "critical" } as const;

    for (const invalid of [
      { ...base, firstSeen: "not-a-date" },
      { ...base, firstSeen: "2026-02-30" },
      { ...base, firstSeen: "2026-01-02", lastSeen: "2026-01-01" },
      { ...base, family: 42 },
      { ...base, campaign: "bad\nmetadata" },
      { ...base, source: "x".repeat(513) },
    ]) {
      expect(isValidFeedIOC(invalid), JSON.stringify(invalid)).toBe(false);
    }

    expect(isValidFeedIOC({
      ...base,
      firstSeen: "2026-01-01T12:30:45Z",
      lastSeen: "2026-01-02T00:00:00+01:00",
      source: "curated-feed",
    })).toBe(true);
  });

  it("skills-scanner surfaces an oversized agent-rules file (parity with the 4 main families)", async () => {
    const { scanAgentSkillFiles } = await import("../skills-scanner.js");
    const dir = makeTempDir("scg-issue54-skills-");
    try {
      fs.writeFileSync(path.join(dir, "CLAUDE.md"), Buffer.alloc(MAX_FILE_SIZE + 1));
      const findings = scanAgentSkillFiles(dir);
      const skip = findings.find((f) => f.rule === "FILE_TOO_LARGE_SKIPPED");
      expect(skip).toBeDefined();
      expect(skip?.file).toBe("CLAUDE.md");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
