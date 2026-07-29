import { performance } from "node:perf_hooks";
import { describe, expect, it } from "vitest";
import { CORRELATED_PATTERN_MATCHERS } from "../correlated-pattern-matchers.js";
import type { CorrelatedPatternMatcher } from "../types.js";

const EXPECTED_RULES = [
  "PYPI_B64_EXEC_COMBINED",
  "PYPI_CUSTOM_INSTALL",
  "PYPI_CUSTOM_DEVELOP",
  "PYPI_CUSTOM_EGG_INFO",
  "PYPI_CUSTOM_SDIST",
  "PYPI_CUSTOM_BUILD_EXT",
  "PROTESTWARE_IP_GEO_V2",
  "PROXY_HANDLER_TRAP",
  "DROPPER_TEMP_EXEC",
] as const;

const matches = (matcher: CorrelatedPatternMatcher, source: string) =>
  [...matcher(source)];

const expectValidMatches = (
  matcher: CorrelatedPatternMatcher,
  source: string,
  minimum = 1,
) => {
  const found = matches(matcher, source);
  expect(found.length).toBeGreaterThanOrEqual(minimum);
  for (const match of found) {
    expect(match.start).toBeGreaterThanOrEqual(0);
    expect(match.end).toBeGreaterThan(match.start);
    expect(match.end).toBeLessThanOrEqual(source.length);
    expect(match.evidence.length).toBeLessThanOrEqual(240);
  }
  return found;
};

describe("correlated structural pattern matchers", () => {
  it("exports exactly the nine shipped correlated rules", () => {
    expect(Object.keys(CORRELATED_PATTERN_MATCHERS).sort()).toEqual(
      [...EXPECTED_RULES].sort(),
    );
  });

  describe("PyPI cmdclass objects", () => {
    const cases = [
      ["PYPI_CUSTOM_INSTALL", "install"],
      ["PYPI_CUSTOM_DEVELOP", "develop"],
      ["PYPI_CUSTOM_EGG_INFO", "egg_info"],
      ["PYPI_CUSTOM_SDIST", "sdist"],
      ["PYPI_CUSTOM_BUILD_EXT", "build_ext"],
    ] as const;

    it.each(cases)("finds %s only as a key in the cmdclass object", (rule, key) => {
      const source = `setup(\n  name="safe",\n  cmdclass = {\n    '${key}': CustomCommand,\n  },\n)\n`;
      expectValidMatches(CORRELATED_PATTERN_MATCHERS[rule], source);

      const unrelated = `cmdclass = {'other': CustomCommand}\nunrelated = {'${key}': CustomCommand}\n`;
      expect(matches(CORRELATED_PATTERN_MATCHERS[rule], unrelated)).toEqual([]);
    });

    it("discovers an active cmdclass object nested inside an earlier one", () => {
      const source = "setup(cmdclass={'wrapper': (lambda: setup(cmdclass={'install': Evil}))()})";
      expectValidMatches(CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_INSTALL, source);
    });
    it("ignores key-shaped text in comments, values, and nested objects", () => {
      const matcher = CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_INSTALL;
      expect(matches(matcher, "# cmdclass = {'install': Evil}\ncmdclass = {'other': 'install'}\n")).toEqual([]);
      expect(matches(matcher, "cmdclass = {'other': {'install': Evil}}\n")).toEqual([]);
    });
  });

  describe("PYPI_B64_EXEC_COMBINED", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.PYPI_B64_EXEC_COMBINED;

    it.each([
      "exec(base64.b64decode(blob))",
      "payload = base64.b64decode(blob); exec(payload)",
      "payload = base64.b64decode(blob)\nverify(payload)\nexec(payload)",
    ])("detects decoded data reaching exec: %s", (source) => {
      expectValidMatches(matcher, source);
    });

    it("retains a viable decode path across an indented conditional reassignment", () => {
      const source = `payload = base64.b64decode(blob)
if False:
  payload = trusted
exec(payload)`;
      expectValidMatches(matcher, source);
    });
    it.each([
      "payload = base64.b64decode(blob)\n# exec(payload)",
      "payload = base64.b64decode(blob)\nmessage = 'exec(payload)'",
      "payload = base64.b64decode(blob)\nexec(trusted)",
      "payload = base64.b64decode(blob)\npayload = trusted\nexec(payload)",
      "obj.exec(base64.b64decode(blob))",
    ])("rejects non-executable or differently assigned data: %s", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
  });

  describe("PROXY_HANDLER_TRAP", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.PROXY_HANDLER_TRAP;

    it.each([
      "const p = new Proxy(target, { get: (obj, key) => { fetch(key); return obj[key]; } });",
      "const p = new Proxy(target, { set(obj, key, value) { eval(value); obj[key] = value; } });",
      "const p = new Proxy(target, { get: () => `value: ${fetch(secret)}` });",
    ])("detects a hostile operation inside a trap", (source) => {
      expectValidMatches(matcher, source);
    });

    it.each([
      [
        "double-quoted",
        'const p = new Proxy(target, { "get": (obj, key) => { fetch(key); return obj[key]; } });',
      ],
      [
        "single-quoted",
        "const p = new Proxy(target, { 'get': (obj, key) => { fetch(key); return obj[key]; } });",
      ],
      [
        "computed quoted",
        'const p = new Proxy(target, { ["get"]: (obj, key) => { fetch(key); return obj[key]; } });',
      ],
    ])("detects a hostile operation under a %s trap key", (_name, source) => {
      expectValidMatches(matcher, source);
    });
    it("continues past an earlier Proxy whose handler is an identifier", () => {
      const source = "const normal = new Proxy(target, sharedHandler); const hostile = new Proxy(target, { get: () => fetch(secret) });";
      expectValidMatches(matcher, source);
    });

    it("discovers a hostile Proxy nested inside an earlier Proxy call", () => {
      const source = "new Proxy(a, wrap(new Proxy(b, { get: () => fetch(secret) })))";
      const found = expectValidMatches(matcher, source);
      expect(found.some((match) => match.start === source.lastIndexOf("new Proxy"))).toBe(true);
    });
    it.each([
      "const p = new Proxy(target, { get: (obj, key) => obj[key] }); fetch('/api');",
      "const p = new Proxy(target, { helper: () => fetch('/api'), get: (obj, key) => obj[key] });",
      "const p = new Proxy(target, { get: () => 'fetch(secret)' });",
      "const p = new Proxy(target, { get: () => `fetch(secret)` });",
      'const p = new Proxy(target, { "get": (obj, key) => obj[key] }); fetch("/api");',
      "const p = new Proxy(target, { 'get': () => 'fetch(secret)' });",
      'const p = new Proxy(target, { ["get"]: () => "fetch(secret)" });',
      'const sample = \'new Proxy(target, { "get": () => fetch(secret) })\';',
      "// new Proxy(target, { get: () => fetch(secret) })",
    ])("does not borrow hostile-looking text outside executable trap code", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
  });

  describe("PROTESTWARE_IP_GEO_V2", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.PROTESTWARE_IP_GEO_V2;

    it.each([
      "const geo = require('geoip-lite'); if (geo.lookup(ip)) fs.unlinkSync('/data');",
      "const reader = maxmind.open(db); fs.rmSync(process.cwd(), { recursive: true });",
      "ipinfo; execSync('rm -rf /home/service');",
    ])("detects geo-targeted sensitive destruction", (source) => {
      expectValidMatches(matcher, source);
    });

    it("discovers sensitive destruction nested in a safe outer cleanup call", () => {
      expectValidMatches(matcher, "maxmind; rm('/tmp/cache', rmSync('/data'))");
    });

    it("keeps JavaScript private methods executable in mixed lexical mode", () => {
      expectValidMatches(matcher, "const maxmind = 1; class X { #go(){ rmSync('/data') } }");
      expect(matches(matcher, "maxmind; #comment() rmSync('/data')")).toEqual([]);
    });
    it.each([
      "const maxmind = require('maxmind'); fs.unlinkSync(tempArchive);",
      "const maxmind = require('maxmind'); fs.rmSync('/var/tmp/GeoLite2.mmdb');",
      "// maxmind; fs.rmSync('/data')",
      "fs.rmSync('/data'); const maxmind = require('maxmind');",
    ])("rejects safe cleanup, comments, and reversed correlation", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
  });

  describe("DROPPER_TEMP_EXEC", () => {
    const matcher = CORRELATED_PATTERN_MATCHERS.DROPPER_TEMP_EXEC;

    it.each([
      "const p = os.tmpdir() + '/payload.exe'; writeFileSync(p, data); execSync(p);",
      "writeFile(TEMP + '/payload.exe', data); exec(TEMP + '/payload.exe');",
      "write_bytes('/tmp/run.ps1', data); ShellExecute('/tmp/run.ps1');",
    ])("detects the same written and executed path", (source) => {
      expectValidMatches(matcher, source);
    });

    it("records a nested write before a later payload execution", () => {
      const source = "fetch(url); exec('true', writeFileSync('/tmp/payload.exe', data)); execSync('/tmp/payload.exe')";
      expectValidMatches(matcher, source);
    });

    it("keeps JavaScript private methods executable in the shared mixed lexer", () => {
      const source = "class X { #go(){ writeFileSync('/tmp/payload.exe', data); execSync('/tmp/payload.exe') } }";
      expectValidMatches(matcher, source);
    });
    it.each([
      "const a = '/tmp/a.exe'; const b = '/tmp/b.exe'; writeFileSync(a, data); execSync(b);",
      "writeFileSync(installDir + '/package.json', '{}'); child_process.execSync('node --version');",
      "const p = '/tmp/a.exe'; writeFileSync(p, data); p = '/tmp/b.exe'; execSync(p);",
      "const text = \"writeFileSync('/tmp/a.exe'); execSync('/tmp/a.exe')\";",
    ])("rejects mismatched, reassigned, or non-code paths", (source) => {
      expect(matches(matcher, source)).toEqual([]);
    });
  });

  it("finds every correlation beyond 5,000 characters on one physical line", () => {
    const padding = "x++;".repeat(1_300);
    const cases: Array<[CorrelatedPatternMatcher, string]> = [
      [
        CORRELATED_PATTERN_MATCHERS.PYPI_B64_EXEC_COMBINED,
        `payload=base64.b64decode(blob);${padding}exec(payload)`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_INSTALL,
        `cmdclass={${" ".repeat(5_200)}'install':CustomInstall}`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_DEVELOP,
        `cmdclass={${" ".repeat(5_200)}'develop':CustomDevelop}`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_EGG_INFO,
        `cmdclass={${" ".repeat(5_200)}'egg_info':CustomEggInfo}`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_SDIST,
        `cmdclass={${" ".repeat(5_200)}'sdist':CustomSdist}`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PYPI_CUSTOM_BUILD_EXT,
        `cmdclass={${" ".repeat(5_200)}'build_ext':CustomBuildExt}`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PROXY_HANDLER_TRAP,
        `new Proxy(target,{get:(obj,key)=>{${padding}fetch(key);return obj[key]}})`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.PROTESTWARE_IP_GEO_V2,
        `maxmind;${padding}rmSync('/data')`,
      ],
      [
        CORRELATED_PATTERN_MATCHERS.DROPPER_TEMP_EXEC,
        `writeFileSync('/tmp/payload.exe',data);${padding}execSync('/tmp/payload.exe')`,
      ],
    ];

    for (const [matcher, source] of cases) {
      const found = expectValidMatches(matcher, source);
      expect(found[0]!.end - found[0]!.start).toBeGreaterThan(5_000);
      expect(found[0]!.evidence.length).toBe(240);
    }
  });

  it("stays near-linear on 5 MiB adversarial inputs", { timeout: 15_000 }, () => {
    const fiveMiB = 5 * 1024 * 1024;
    const adversarial: Record<(typeof EXPECTED_RULES)[number], string> = {
      PYPI_B64_EXEC_COMBINED: "rm(".repeat(Math.ceil(fiveMiB / 3)).slice(0, fiveMiB),
      PYPI_CUSTOM_INSTALL: "cmdclass={".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
      PYPI_CUSTOM_DEVELOP: "cmdclass={".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
      PYPI_CUSTOM_EGG_INFO: "cmdclass={".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
      PYPI_CUSTOM_SDIST: "cmdclass={".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
      PYPI_CUSTOM_BUILD_EXT: "cmdclass={".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
      PROTESTWARE_IP_GEO_V2: ("maxmind;" + "rm(".repeat(Math.ceil(fiveMiB / 3))).slice(0, fiveMiB),
      PROXY_HANDLER_TRAP: "new Proxy(".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
      DROPPER_TEMP_EXEC: "writeFile(".repeat(Math.ceil(fiveMiB / 10)).slice(0, fiveMiB),
    };

    const started = performance.now();
    for (const rule of EXPECTED_RULES) {
      expect(matches(CORRELATED_PATTERN_MATCHERS[rule], adversarial[rule])).toEqual([]);
    }
    const elapsed = performance.now() - started;
    expect(elapsed).toBeLessThan(10_000);
  });
});