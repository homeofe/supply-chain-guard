import { describe, expect, it } from "vitest";
import { performanceBudget } from "./performance-budget.js";
import { scanInternalDisclosure } from "../internal-disclosure.js";
import { isPatternApplicableToFile, TEST_FILE_PATTERN } from "../pattern-applicability.js";
import type { Finding } from "../types.js";

/**
 * Precision fixes for the internal-disclosure family: each block pairs the
 * false positive that motivated a change with the true positives that must
 * keep firing after it. The private literals below are required by the shapes
 * under test; everything else uses reserved documentation names.
 */

function scanLines(file: string, ...lines: string[]): Finding[] {
  return scanInternalDisclosure(lines.join("\n"), file);
}

function ofRule(findings: Finding[], rule: string): Finding[] {
  return findings.filter((f) => f.rule === rule);
}

// ---------------------------------------------------------------------------
// Test-file classification (pytest prefix form)
// ---------------------------------------------------------------------------

const PYTEST_BODY = [
  "from pkg.net import is_private",
  "",
  "def test_rfc1918():",
  '    assert is_private("10.1.2.3")',
];

describe("test-file classification: pytest test_*.py", () => {
  it("exempts both pytest default forms from the disclosure rules", () => {
    for (const file of ["pkg/test_net.py", "pkg/net_test.py", "test_net.py", "Pkg/Test_Net.PY"]) {
      expect(ofRule(scanLines(file, ...PYTEST_BODY), "INTERNAL_PRIVATE_IP"), file).toHaveLength(0);
    }
  });

  it("still reports the same literal in names that only resemble a test", () => {
    for (const file of [
      "pkg/net.py",
      "pkg/testing.py",
      "pkg/latest_net.py",
      "pkg/contest.py",
      "pkg/test_net.pyc.txt",
      "pkg/test_net.ts",
      "pkg/mytest_net.py",
      "pkg/test_dir/net.py",
    ]) {
      const found = ofRule(scanLines(file, ...PYTEST_BODY), "INTERNAL_PRIVATE_IP");
      expect(found, file).toHaveLength(1);
      expect(found[0].severity, file).toBe("medium");
    }
  });

  it("keeps every notTestFile PatternEntry armed on test_*.py", () => {
    // The scanned package names its own files, so the pytest prefix form must
    // not exempt the malware rules: `eval(atob(...))` in `test_backdoor.py`
    // would scan clean. Only the disclosure family opts in (above).
    const guarded = {
      notTestFile: true,
    };
    for (const file of ["pkg/test_net.py", "test_net.py", "pkg/net.py", "pkg/testing.py", "pkg/contest.py"]) {
      expect(isPatternApplicableToFile(guarded, "", file), file).toBe(true);
    }
    expect(isPatternApplicableToFile(guarded, "", "pkg/net_test.py")).toBe(false);
  });

  /**
   * The two test-path regexes share their file-name forms and a directory core.
   * They differ ONLY in the directory names listed below, which the disclosure
   * family keeps armed on purpose, and in pytest's `test_*.py` prefix form,
   * which only the disclosure family treats as a test (see the TEST_FILE
   * comment in internal-disclosure.ts). A new difference fails this test.
   */
  const SHARED_FIXTURES: Array<[string, boolean]> = [
    ["src/net.ts", false],
    ["src/net.test.ts", true],
    ["src/net.spec.ts", true],
    ["src/net-mock.js", true],
    ["src/net_fixture.json", true],
    ["src/net.stub.ts", true],
    ["src/net.fake.ts", true],
    ["pkg/net_test.py", true],
    ["pkg/conftest.py", true],
    ["pkg/testing.py", false],
    ["pkg/latest_net.py", false],
    ["pkg/contest.py", false],
    ["pkg/test_net.ts", false],
    ["test/net.ts", true],
    ["tests/net.ts", true],
    ["a/__tests__/net.ts", true],
    ["a/__fixtures__/net.ts", true],
    ["a/__mocks__/net.ts", true],
    ["a/__snapshots__/net.ts", true],
    ["e2e/net.ts", true],
    ["integration-tests/net.ts", true],
    ["fixtures/net.ts", true],
    ["testdata/net.ts", true],
    ["test-data/net.ts", true],
    ["src/latest/net.ts", false],
    ["src/contest/net.ts", false],
  ];
  const APPLICABILITY_ONLY_DIRS = [
    "spec/net.ts",
    "specs/net.ts",
    "snapshot/net.ts",
    "snapshots/net.ts",
    "test-fixtures/net.ts",
    "mock/net.ts",
    "mocks/net.ts",
    "stub/net.ts",
    "stubs/net.ts",
    "fake/net.ts",
    "fakes/net.ts",
  ];
  const DISCLOSURE_ONLY_PYTEST = ["pkg/test_net.py", "test_net.py", "a/b/test_x.py"];
  const LITERAL = 'const peer = "10.20.30.40";';

  it("classifies a shared fixture list identically in both regexes", () => {
    for (const [file, isTest] of SHARED_FIXTURES) {
      expect(TEST_FILE_PATTERN.test(file), `applicability: ${file}`).toBe(isTest);
      const disclosureExempt = ofRule(scanLines(file, LITERAL), "INTERNAL_PRIVATE_IP").length === 0;
      expect(disclosureExempt, `disclosure: ${file}`).toBe(isTest);
    }
  });

  it("adds the pytest prefix form to the disclosure matcher only, against the previous matchers", () => {
    // The two literals as they stood before they were rebuilt from shared parts.
    const previousApplicability =
      /(?:^|\/)(?:tests?|specs?|__tests__|__fixtures__|__mocks__|__snapshots__|snapshots?|e2e|integration-tests?|test-fixtures?|fixtures?|testdata|test-data|mocks?|stubs?|fakes?)\/|[._-](?:test|spec|mock|fixture|stub|fake)\.|(?:^|\/)conftest\.py$/i;
    const previousDisclosure =
      /(?:^|\/)(?:tests?|__tests__|__fixtures__|__mocks__|__snapshots__|e2e|integration-tests?|fixtures?|testdata|test-data)\/|[._-](?:test|spec|mock|fixture|stub|fake)\.|(?:^|\/)conftest\.py$/i;
    const pytestPrefix = /(?:^|\/)test_[^/]*\.py$/i;
    const paths = [
      ...SHARED_FIXTURES.map(([file]) => file),
      ...APPLICABILITY_ONLY_DIRS,
      "Tests/Net.ts",
      "SPEC/net.ts",
      "src/specs.ts",
      "src/mocks.ts",
      "a/b/test_x.py",
      "a/test_/x.py",
      "a/_test_x.py",
      "test_.py",
    ];
    for (const file of paths) {
      const added = pytestPrefix.test(file);
      expect(TEST_FILE_PATTERN.test(file), `applicability: ${file}`).toBe(previousApplicability.test(file));
      const disclosureExempt = ofRule(scanLines(file, LITERAL), "INTERNAL_PRIVATE_IP").length === 0;
      expect(disclosureExempt, `disclosure: ${file}`).toBe(previousDisclosure.test(file) || added);
    }
  });

  it("differs only in the enumerated directory names, which disclosure keeps armed", () => {
    for (const file of APPLICABILITY_ONLY_DIRS) {
      expect(TEST_FILE_PATTERN.test(file), `applicability: ${file}`).toBe(true);
      expect(ofRule(scanLines(file, LITERAL), "INTERNAL_PRIVATE_IP"), `disclosure: ${file}`).toHaveLength(1);
    }
  });

  it("differs in the pytest prefix form, which only disclosure treats as a test", () => {
    for (const file of DISCLOSURE_ONLY_PYTEST) {
      expect(TEST_FILE_PATTERN.test(file), `applicability: ${file}`).toBe(false);
      expect(ofRule(scanLines(file, LITERAL), "INTERNAL_PRIVATE_IP"), `disclosure: ${file}`).toHaveLength(0);
    }
  });
});

// ---------------------------------------------------------------------------
// GCP metadata hostname
// ---------------------------------------------------------------------------

describe("INTERNAL_HOSTNAME: the GCP metadata hostname", () => {
  it("does not report metadata.google.internal", () => {
    const cases: Array<[string, string]> = [
      ["src/ssrf.ts", 'export const BLOCKED_HOSTS = new Set(["localhost", "metadata.google.internal"]);'],
      ["src/ssrf.ts", 'const url = "http://metadata.google.internal/computeMetadata/v1/";'],
      ["src/ssrf.ts", 'const url = "http://metadata.google.internal:80/computeMetadata/v1/";'],
      ["docs/ssrf.md", "The deny list blocks metadata.google.internal by name."],
    ];
    for (const [file, line] of cases) {
      expect(scanLines(file, line), line).toHaveLength(0);
    }
  });

  it("still reports other names in the same TLD", () => {
    for (const host of ["db.internal", "metadata.internal", "metadata.corp.internal", "x.metadata.google.internal"]) {
      const found = ofRule(scanLines("src/ssrf.ts", `const h = "${host}";`), "INTERNAL_HOSTNAME");
      expect(found, host).toHaveLength(1);
      expect(found[0].severity).toBe("medium");
    }
  });
});

// ---------------------------------------------------------------------------
// Dotted identifiers that are not hosts
// ---------------------------------------------------------------------------

describe("INTERNAL_HOSTNAME: dotted keys and replacement fields", () => {
  it("does not report a dotted identifier path in key position", () => {
    const cases: Array<[string, string[]]> = [
      ["src/i18n/en.ts", ['export const en = { "status.internal": "Internal", "nav.home": "Home" };']],
      ["src/i18n/en.ts", ["export const en = {", '  "status.internal": "Internal",', "  'nav.home': 'Home',", "};"]],
      ["src/i18n/types.ts", ["interface Catalogue {", '  "status.internal"?: string;', "}"]],
      ["locales/en.json", ['{ "nav.home": "Home", "status.internal": "Internal" }']],
      ["locales/en.json", ["{", '  "status.internal": "Internal",', '  "nav.home" : "Home"', "}"]],
      ["app/i18n.py", ['LABELS = {"status.internal": "Internal", "nav.home": "Home"}']],
    ];
    for (const [file, lines] of cases) {
      expect(ofRule(scanLines(file, ...lines), "INTERNAL_HOSTNAME"), `${file}: ${lines.join(" ")}`).toHaveLength(0);
    }
  });

  it("does not report attribute access inside a replacement field", () => {
    const cases: Array<[string, string]> = [
      ["tools/report.py", 'print(f"{report.local} local reference(s) exempt")'],
      ["tools/report.py", "print(F'{report.local:>4} local')"],
      ["tools/report.py", 'print(rf"{a.b.local} and {counts.home}")'],
      ["src/log.js", "console.log(`${counts.local} local actions`)"],
      ["src/log.ts", "const s = `total ${a + counts.local} and ${ stats.home }`;"],
    ];
    for (const [file, line] of cases) {
      expect(ofRule(scanLines(file, line), "INTERNAL_HOSTNAME"), line).toHaveLength(0);
    }
  });

  it("still reports hosts in value position, as values, behind a scheme, and in the literal part of a string", () => {
    const cases: Array<[string, string[]]> = [
      ["src/config.ts", ['const DB_HOST = "db.internal";']],
      ["config/app.json", ['{"host": "build.corp"}']],
      ["config/app.json", ['{"http://git.lan/repo": 1}']],
      ["app/db.py", ['DSN = f"postgres://{user}@db.internal/app"']],
      // Shapes a key-position rule must not swallow.
      ["src/config.ts", ['const h = prod ? "db.internal" : "other.example";']],
      ["src/config.ts", ['switch (h) { case "db.internal": return 1; }']],
      ["config/hosts.json", ['{"db.internal": {"port": 5432}}']],
      ["config/hosts.json", ["{", '  "db.internal": [5432]', "}"]],
      // Value on the next line (CRLF file): unknown, so the key still reports.
      ["config/hosts.json", ["{\r", '  "db.internal":\r', '    {"port": 5432}\r', "}\r"]],
      ["src/config.ts", ['if (host === "db.internal") {}']],
      // A host written as a nested string inside a replacement field.
      ["src/config.ts", ['const u = `${env.HOST ?? "db.internal"}/api`;']],
      ["app/db.py", ["u = f\"{cfg.get('host', 'db.internal')}\""]],
      // A field in a plain (non-f) Python string is text, not code.
      ["app/db.py", ['u = "{db.internal}"']],
      // A template literal in a non-JS file is not a template.
      ["app/run.py", ["u = `${db.internal}`"]],
      ["src/config.ts", ['const u = "${db.internal}";']],
    ];
    for (const [file, lines] of cases) {
      const found = ofRule(scanLines(file, ...lines), "INTERNAL_HOSTNAME");
      expect(found, `${file}: ${lines.join(" ")}`).toHaveLength(1);
      expect(found[0].severity).toBe("medium");
    }
  });
});

// ---------------------------------------------------------------------------
// Four-part requirement numbers
// ---------------------------------------------------------------------------

describe("INTERNAL_PRIVATE_IP: requirement numbers", () => {
  it("does not report a four-part number directly after a requirement marker", () => {
    for (const text of [
      "Req 10.4.1.1 introduces automated review of audit logs",
      "Requirement 10.4.1.1 introduces automated review of audit logs",
      "§ 10.4.1.1 introduces automated review of audit logs",
      "§10.4.1.1",
      "Req. 10.4.1.1",
      "Req: 10.4.1.1",
      "see Section 10.2.1.1 and",
      "Sec. 10.2.1.1",
      "Control 10.2.1.1",
      "clause 10.2.1.1",
      "Annex 10.2.1.1",
      "Req 10.4.1.1.2 is a sub-requirement",
    ]) {
      expect(ofRule(scanLines("src/catalog.ts", `const t = "${text}";`), "INTERNAL_PRIVATE_IP"), text).toHaveLength(0);
      expect(ofRule(scanLines("docs/pci.md", text), "INTERNAL_PRIVATE_IP"), text).toHaveLength(0);
    }
  });

  it("still reports the address when no marker is adjacent", () => {
    const cases: Array<[string, string]> = [
      ["docs/net.md", "host 10.4.1.1"],
      ["config/app.json", '{"server": "10.4.1.1"}'],
      ["src/client.ts", 'const u = "http://10.4.1.1/";'],
      ["docs/net.md", "Req host 10.4.1.1"],
      ["docs/net.md", "Prereq 10.4.1.1"],
      ["docs/net.md", "Requirements 10.4.1.1"],
      ["docs/net.md", "Sec 10.4.1.1"],
      ["docs/net.md", "Section\n10.4.1.1"],
      ["docs/net.md", "Section 192.168.4.1"],
      ["docs/net.md", "Section 172.20.4.1"],
    ];
    for (const [file, text] of cases) {
      const found = ofRule(scanLines(file, text), "INTERNAL_PRIVATE_IP");
      expect(found, text).toHaveLength(1);
      expect(found[0].severity).toBe("medium");
    }
  });
});

// ---------------------------------------------------------------------------
// Private literals in the documentation of an address classifier
// ---------------------------------------------------------------------------

const CLASSIFIER_EXAMPLE = [
  "// A stored literal such as 10.0.0.5 is refused before connect.",
  '// URL.hostname keeps the brackets: "http://[fd00::1]/" gives "[fd00::1]",',
  '// so a test on the "fd" prefix never fired.',
  'if (/^f[cd]/.test(host) || host.startsWith("10.")) return reject();',
];

describe("INTERNAL_PRIVATE_IP/IPV6: comments in an address classifier", () => {
  it("reports the classifier's explanatory comment at info, not drops it", () => {
    const found = scanLines("src/ssrf.ts", ...CLASSIFIER_EXAMPLE);
    const v4 = ofRule(found, "INTERNAL_PRIVATE_IP");
    const v6 = ofRule(found, "INTERNAL_PRIVATE_IPV6");
    expect(v4).toHaveLength(1);
    expect(v4[0].severity).toBe("info");
    expect(v6.length).toBeGreaterThanOrEqual(1);
    for (const f of v6) expect(f.severity).toBe("info");
  });

  it("recognises each documented classifier signal", () => {
    const comment = "# addresses such as 10.0.0.5 are rejected";
    const signals: Array<[string, string]> = [
      ["app/net.py", 'if host.startswith(("10.", "192.168.")): raise Reject()'],
      ["app/net.py", "if ipaddress.ip_address(h).is_private: raise Reject()"],
      ["app/net.py", "if is_private(h): raise Reject()"],
      ["app/net.py", 'PRIVATE = re.compile(r"^192\\.168\\.")'],
      ["app/net.py", 'if h.startswith("172.16."): raise Reject()'],
      ["app/net.py", 'if h.lower().startswith("fe80"): raise Reject()'],
    ];
    for (const [file, code] of signals) {
      const found = ofRule(scanLines(file, comment, code), "INTERNAL_PRIVATE_IP");
      expect(found, code).toHaveLength(1);
      expect(found[0].severity, code).toBe("info");
    }
    const js: Array<[string, string]> = [
      ["src/net.ts", "if (isPrivateAddress(h)) return reject();"],
      ["src/net.ts", 'if (ipaddr.parse(h).range() === "private") return reject();'],
      ["src/net.ts", "if (/^10\\./.test(h)) return reject();"],
      ["src/net.go", "if ip.IsPrivate() { return errBlocked }"],
    ];
    for (const [file, code] of js) {
      const found = ofRule(scanLines(file, "// addresses such as 10.0.0.5 are rejected", code), "INTERNAL_PRIVATE_IP");
      expect(found, code).toHaveLength(1);
      expect(found[0].severity, code).toBe("info");
    }
  });

  it("keeps medium for an infrastructure comment, even in a classifier file", () => {
    for (const [file, comment, code] of [
      ["app/net.py", "# primary database at 10.20.30.40", "if ipaddress.ip_address(h).is_private: raise Reject()"],
      ["app/net.py", "# primary database at 10.20.30.40", ""],
      ["src/net.ts", "// primary database at 10.20.30.40", 'if (host.startsWith("10.")) return reject();'],
      ["config/app.yaml", "# primary database at 10.20.30.40", ""],
    ]) {
      const found = ofRule(scanLines(file, comment, code), "INTERNAL_PRIVATE_IP");
      expect(found, `${file}: ${comment}`).toHaveLength(1);
      expect(found[0].severity, `${file}: ${comment}`).toBe("medium");
    }
  });

  it("keeps medium for the same comment in a file with no classifier", () => {
    const found = scanLines("src/ssrf.ts", ...CLASSIFIER_EXAMPLE.slice(0, 3), "return connect(host);");
    const all = [...ofRule(found, "INTERNAL_PRIVATE_IP"), ...ofRule(found, "INTERNAL_PRIVATE_IPV6")];
    expect(all.length).toBeGreaterThanOrEqual(2);
    for (const f of all) expect(f.severity).toBe("medium");
  });

  it("keeps medium for a literal in string position, even in a classifier file", () => {
    for (const line of [
      'const probe = "10.0.0.5"; // such as this one, refused',
      'const probe = "fd00::1";',
      'const note = "// such as 10.0.0.5 is refused";',
    ]) {
      const found = scanLines("src/ssrf.ts", line, 'if (host.startsWith("10.")) return reject();');
      const all = [...ofRule(found, "INTERNAL_PRIVATE_IP"), ...ofRule(found, "INTERNAL_PRIVATE_IPV6")];
      expect(all, line).toHaveLength(1);
      expect(all[0].severity, line).toBe("medium");
    }
  });
});

// ---------------------------------------------------------------------------
// Bounded cost on attacker-sized input
// ---------------------------------------------------------------------------

describe("rule precision: bounded cost", () => {
  it("stays fast on a large file full of near-miss shapes", { timeout: performanceBudget(60_000) }, () => {
    const lines: string[] = [];
    // ~5 MB: every line is under MAX_LINE_LENGTH so each candidate is examined.
    const filler = "{".repeat(200) + "${".repeat(200) + '"a.b.local": ' + "Req ".repeat(100);
    for (let i = 0; i < 5_000; i++) {
      lines.push(`// ${filler} ${"startsWith(".repeat(20)} 10.${i % 250}.1.${(i % 200) + 1} such as`);
    }
    const content = lines.join("\n");
    expect(content.length).toBeGreaterThan(4_000_000);
    const started = Date.now();
    scanInternalDisclosure(content, "src/big.ts");
    scanInternalDisclosure(content, "app/big.py");
    scanInternalDisclosure(content, "data/big.json");
    expect(Date.now() - started).toBeLessThan(performanceBudget(10_000));
  });

  it("stays fast on long lines of replacement fields and quoted keys", { timeout: performanceBudget(60_000) }, () => {
    const line = "const s = `" + "${a.b.local} ".repeat(140) + "`;";
    const key = '{ ' + '"a.b.local": 1, '.repeat(110) + "}";
    const lines: string[] = [];
    for (let i = 0; i < 2_000; i++) lines.push(i % 2 === 0 ? line : key);
    const content = lines.join("\n");
    const started = Date.now();
    const found = scanInternalDisclosure(content, "src/big.ts");
    expect(Date.now() - started).toBeLessThan(performanceBudget(10_000));
    expect(ofRule(found, "INTERNAL_HOSTNAME")).toHaveLength(0);
  });
});
