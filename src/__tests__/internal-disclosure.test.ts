import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { performanceBudget } from "./performance-budget.js";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as crypto from "node:crypto";
import {
  scanInternalDisclosure,
  loadInternalDisclosureConfig,
  emptyInternalDisclosureRuntime,
  hashInternalTerm,
  normalizeInternalTerm,
  candidateTokens,
  classifyIPv4,
  isDocumentationFile,
  classifyFileSurface,
  isWellKnownInfraValue,
  isSingleLabelHost,
  severityForHost,
  isDevPathContextOk,
  isHostnameLexicalContextOk,
  lineCommentStart,
  buildLineIndex,
  lineAtOffset,
  INTERNAL_DISCLOSURE_PATTERNS,
  INTERNAL_DISCLOSURE_ENV,
  INTERNAL_HASH_SALT_ENV,
  MAX_LINE_LENGTH,
  MAX_FINDINGS_PER_RULE,
  MAX_FINDINGS_PER_FILE,
  MAX_SCANNED_TREE_REGEX_LENGTH,
} from "../internal-disclosure.js";
import { loadPolicyConfig, applyPolicy } from "../policy-engine.js";
import { scan } from "../scanner.js";
import type { Finding } from "../types.js";

/**
 * Internal-disclosure rule family.
 *
 * Every fixture in this file is NEUTRAL on purpose: RFC5737 documentation
 * addresses, RFC2606 example domains, `acme/sample-service` as the repository
 * name and `alex` as the account name. Nothing here names real infrastructure,
 * which is the same discipline the feature asks its users to adopt.
 *
 * Each rule gets both halves of the contract: a TRUE POSITIVE proving the leak
 * is caught, and a FALSE POSITIVE proving the documentation shape that would
 * otherwise get the rule switched off stays silent.
 */

/** Run the built-in shape rules with no deny-list configured. */
function shapeScan(file: string, ...lines: string[]): Finding[] {
  return scanInternalDisclosure(lines.join("\n"), file);
}

function rules(findings: Finding[]): string[] {
  return findings.map((f) => f.rule);
}

describe("internal-disclosure: built-in shape rules (true positives)", () => {
  it("INTERNAL_PRIVATE_IP flags RFC1918, CGNAT and link-local addresses", () => {
    const cases = [
      'const db = "10.20.30.40";',
      'const gw = "172.20.4.9";',
      'const nas = "192.168.7.12";',
      'const cgnat = "100.72.1.8";',
      'const linkLocal = "169.254.11.4";',
    ];
    for (const line of cases) {
      const found = shapeScan("src/config.ts", line);
      expect(rules(found), line).toContain("INTERNAL_PRIVATE_IP");
      expect(found[0].severity).toBe("medium");
    }
  });

  it("INTERNAL_PRIVATE_IP reports a /32 host route but not a subnet range", () => {
    expect(rules(shapeScan("infra/main.tf", 'allow = "10.20.30.40/32"'))).toContain(
      "INTERNAL_PRIVATE_IP",
    );
    expect(shapeScan("infra/main.tf", 'cidr_block = "10.0.0.0/16"')).toHaveLength(0);
  });

  it("INTERNAL_PRIVATE_IPV6 flags a ULA address", () => {
    const found = shapeScan("src/net.ts", 'const peer = "fd12:3456:789a:1::1";');
    expect(rules(found)).toContain("INTERNAL_PRIVATE_IPV6");
  });

  it("INTERNAL_HOSTNAME flags every internal-only TLD", () => {
    for (const host of [
      "build-01.intranet",
      "vault.corp",
      "nas.lan",
      "printer.home",
      "api.svc.internal",
      "media-box.local",
    ]) {
      const found = shapeScan("src/config.ts", `const host = "${host}";`);
      expect(rules(found), host).toContain("INTERNAL_HOSTNAME");
    }
  });

  it("INTERNAL_SINGLE_LABEL_URL flags a URL with a dotless machine name", () => {
    const found = shapeScan("src/config.ts", 'const url = "http://build-01/status";');
    expect(rules(found)).toContain("INTERNAL_SINGLE_LABEL_URL");
    // Weakest signal in the family, so the weakest severity.
    expect(found[0].severity).toBe("low");
  });

  it("INTERNAL_SERVICE_ENDPOINT flags host plus port on a private host", () => {
    const found = shapeScan("src/config.ts", 'const url = "http://10.20.30.40:8086/write";');
    expect(rules(found)).toContain("INTERNAL_SERVICE_ENDPOINT");
  });

  it("INTERNAL_GIT_REMOTE flags ssh:// and scp-style remotes on a non-public forge", () => {
    expect(
      rules(shapeScan("docs-src/setup.ts", 'const r = "ssh://git@forge.lan:2222/acme/sample-service.git";')),
    ).toContain("INTERNAL_GIT_REMOTE");
    expect(
      rules(shapeScan("src/config.ts", 'const r = "git@forge.corp:acme/sample-service.git";')),
    ).toContain("INTERNAL_GIT_REMOTE");
  });

  it("INTERNAL_DEV_PATH flags a home directory on Linux, macOS and Windows", () => {
    expect(rules(shapeScan("scripts/build.sh", "cp dist/* /home/alex/work/acme/"))).toContain(
      "INTERNAL_DEV_PATH",
    );
    expect(rules(shapeScan("scripts/build.sh", "cp dist/* /Users/alex/work/acme/"))).toContain(
      "INTERNAL_DEV_PATH",
    );
    expect(
      rules(shapeScan("scripts/build.ps1", "Copy-Item C:\\Users\\alex\\work\\acme\\out")),
    ).toContain("INTERNAL_DEV_PATH");
    expect(
      rules(shapeScan("tsconfig.paths.json", '{ "baseUrl": "C:/Users/alex/work/acme" }')),
    ).toContain("INTERNAL_DEV_PATH");
  });

  it("reports the same value repeated on one line once, two different values twice", () => {
    expect(
      shapeScan("src/config.ts", 'if (a === "10.20.30.40" || b === "10.20.30.40") {}'),
    ).toHaveLength(1);
    expect(
      shapeScan("src/config.ts", 'const pair = ["10.20.30.40", "10.20.30.41"];'),
    ).toHaveLength(2);
  });

  it("reports one finding per leak, not one per overlapping reading", () => {
    // Endpoint, hostname and single-label URL all see this line.
    const endpoint = shapeScan("src/config.ts", 'const u = "https://vault.corp:8443/v1";');
    expect(rules(endpoint)).toEqual(["INTERNAL_SERVICE_ENDPOINT"]);

    // The scp-style remote hides inside the ssh:// one.
    const remote = shapeScan("src/config.ts", 'const r = "ssh://git@forge.lan:2222/acme/x.git";');
    expect(remote).toHaveLength(1);
    expect(remote[0].match).toContain("ssh://");
  });
});

describe("internal-disclosure: false positives that would get the family disabled", () => {
  it("never fires on RFC5737 documentation addresses", () => {
    for (const addr of ["192.0.2.10", "198.51.100.7", "203.0.113.42"]) {
      expect(shapeScan("src/config.ts", `const example = "${addr}";`), addr).toHaveLength(0);
      expect(
        shapeScan("src/config.ts", `const url = "http://${addr}:8080/health";`),
        addr,
      ).toHaveLength(0);
    }
  });

  it("never fires on loopback, the unspecified address or localhost URLs", () => {
    expect(shapeScan("src/config.ts", 'const a = ["127.0.0.1", "0.0.0.0", "::1"];')).toHaveLength(0);
    expect(shapeScan("src/config.ts", 'const u = "http://localhost:3000/api";')).toHaveLength(0);
    expect(shapeScan("src/config.ts", 'const u = "http://127.0.0.1:5432";')).toHaveLength(0);
  });

  it("never fires on RFC2606 example domains", () => {
    const lines = [
      'const forge = "ssh://git@forge.internal.example:2222/acme/sample-service.git";',
      'const scp = "git@forge.internal.example:acme/sample-service.git";',
      'const api = "https://api.example.com:8443/v1";',
      'const box = "https://staging.example.org:9000/";',
    ];
    for (const line of lines) {
      expect(shapeScan("src/config.ts", line), line).toHaveLength(0);
    }
  });

  it("never fires on public forge clone URLs", () => {
    const lines = [
      "git clone git@github.com:acme/sample-service.git",
      "git clone ssh://git@gitlab.com/acme/sample-service.git",
      "git clone git@ssh.github.com:acme/sample-service.git",
      "git clone git@codeberg.org:acme/sample-service.git",
      "git clone git@git.sr.ht:~acme/sample-service",
    ];
    for (const line of lines) {
      expect(shapeScan("scripts/clone.sh", line), line).toHaveLength(0);
    }
  });

  it("never fires on container service aliases", () => {
    const line = 'const urls = ["http://redis:6379", "http://db:5432", "http://minio:9000"];';
    expect(shapeScan("src/config.ts", line)).toHaveLength(0);
  });

  it("never fires on filenames that merely contain a .local segment", () => {
    const line = 'for (const p of [".claude/settings.local.json", "vite.config.local.ts"]) {}';
    expect(shapeScan("src/skills.ts", line)).toHaveLength(0);
  });

  it("never fires on a namespace whose middle segment is an internal TLD", () => {
    // An internal-only TLD is the LAST label of a host, so these are not hosts.
    const lines = [
      "import com.acme.internal.util.Helper;",
      "const timeout = config.internal.timeout;",
      'log.debug("state", state.local.value);',
      "package_dir = pkg.corp.tools",
    ];
    for (const line of lines) {
      expect(shapeScan("src/App.java", line), line).toHaveLength(0);
    }
  });

  it("never fires on a property access in source code, but does inside a string or a comment", () => {
    // `config.internal` in code is a property, not a machine.
    expect(shapeScan("src/app.ts", "return config.internal;")).toHaveLength(0);
    expect(shapeScan("src/app.py", "value = settings.local")).toHaveLength(0);

    // Quoted, so it is a value.
    expect(rules(shapeScan("src/app.ts", 'const h = "api.svc.internal";'))).toContain(
      "INTERNAL_HOSTNAME",
    );
    // In a comment, where this kind of thing really does leak.
    expect(rules(shapeScan("src/app.ts", "// staging runs on api.svc.internal"))).toContain(
      "INTERNAL_HOSTNAME",
    );
    // Data and config files carry unquoted values, so no quotes are required.
    expect(rules(shapeScan("deploy.yml", "host: api.svc.internal"))).toContain(
      "INTERNAL_HOSTNAME",
    );
  });

  it("never fires on CI runner or shared system accounts", () => {
    const lines = [
      'const workspace = "/home/runner/work/repo/repo";',
      'const home = "/home/vscode/.cache";',
      'const win = "C:\\\\Users\\\\Public\\\\shared\\\\tools";',
      'const tpl = "/home/your-name/projects";',
      'const doc = "C:\\\\Users\\\\dev\\\\projects";',
    ];
    for (const line of lines) {
      expect(shapeScan("src/paths.ts", line), line).toHaveLength(0);
    }
  });

  it("never fires on version strings that only look like addresses", () => {
    expect(
      shapeScan("src/versions.ts", 'const v = ["9.1.6", "10.1.1", "1.2.3.4", "10.0.0.257"];'),
    ).toHaveLength(0);
  });

  it("distinguishes four-component V8 versions from private addresses", () => {
    for (const line of [
      'const V8_VERSION = "10.2.154.26";',
      'const V8_VERSIONS = ["10.2.154.26", "10.3.22.1"];',
      'const runtime = { "v8": "10.2.154.26" };',
      'V8 version | 10.2.154.26',
    ]) {
      expect(
        rules(shapeScan("src/versions.ts", line)),
        line,
      ).not.toContain("INTERNAL_PRIVATE_IP");
    }

    const mixed = shapeScan(
      "src/runtime.ts",
      'const runtime = { v8: "10.2.154.26", host: "10.20.30.40" };',
    ).filter((finding) => finding.rule === "INTERNAL_PRIVATE_IP");
    expect(mixed).toHaveLength(1);
    expect(mixed[0]!.match).toBe("10.20.30.40");

    for (const line of [
      'const V8_VERSION = "192.168.7.12";',
      'const V8_VERSIONS = ["172.16.8.9"];',
      'const runtime = { v8: "10.2.154.26/32" };',
      'V8 version | 192.168.7.12',
    ]) {
      expect(
        rules(shapeScan("src/versions.ts", line)),
        line,
      ).toContain("INTERNAL_PRIVATE_IP");
    }
  });

  it("recognizes exact same-line V8 member and private-field owners", () => {
    for (const line of [
      'runtime.v8 = "10.2.154.26";',
      'process.versions.v8Version = "10.2.154.26";',
      'runtime["v8Versions"] = "10.2.154.26";',
      'runtime.v8 = ["10.2.154.26"];',
      'class Runtime { #v8 = "10.2.154.26"; }',
      'class Runtime { #v8Version: string = "10.2.154.26"; }',
    ]) {
      expect(
        rules(shapeScan("src/versions.ts", line)),
        line,
      ).not.toContain("INTERNAL_PRIVATE_IP");
    }
  });

  it("does not let V8 owner lookalikes hide private addresses", () => {
    for (const line of [
      'runtime.v8Host = "10.20.30.40";',
      'runtime["notV8"] = "10.20.30.40";',
      'class Runtime { #v8Host = "10.20.30.40"; }',
    ]) {
      expect(
        rules(shapeScan("src/runtime.ts", line)),
        line,
      ).toContain("INTERNAL_PRIVATE_IP");
    }

    for (const line of [
      'runtime.v8 = "10.2.154.26"; runtime.host = "10.20.30.40";',
      'runtime.v8 = { host: "10.20.30.40" };',
      'class Runtime { #v8 = "10.2.154.26"; #host = "10.20.30.40"; }',
    ]) {
      const privateIps = shapeScan("src/runtime.ts", line)
        .filter((finding) => finding.rule === "INTERNAL_PRIVATE_IP");
      expect(privateIps.map((finding) => finding.match), line).toEqual([
        "10.20.30.40",
      ]);
    }
  });

  it("recognizes bounded multiline V8 array ownership", () => {
    for (const lines of [
      [
        "const V8_VERSIONS = [",
        '  "10.2.154.26",',
        '  "10.3.22.1",',
        "];",
      ],
      [
        "const runtime = {",
        '  "v8": [',
        '    "10.2.154.26",',
        "  ],",
        "};",
      ],
      [
        "const V8_VERSION = [",
        "",
        '  "10.2.154.26",',
        "];",
      ],
      [
        "export const V8_VERSIONS: readonly string[] = [",
        '  "10.2.154.26",',
        "];",
      ],
      [
        "const V8_VERSIONS = [",
        '  /* bundled */ "10.2.154.26",',
        "];",
      ],
    ]) {
      expect(
        rules(shapeScan("src/versions.ts", ...lines)),
        lines.join("\n"),
      ).not.toContain("INTERNAL_PRIVATE_IP");
    }
  });

  it("handles CRLF and lets nearer nested array ownership override V8", () => {
    const crlf = scanInternalDisclosure(
      [
        "const V8_VERSIONS = [",
        '  /* bundled */ "10.2.154.26",',
        "];",
        'const host = "10.20.30.40";',
      ].join("\r\n"),
      "src/versions.ts",
    ).filter((finding) => finding.rule === "INTERNAL_PRIVATE_IP");
    expect(crlf.map((finding) => finding.match)).toEqual(["10.20.30.40"]);

    const nestedHost = shapeScan(
      "src/versions.ts",
      "const V8_VERSIONS = [",
      "  { host: [",
      '    "10.20.30.40",',
      "  ] },",
      "];",
    );
    expect(rules(nestedHost)).toContain("INTERNAL_PRIVATE_IP");
  });

  it("carries V8 ownership across a split array opener", () => {
    for (const lines of [
      [
        "const V8_VERSIONS =",
        "[",
        '  "10.2.154.26",',
        "];",
      ],
      [
        "const runtime = {",
        "  v8:",
        "  // generated versions",
        "  [",
        '    "10.2.154.26",',
        "  ],",
        "};",
      ],
    ]) {
      expect(
        rules(shapeScan("src/versions.ts", ...lines)),
        lines.join("\n"),
      ).not.toContain("INTERNAL_PRIVATE_IP");
    }
  });

  it("does not let V8 ownership hide a nearer host context or host prose", () => {
    for (const lines of [
      [
        "const V8_VERSIONS = [",
        "  { host:",
        '    "10.20.30.40",',
        "  },",
        "];",
      ],
      [
        "const V8_VERSIONS = [",
        "  connect(",
        '    "10.20.30.40",',
        "  ),",
        "];",
      ],
      ['const log = "v8: connected to host 10.20.30.40";'],
    ]) {
      const found = shapeScan("src/runtime.ts", ...lines)
        .filter((finding) => finding.rule === "INTERNAL_PRIVATE_IP");
      expect(found.map((finding) => finding.match), lines.join("\n"))
        .toContain("10.20.30.40");
    }
  });

  it("recognizes bounded V8 engine version prose lists", () => {
    for (const lines of [
      ["V8 engine versions:", "- 10.2.154.26", "- 10.3.22.1"],
      ["### V8 engine versions", "- 10.2.154.26"],
      ["| V8 engine version |", "| 10.2.154.26 |"],
      ["V8 engine version: 10.2.154.26"],
    ]) {
      expect(
        rules(shapeScan("src/versions.ts", ...lines)),
        lines.join("\n"),
      ).not.toContain("INTERNAL_PRIVATE_IP");
    }
  });

  it("keeps bounded V8 context from hiding later real hosts", () => {
    for (const lines of [
      [
        "const V8_VERSIONS = [",
        '  "10.2.154.26",',
        "];",
        'const host = "10.20.30.40";',
      ],
      [
        "V8 engine versions:",
        "- 10.2.154.26",
        "host: 10.20.30.40",
      ],
      [
        "V8 engine versions:",
        ...Array.from({ length: 33 }, () => ""),
        "- 10.20.30.40",
      ],
      [
        "const V8_VERSIONS = [",
        `  /* ${"x".repeat(4_100)} */`,
        '  "10.20.30.40",',
      ],
    ]) {
      expect(
        rules(shapeScan("src/runtime.ts", ...lines)),
        lines.join("\n"),
      ).toContain("INTERNAL_PRIVATE_IP");
    }
  });

  it("never fires on a public host with a port", () => {
    expect(shapeScan("src/config.ts", 'const u = "https://registry.npmjs.org:443/";')).toHaveLength(0);
  });
});

describe("internal-disclosure: documentation context", () => {
  const docLeak = [
    "# Setup",
    "",
    "Point the client at 10.20.30.40 and copy the build to /home/alex/work.",
    "",
    "```bash",
    "export API=http://10.20.30.40:8086",
    "cp dist/* /home/alex/work/",
    "git clone ssh://git@forge.lan:2222/acme/sample-service.git",
    "```",
    "",
    "The staging box is api.svc.internal and the address is `192.168.7.12`.",
  ];

  it("reports a private address and a developer path written in a README", () => {
    // The rebalance that matters. Excluding documentation wholesale silenced
    // exactly the case this family exists for: a README naming the staging box
    // and the path it was built from. Only the reserved namespace stays quiet.
    const found = shapeScan("README.md", ...docLeak);
    expect(rules(found)).toContain("INTERNAL_PRIVATE_IP");
    expect(rules(found)).toContain("INTERNAL_DEV_PATH");
    expect(rules(found)).toContain("INTERNAL_HOSTNAME");
  });

  it("reports inside a fenced code block, where a pasted stack trace leaks a path", () => {
    const found = shapeScan("README.md", ...docLeak);
    const fenced = found.filter((f) => f.line !== undefined && f.line >= 5 && f.line <= 9);
    expect(rules(fenced)).toContain("INTERNAL_GIT_REMOTE");
    expect(rules(fenced)).toContain("INTERNAL_DEV_PATH");
    expect(rules(fenced)).toContain("INTERNAL_SERVICE_ENDPOINT");
  });

  it("keeps the reserved documentation space quiet on every markdown surface", () => {
    expect(shapeScan("README.md", "Use 192.0.2.10 and 203.0.113.7 in your examples.")).toHaveLength(0);
    expect(shapeScan("README.md", "Open http://127.0.0.1:3000 in the browser.")).toHaveLength(0);
    expect(shapeScan("README.md", "```sh", "curl http://192.0.2.10:8080/health", "```")).toHaveLength(0);
    expect(shapeScan("README.md", "Clone it from ssh://git@forge.internal.example/acme/x.git")).toHaveLength(0);
  });

  it("stays quiet in an inline code span and in a placeholder fence", () => {
    // Measured on axios, express, got and awesome-compose: inline spans
    // produced eight findings and every one was an API signature or a
    // documented example, so the example-prone rules stay off there.
    expect(shapeScan("README.md", "The address is `192.168.7.12` in the lab.")).toHaveLength(0);
    expect(shapeScan("README.md", "Set `HOME=/home/alex/` before building.")).toHaveLength(0);
    expect(shapeScan("README.md", "```text", "host 10.20.30.40", "```")).toHaveLength(0);
    // A hostname in a span is still a hostname: a name is not an example shape.
    expect(rules(shapeScan("README.md", "The box is `api.svc.internal` today."))).toContain(
      "INTERNAL_HOSTNAME",
    );
  });

  it("never reads a method call in prose as a hostname", () => {
    // A changelog line: "Added `res.local(name, val)`". A host is never
    // followed by an opening parenthesis.
    expect(shapeScan("History.md", "  * Added `res.local(name, val)` for view locals")).toHaveLength(0);
    expect(shapeScan("src/app.ts", "return cache.local(key);")).toHaveLength(0);
  });

  it("keeps the single-label URL rule off in prose, where it is noise", () => {
    expect(shapeScan("README.md", "Then open http://myapp/ in your browser.")).toHaveLength(0);
    expect(rules(shapeScan("src/config.ts", 'const u = "http://myapp/";'))).toContain(
      "INTERNAL_SINGLE_LABEL_URL",
    );
  });

  it("separates prose from files that exist to BE an example", () => {
    expect(classifyFileSurface("docs/setup.md")).toBe("prose");
    expect(classifyFileSurface("docs/deploy.yml")).toBe("prose");
    expect(classifyFileSurface("README.md")).toBe("prose");
    expect(classifyFileSurface("examples/compose.yml")).toBe("example");
    expect(classifyFileSurface("config.example.yml")).toBe("example");
    expect(classifyFileSurface(".env.example")).toBe("example");
    expect(classifyFileSurface("docs/config.example.yml")).toBe("example");
    expect(classifyFileSurface("src/config.ts")).toBe("source");
    expect(classifyFileSurface("src/sample-service.ts")).toBe("source");

    expect(isDocumentationFile("docs/setup.md")).toBe(true);
    expect(isDocumentationFile("src/config.ts")).toBe(false);

    // Documentation about the project reports the address; a file whose whole
    // purpose is to show a shape does not.
    expect(rules(shapeScan("docs/deploy.yml", 'host: "10.20.30.40"'))).toContain(
      "INTERNAL_PRIVATE_IP",
    );
    expect(shapeScan("config.example.yml", 'host: "10.20.30.40"')).toHaveLength(0);
    expect(shapeScan("examples/compose.yml", 'host: "10.20.30.40"')).toHaveLength(0);
    // A hostname keeps its meaning even in an example file.
    expect(rules(shapeScan("config.example.yml", 'host: "vault.corp"'))).toContain(
      "INTERNAL_HOSTNAME",
    );
  });

  it("skips test fixtures and minified bundles", () => {
    expect(shapeScan("src/__tests__/proxy.test.ts", 'const ip = "10.20.30.40";')).toHaveLength(0);
    expect(shapeScan("assets/vendor.min.js", 'var h="10.20.30.40"')).toHaveLength(0);
    expect(shapeScan("assets/app.bundle.js", 'var h="10.20.30.40"')).toHaveLength(0);
  });

  it("excludes a TOP-LEVEL test directory, not only a nested one", () => {
    // The bug this replaces: the previous pattern required a LEADING slash
    // (`/tests?/`), so `test/` at the repository root - the dominant
    // JavaScript layout - never matched. 28 of 35 findings on a four-repository
    // sample came from directories that were supposed to be excluded.
    const leak = 'const ip = "10.20.30.40";';
    for (const file of [
      "test/req.ip.js",
      "tests/req.ip.js",
      "spec/req_spec.rb",
      "e2e/checkout.ts",
      "fixtures/response.json",
      "testdata/golden.json",
      "test-data/golden.json",
      "__tests__/proxy.ts",
      "__fixtures__/response.ts",
      "__mocks__/http.ts",
      "__snapshots__/app.snap",
      "packages/core/test/unit.js",
      "src/app.test.ts",
      "conftest.py",
    ]) {
      expect(shapeScan(file, leak), file).toHaveLength(0);
    }

    // Not a test directory just because the word appears in a name.
    expect(rules(shapeScan("src/latest/config.ts", leak))).toContain("INTERNAL_PRIVATE_IP");
    expect(rules(shapeScan("src/protest.ts", leak))).toContain("INTERNAL_PRIVATE_IP");
  });

  it("still scans a spec directory, which is as often OpenAPI as it is RSpec", () => {
    // `spec/` is the conventional OpenAPI and AsyncAPI location, and a server
    // URL in an API spec is the endpoint-plus-port shape this family most wants
    // to catch. Excluding the directory wholesale would have hidden it.
    expect(rules(shapeScan("spec/openapi.yaml", "  url: http://payments.acme.internal:8443"))).toContain(
      "INTERNAL_SERVICE_ENDPOINT",
    );
    expect(rules(shapeScan("specs/asyncapi.yaml", 'const ip = "10.20.30.40";'))).toContain(
      "INTERNAL_PRIVATE_IP",
    );
    // The suffix form is what actually identifies an RSpec file, and it still wins.
    expect(shapeScan("spec/req_spec.rb", 'const ip = "10.20.30.40";')).toHaveLength(0);
  });
});

describe("internal-disclosure: universal infrastructure constants", () => {
  it("never reports a cloud metadata endpoint", () => {
    for (const line of [
      'const META = "http://169.254.169.254/latest/meta-data/";',
      "metadata_host: 169.254.169.254",
      'const ecs = "http://169.254.170.2/v2/credentials";',
      "ntp_server: 169.254.169.123",
      "aliyun_meta: 100.100.100.200",
    ]) {
      expect(shapeScan("src/config.ts", line), line).toHaveLength(0);
    }
  });

  it("never reports Kubernetes and Docker documented defaults", () => {
    for (const line of [
      "clusterDNS: 10.96.0.10",
      "kubernetesService: 10.96.0.1",
      "serviceSubnet: 10.96.0.0/12",
      "podSubnet: 10.244.0.0/16",
      "k3sClusterDNS: 10.43.0.10",
      "dockerBridgeGateway: 172.17.0.1",
      'const h = "host.docker.internal";',
      'const u = "http://host.docker.internal:5432/";',
    ]) {
      expect(shapeScan("compose.yaml", line), line).toHaveLength(0);
    }
  });

  it("still reports a real address inside the same private ranges", () => {
    expect(rules(shapeScan("compose.yaml", "clusterDNS: 10.96.4.11"))).toContain(
      "INTERNAL_PRIVATE_IP",
    );
    expect(rules(shapeScan("compose.yaml", "gateway: 172.17.4.9"))).toContain(
      "INTERNAL_PRIVATE_IP",
    );
    expect(isWellKnownInfraValue("169.254.169.254")).toBe(true);
    expect(isWellKnownInfraValue("10.96.0.10")).toBe(true);
    expect(isWellKnownInfraValue("10.96.4.11")).toBe(false);
  });
});

describe("internal-disclosure: severity follows the host, not the rule", () => {
  it("keeps a single-label host at low even when the endpoint rule reports it", () => {
    // A compose or Kubernetes service name with a port is the same weak signal
    // as one without. INTERNAL_SERVICE_ENDPOINT used to promote it to medium
    // purely because its reading of the line won the overlap dedupe.
    for (const line of [
      'const u = "http://payments:8080/health";',
      'const u = "http://orders-svc:9000/";',
    ]) {
      const found = shapeScan("src/config.ts", line);
      expect(found, line).toHaveLength(1);
      expect(found[0].severity, line).toBe("low");
    }
  });

  it("keeps a dotted internal host at medium", () => {
    const found = shapeScan("src/config.ts", 'const u = "https://vault.corp:8443/v1";');
    expect(found).toHaveLength(1);
    expect(found[0].rule).toBe("INTERNAL_SERVICE_ENDPOINT");
    expect(found[0].severity).toBe("medium");
  });

  it("keeps a private address endpoint at medium", () => {
    const found = shapeScan("src/config.ts", 'const u = "http://10.20.30.40:8086/write";');
    expect(found[0].severity).toBe("medium");
  });

  it("severityForHost is the single decision point", () => {
    expect(isSingleLabelHost("payments")).toBe(true);
    expect(isSingleLabelHost("vault.corp")).toBe(false);
    expect(isSingleLabelHost("10.20.30.40")).toBe(false);
    expect(severityForHost("payments", "medium")).toBe("low");
    expect(severityForHost("vault.corp", "medium")).toBe("medium");
  });
});

describe("internal-disclosure: developer paths versus REST routes", () => {
  it("never reads a lowercase /users/ route as a macOS home directory", () => {
    // `/Users` is the macOS home directory; `/users` is a route. Compiling the
    // rule case-insensitively made every REST API in the world a finding.
    for (const line of [
      'app.get("/users/:id", handler);',
      'router.get("/users/{id}", handler);',
      'app.get("/users", handler);',
      'app.get("/users/profile/edit", handler);',
      'fetch("/api/users/alex/orders");',
      'const p = "/users/alex/";',
    ]) {
      expect(shapeScan("src/routes.js", line), line).toHaveLength(0);
    }
  });

  it("still reports the capitalised macOS path and the Linux one", () => {
    expect(rules(shapeScan("src/config.ts", 'const c = "/Users/alex/Library/Caches";'))).toContain(
      "INTERNAL_DEV_PATH",
    );
    expect(rules(shapeScan("scripts/build.sh", "cp dist/* /home/alex/work/"))).toContain(
      "INTERNAL_DEV_PATH",
    );
    // A Windows path is unambiguous because of the drive letter, so both
    // spellings of the directory stay accepted.
    expect(rules(shapeScan("scripts/build.ps1", "Copy-Item C:\\users\\alex\\work"))).toContain(
      "INTERNAL_DEV_PATH",
    );
  });

  it("rejects a route or template parameter after the account segment", () => {
    expect(isDevPathContextOk("/home/alex/work", "/home/alex/".length)).toBe(true);
    for (const following of [":", "{", "<", "$", "%", "*"]) {
      expect(isDevPathContextOk(`/home/alex/${following}x`, "/home/alex/".length), following).toBe(
        false,
      );
    }
  });
});

describe("internal-disclosure: hostname shape versus file path", () => {
  it("never reads a module specifier ending in .local as a hostname", () => {
    for (const line of [
      'import cfg from "./config.local";',
      'const p = "src/config.local";',
      'require("../lib/settings.local");',
      'readFile("settings.local.json")',
      'import cfg from "./vite.config.local.ts";',
      "const p = 'dist\\\\assets\\\\bundle.local'",
    ]) {
      expect(shapeScan("src/app.ts", line), line).toHaveLength(0);
    }
  });

  it("still reads a URL host and a user-prefixed host as hostnames", () => {
    expect(rules(shapeScan("src/app.ts", 'const u = "https://vault.corp/v1";'))).toContain(
      "INTERNAL_HOSTNAME",
    );
    expect(rules(shapeScan("src/app.ts", 'const u = "//registry.svc.corp/npm/";'))).toContain(
      "INTERNAL_HOSTNAME",
    );
    expect(isHostnameLexicalContextOk("x = vault.corp", 4)).toBe(true);
    expect(isHostnameLexicalContextOk("./config.local", 2)).toBe(false);
  });

  it("does not treat a URL scheme as the start of a comment", () => {
    // `line.indexOf("//")` found the "//" of "https://", so every dotted name
    // to the right of a URL was accepted as being inside a comment.
    expect(
      shapeScan("src/app.ts", 'fetch("https://api.example.com"); return config.internal;'),
    ).toHaveLength(0);
    expect(lineCommentStart('fetch("https://x");', true)).toBe(-1);
    expect(lineCommentStart("const a = 1; // note", true)).toBe(13);
    expect(lineCommentStart("value = 1  # note", true)).toBe(11);
    // `#` is not a comment in the C family (`#private`, `${...}` templates).
    expect(lineCommentStart("this.#count = 1;", false)).toBe(-1);
  });

  it("never reports the unix-socket pseudo-host", () => {
    // `http://unix/...` is the convention for a request over a UNIX domain
    // socket (got, axios, dockerode). No DNS and no machine is involved, and
    // it accounted for 14 of 35 findings on the tuning sample.
    for (const line of [
      'await got("http://unix:/var/run/docker.sock:/containers/json");',
      'const u = "http://npipe//./pipe/docker_engine";',
    ]) {
      expect(shapeScan("src/client.ts", line), line).toHaveLength(0);
    }
  });
});

describe("internal-disclosure: bounded cost on generated files", () => {
  /** An 810 KB single-line bundle: the shape every build step emits. */
  function minifiedBundle(): string {
    let s = "";
    let a = 0;
    while (s.length < 810 * 1024) {
      s += `var c${a}={h:t.storage.local.get(x${a}),p:"10.${a % 250}.${(a * 7) % 250}.${(a % 253) + 1}",u:"http://svchost${a}/api"};`;
      a++;
    }
    return s.slice(0, 810 * 1024);
  }

  it("scans an 810 KB single-line bundle in well under a second", () => {
    const content = minifiedBundle();
    expect(content.split("\n")).toHaveLength(1);

    const started = Date.now();
    const found = scanInternalDisclosure(content, "assets/app.js");
    const elapsed = Date.now() - started;

    // Before the line index, the per-line context cache and the line-length
    // guard, this same file took roughly 40 seconds and produced a 26 MB
    // report, because every match rescanned the whole line for quotes and
    // comment markers and the overlap dedupe was quadratic across the file.
    expect(elapsed).toBeLessThan(2000);
    expect(JSON.stringify(found).length).toBeLessThan(64 * 1024);
    // Never silent about the gap.
    expect(rules(found)).toEqual(["INTERNAL_DISCLOSURE_TRUNCATED"]);
    expect(found[0].severity).toBe("info");
  });

  it("keeps repeated multiline V8-version suppression near-linear", { timeout: 15_000 }, () => {
    const padding = " ".repeat(221);
    const unit = [
      "const V8_VERSIONS = [",
      `  ${padding}"10.2.154.26",`,
      "];",
      "",
    ].join("\n");
    const content = unit.repeat(20_000);
    expect(Buffer.byteLength(content)).toBeGreaterThan(5 * 1024 * 1024);

    const started = Date.now();
    const found = scanInternalDisclosure(content, "src/versions.ts");
    const elapsed = Date.now() - started;

    expect(elapsed).toBeLessThan(performanceBudget(5_000));
    expect(rules(found)).not.toContain("INTERNAL_PRIVATE_IP");
  });
  it("caps findings per rule and per file, and says so", () => {
    const lines: string[] = [];
    for (let i = 0; i < 3000; i++) {
      lines.push(`  const h${i} = { ip: "10.1.${i % 250}.${(i % 253) + 1}", host: "box${i}.corp" };`);
    }
    const found = scanInternalDisclosure(lines.join("\n"), "src/generated.ts");

    const perRule = new Map<string, number>();
    for (const f of found) perRule.set(f.rule, (perRule.get(f.rule) ?? 0) + 1);
    expect(perRule.get("INTERNAL_PRIVATE_IP")).toBe(MAX_FINDINGS_PER_RULE);
    expect(perRule.get("INTERNAL_HOSTNAME")).toBe(MAX_FINDINGS_PER_RULE);
    expect(found.length).toBeLessThanOrEqual(MAX_FINDINGS_PER_FILE);
    expect(rules(found)).toContain("INTERNAL_DISCLOSURE_TRUNCATED");
  });

  it("fills the per-file cap exactly and keeps the most severe findings", () => {
    // Enough DISTINCT shapes that the per-rule caps sum past the file cap,
    // which is the only way the file cap is reached at all. Low-severity
    // single-label URLs are emitted first so that dropping by declaration
    // order rather than by severity would be visible.
    const lines: string[] = [];
    for (let i = 0; i < 60; i++) lines.push(`  const u${i} = "http://svc${i}:8080/health";`);
    for (let i = 0; i < 60; i++) lines.push(`  const a${i} = "10.1.${i % 250}.${(i % 253) + 1}";`);
    for (let i = 0; i < 60; i++) lines.push(`  const h${i} = "box${i}.corp";`);
    for (let i = 0; i < 60; i++) lines.push(`  const p${i} = "/home/asmith/work/p${i}/main.js";`);
    for (let i = 0; i < 60; i++) lines.push(`  const w${i} = "C:\\\\Users\\\\asmith\\\\p${i}\\\\main.js";`);
    const found = scanInternalDisclosure(lines.join("\n"), "src/generated.ts");

    // The notice occupies one of the slots rather than pushing the file one
    // over its own documented limit.
    expect(found.length).toBe(MAX_FINDINGS_PER_FILE);
    expect(rules(found)).toContain("INTERNAL_DISCLOSURE_TRUNCATED");

    // Every surviving finding outranks every dropped one, so the low-severity
    // rule declared first does not crowd out the medium-severity ones.
    const kept = found.filter((f) => f.rule !== "INTERNAL_DISCLOSURE_TRUNCATED");
    expect(kept).toHaveLength(MAX_FINDINGS_PER_FILE - 1);
    expect(kept.every((f) => f.severity === "medium")).toBe(true);
    expect(rules(found)).not.toContain("INTERNAL_SINGLE_LABEL_URL");
  });

  it("does not report a coverage gap for a long line with nothing plausible on it", () => {
    // SVG path coordinates ("1.16.68.344") have the shape of an address and
    // are not one; the value guard settles them before the length guard runs.
    const svg = `<svg><path d="M ${Array.from({ length: 400 }, (_, i) => `${i}.16.68.344`).join(" L ")}"/></svg>`;
    expect(svg.length).toBeGreaterThan(MAX_LINE_LENGTH);
    expect(scanInternalDisclosure(svg, "assets/banner.svg")).toHaveLength(0);
  });

  it("maps a match offset back to its line by binary search", () => {
    const index = buildLineIndex("alpha\nbeta\n\ngamma");
    expect(index.starts).toEqual([0, 6, 11, 12]);
    expect(lineAtOffset(index, 0)).toBe(0);
    expect(lineAtOffset(index, 5)).toBe(0);
    expect(lineAtOffset(index, 6)).toBe(1);
    expect(lineAtOffset(index, 11)).toBe(2);
    expect(lineAtOffset(index, 16)).toBe(3);
  });
});

describe("internal-disclosure: severity discipline", () => {
  it("never assigns high or critical to a topology finding", () => {
    for (const pattern of INTERNAL_DISCLOSURE_PATTERNS) {
      expect(["medium", "low"], pattern.rule).toContain(pattern.severity);
    }
  });

  it("classifies addresses honestly", () => {
    expect(classifyIPv4("10.20.30.40")).toBe("private");
    expect(classifyIPv4("192.0.2.10")).toBe("documentation");
    expect(classifyIPv4("127.0.0.1")).toBe("loopback");
    expect(classifyIPv4("93.184.216.34")).toBe("public");
    expect(classifyIPv4("10.0.0.999")).toBe("invalid");
  });
});

// ---------------------------------------------------------------------------
// Deny-list: all three modes
// ---------------------------------------------------------------------------

describe("internal-disclosure: configurable deny-list", () => {
  let tempDir: string;
  const SECRET_TERM = "forge.internal.example";
  const SECRET_REPO = "acme/sample-service";

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-internal-"));
    delete process.env[INTERNAL_DISCLOSURE_ENV];
  });

  afterEach(() => {
    delete process.env[INTERNAL_DISCLOSURE_ENV];
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function writePolicy(...lines: string[]): void {
    fs.writeFileSync(path.join(tempDir, ".supply-chain-guard.yml"), lines.join("\n"), "utf-8");
  }

  it("mode a: a hashed term matches without the term ever being written down", () => {
    writePolicy("internalDisclosure:", "  hashedTerms:", `    - ${hashInternalTerm(SECRET_TERM)}`);
    const policy = loadPolicyConfig(tempDir);
    const runtime = loadInternalDisclosureConfig(tempDir, policy);
    expect(runtime.enabled).toBe(true);

    const found = scanInternalDisclosure(
      `const registry = "https://${SECRET_TERM}/npm/";`,
      "src/config.ts",
      runtime,
    );
    const hit = found.find((f) => f.rule === "INTERNAL_DENYLIST_MATCH");
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe("medium");
  });

  it("mode a: the hashed path never stores or reports the plaintext term", () => {
    const digest = hashInternalTerm(SECRET_TERM);
    writePolicy("internalDisclosure:", "  hashedTerms:", `    - ${digest}`);

    // 1. The committed config carries only the digest.
    const configText = fs.readFileSync(path.join(tempDir, ".supply-chain-guard.yml"), "utf-8");
    expect(configText).not.toContain(SECRET_TERM);

    // 2. The in-memory runtime carries only the digest.
    const runtime = loadInternalDisclosureConfig(tempDir, loadPolicyConfig(tempDir));
    expect([...runtime.hashes]).toEqual([digest]);
    expect(JSON.stringify([...runtime.hashes])).not.toContain(SECRET_TERM);
    expect(runtime.matchers).toHaveLength(0);

    // 3. The finding it produces carries only the digest prefix.
    const found = scanInternalDisclosure(`host = ${SECRET_TERM}`, "src/config.ts", runtime);
    const hit = found.find((f) => f.rule === "INTERNAL_DENYLIST_MATCH");
    expect(hit).toBeDefined();
    expect(JSON.stringify(hit)).not.toContain(SECRET_TERM);
    expect(hit?.match).toContain("redacted");
    expect(hit?.match).toContain(digest.slice(0, 12));
  });

  it("says so when a line has too many tokens for the deny-list pass to read", () => {
    // A line under MAX_LINE_LENGTH can still exceed the per-line token budget.
    // Going quiet there would be the one way a CONFIGURED term is missed
    // without a word, so it has to surface as a truncation notice.
    const digest = hashInternalTerm(SECRET_TERM);
    writePolicy("internalDisclosure:", "  hashedTerms:", `    - ${digest}`);
    const runtime = loadInternalDisclosureConfig(tempDir, loadPolicyConfig(tempDir));

    const filler = Array.from({ length: 410 }, (_, i) => `t${i}`).join(" ");
    const found = scanInternalDisclosure(`${filler} ${SECRET_TERM}`, "src/config.ts", runtime);

    expect(rules(found)).toContain("INTERNAL_DISCLOSURE_TRUNCATED");
    expect(JSON.stringify(found)).not.toContain(SECRET_TERM);
  });

  it("reports no truncation for a line that fits the token budget exactly", () => {
    const digest = hashInternalTerm(SECRET_TERM);
    writePolicy("internalDisclosure:", "  hashedTerms:", `    - ${digest}`);
    const runtime = loadInternalDisclosureConfig(tempDir, loadPolicyConfig(tempDir));

    const found = scanInternalDisclosure(`host = ${SECRET_TERM}`, "src/config.ts", runtime);
    expect(rules(found)).not.toContain("INTERNAL_DISCLOSURE_TRUNCATED");
    expect(rules(found)).toContain("INTERNAL_DENYLIST_MATCH");
  });

  it("mode a: hashing normalises with trim plus lowercase, and matches whole tokens only", () => {
    expect(hashInternalTerm("  FORGE.Internal.Example  ")).toBe(hashInternalTerm(SECRET_TERM));
    expect(normalizeInternalTerm("  Mixed.Case ")).toBe("mixed.case");
    // The documented recipe: sha256 of the normalised term, nothing else.
    expect(hashInternalTerm(SECRET_TERM)).toBe(
      crypto.createHash("sha256").update(SECRET_TERM, "utf8").digest("hex"),
    );

    const runtime = emptyInternalDisclosureRuntime();
    runtime.hashes.add(hashInternalTerm(SECRET_TERM));
    runtime.enabled = true;

    // Exact token: matched.
    expect(
      scanInternalDisclosure(`url = https://${SECRET_TERM}/x`, "a.ts", runtime).some(
        (f) => f.rule === "INTERNAL_DENYLIST_MATCH",
      ),
    ).toBe(true);
    // A longer token that merely contains it: NOT matched. This is the honest
    // limitation of hashing and the reason externalFile exists.
    expect(
      scanInternalDisclosure(`url = https://sub-${SECRET_TERM}/x`, "a.ts", runtime).some(
        (f) => f.rule === "INTERNAL_DENYLIST_MATCH",
      ),
    ).toBe(false);
  });

  it("mode a: an org/repo inventory entry is a single token", () => {
    expect(candidateTokens(`git clone git@forge.corp:${SECRET_REPO}.git`)).toContain(SECRET_REPO);
    const runtime = emptyInternalDisclosureRuntime();
    runtime.hashes.add(hashInternalTerm(SECRET_REPO));
    runtime.enabled = true;
    const found = scanInternalDisclosure(
      `  "repository": "git@forge.corp:${SECRET_REPO}.git"`,
      "package.json",
      runtime,
    );
    expect(rules(found)).toContain("INTERNAL_DENYLIST_MATCH");
  });

  it("mode b: an external file holds full patterns and its matches are redacted", () => {
    const externalPath = path.join(tempDir, ".scg-internal-terms");
    fs.writeFileSync(
      externalPath,
      ["# never committed", `/${SECRET_TERM.replace(/\./g, "\\.")}/`, "sample-service-\\d+"].join("\n"),
      "utf-8",
    );
    writePolicy("internalDisclosure:", "  externalFile: .scg-internal-terms");

    const runtime = loadInternalDisclosureConfig(tempDir, loadPolicyConfig(tempDir));
    expect(runtime.enabled).toBe(true);
    expect(runtime.loadFindings).toHaveLength(0);

    const found = scanInternalDisclosure(
      `const host = "sub.${SECRET_TERM}";`,
      "src/config.ts",
      runtime,
    );
    const hit = found.find((f) => f.rule === "INTERNAL_DENYLIST_MATCH");
    expect(hit).toBeDefined();
    expect(JSON.stringify(hit)).not.toContain(SECRET_TERM);
    expect(hit?.match).toContain("redacted");
  });

  it("mode b: the environment variable works without touching the config file", () => {
    const externalPath = path.join(tempDir, "terms.txt");
    fs.writeFileSync(externalPath, "sample-service\n", "utf-8");
    process.env[INTERNAL_DISCLOSURE_ENV] = externalPath;

    const runtime = loadInternalDisclosureConfig(tempDir, null);
    expect(runtime.enabled).toBe(true);
    const found = scanInternalDisclosure('name = "sample-service"', "src/config.ts", runtime);
    expect(rules(found)).toContain("INTERNAL_DENYLIST_MATCH");
  });

  it("mode b: a configured file that is absent is reported, never silently ignored", () => {
    writePolicy("internalDisclosure:", "  externalFile: .scg-internal-terms");
    const runtime = loadInternalDisclosureConfig(tempDir, loadPolicyConfig(tempDir));
    expect(runtime.enabled).toBe(false);
    expect(runtime.loadFindings).toHaveLength(1);
    expect(runtime.loadFindings[0].rule).toBe("INTERNAL_DENYLIST_UNAVAILABLE");
    // info severity: a shared CI runner deliberately has no copy of the file.
    expect(runtime.loadFindings[0].severity).toBe("info");
  });

  it("mode b: an entry that cannot be compiled is reported, and its content never is", () => {
    const externalPath = path.join(tempDir, ".scg-internal-terms");
    fs.writeFileSync(
      externalPath,
      ["# broken entries below", `sha256:${SECRET_TERM}`, "/unclosed(/", "ab"].join("\n"),
      "utf-8",
    );
    writePolicy("internalDisclosure:", "  externalFile: .scg-internal-terms");

    const runtime = loadInternalDisclosureConfig(tempDir, loadPolicyConfig(tempDir));
    const invalid = runtime.loadFindings.filter(
      (f) => f.rule === "INTERNAL_DENYLIST_INVALID_ENTRY",
    );
    expect(invalid).toHaveLength(3);
    expect(JSON.stringify(invalid)).not.toContain(SECRET_TERM);
    for (const f of invalid) expect(f.description).toContain("line");
  });

  it("mode b: the environment variable's value is never printed into a finding", () => {
    // The value is a local path and can itself contain an account name.
    process.env[INTERNAL_DISCLOSURE_ENV] = path.join(tempDir, "home", "alex", "terms.txt");
    const runtime = loadInternalDisclosureConfig(tempDir, null);
    expect(runtime.loadFindings).toHaveLength(1);
    expect(runtime.loadFindings[0].rule).toBe("INTERNAL_DENYLIST_UNAVAILABLE");
    expect(runtime.loadFindings[0].description).toContain(INTERNAL_DISCLOSURE_ENV);
    expect(runtime.loadFindings[0].description).not.toContain("alex");
  });

  it("mode c: plaintext patterns in the committed config match and are not redacted", () => {
    writePolicy(
      "internalDisclosure:",
      "  patterns:",
      "    - sample-service",
      "    - /build-\\d{2}\\.corp/",
    );
    const runtime = loadInternalDisclosureConfig(tempDir, loadPolicyConfig(tempDir));
    expect(runtime.matchers).toHaveLength(2);

    const literal = scanInternalDisclosure('name = "sample-service"', "src/config.ts", runtime);
    const literalHit = literal.find((f) => f.rule === "INTERNAL_DENYLIST_MATCH");
    expect(literalHit?.match).toBe("sample-service");

    const regex = scanInternalDisclosure('host = "build-07.corp"', "src/config.ts", runtime);
    expect(rules(regex)).toContain("INTERNAL_DENYLIST_MATCH");
  });

  it("reports a deny-list entry that can never match instead of failing open", () => {
    writePolicy("internalDisclosure:", "  hashedTerms:", "    - not-a-digest");
    const policy = loadPolicyConfig(tempDir);
    const { findings } = applyPolicy([], policy!);
    expect(rules(findings)).toContain("POLICY_INVALID_INTERNAL_TERM");
  });

  it("accepts the section without warning about unknown keys", () => {
    writePolicy(
      "internalDisclosure:",
      "  hashedTerms:",
      `    - ${hashInternalTerm(SECRET_TERM)}`,
      "  patterns:",
      "    - sample-service",
      "  externalFile: .scg-internal-terms.local",
    );
    const policy = loadPolicyConfig(tempDir);
    const unknown = (policy?.warnings ?? []).filter((w) => w.rule === "POLICY_UNKNOWN_KEY");
    expect(unknown).toEqual([]);
    expect(policy?.internalDisclosure?.hashedTerms).toHaveLength(1);
    expect(policy?.internalDisclosure?.patterns).toEqual(["sample-service"]);
    expect(policy?.internalDisclosure?.externalFile).toBe(".scg-internal-terms.local");
  });

  it("salts the digest when SCG_INTERNAL_HASH_SALT is set", () => {
    // An unsalted sha256 of a low-entropy value such as a hostname is
    // dictionary-attackable: a reader hashes candidate names until one
    // matches. A salt held OUTSIDE the repository is what makes the digest
    // worth what the README now claims it is worth.
    const salt = "project-salt-value";
    const salted = hashInternalTerm(SECRET_TERM, salt);
    expect(salted).not.toBe(hashInternalTerm(SECRET_TERM));
    expect(salted).toBe(
      crypto.createHash("sha256").update(`${salt}\n${SECRET_TERM}`, "utf8").digest("hex"),
    );

    writePolicy(
      "internalDisclosure:",
      "  hashSalted: true",
      "  hashedTerms:",
      `    - ${salted}`,
    );
    const policy = loadPolicyConfig(tempDir);
    const runtime = loadInternalDisclosureConfig(tempDir, policy, {
      [INTERNAL_HASH_SALT_ENV]: salt,
    } as NodeJS.ProcessEnv);
    expect(runtime.salt).toBe(salt);
    expect(runtime.loadFindings).toHaveLength(0);

    const found = scanInternalDisclosure(`host = ${SECRET_TERM}`, "src/config.ts", runtime);
    expect(rules(found)).toContain("INTERNAL_DENYLIST_MATCH");
    expect(JSON.stringify(found)).not.toContain(SECRET_TERM);
  });

  it("reports a missing salt instead of quietly matching nothing", () => {
    writePolicy(
      "internalDisclosure:",
      "  hashSalted: true",
      "  hashedTerms:",
      `    - ${hashInternalTerm(SECRET_TERM, "some-salt")}`,
    );
    const runtime = loadInternalDisclosureConfig(tempDir, loadPolicyConfig(tempDir), {} as NodeJS.ProcessEnv);
    expect(runtime.enabled).toBe(false);
    expect(rules(runtime.loadFindings)).toContain("INTERNAL_DENYLIST_UNAVAILABLE");
    expect(runtime.loadFindings[0].description).toContain(INTERNAL_HASH_SALT_ENV);
    // The declaration is the only reason this is visible at all: without it a
    // salted digest and a clean repository look identical.
    expect(runtime.hashes.size).toBe(0);
  });

  it("accepts hashSalted without warning about unknown keys", () => {
    writePolicy("internalDisclosure:", "  hashSalted: true");
    const policy = loadPolicyConfig(tempDir);
    expect((policy?.warnings ?? []).filter((w) => w.rule === "POLICY_UNKNOWN_KEY")).toEqual([]);
    expect(policy?.internalDisclosure?.hashSalted).toBe(true);
  });

  it("runs the built-in rules with no deny-list configured", () => {
    const runtime = loadInternalDisclosureConfig(tempDir, null);
    expect(runtime.enabled).toBe(false);
    expect(runtime.loadFindings).toHaveLength(0);
    expect(
      rules(scanInternalDisclosure('host = "vault.corp"', "src/config.ts", runtime)),
    ).toContain("INTERNAL_HOSTNAME");
  });
});

// ---------------------------------------------------------------------------
// Trust boundary: the committed policy file travels inside the scanned tree
// ---------------------------------------------------------------------------

/**
 * Whether this host lets an unprivileged process create a directory link. On
 * Windows without Developer Mode it does not, so the one test that needs one is
 * skipped there and runs on CI.
 */
const directoryLinksSupported = (() => {
  const probe = fs.mkdtempSync(path.join(os.tmpdir(), "scg-link-probe-"));
  try {
    fs.mkdirSync(path.join(probe, "target"));
    fs.symlinkSync(
      path.join(probe, "target"),
      path.join(probe, "link"),
      process.platform === "win32" ? "junction" : "dir",
    );
    return true;
  } catch {
    return false;
  } finally {
    fs.rmSync(probe, { recursive: true, force: true });
  }
})();

describe("internal-disclosure: deny-list entries supplied by the scanned tree", () => {
  const SENTINEL = "alpha-sentinel-9f3";
  let root: string;
  let scanDir: string;
  let outsideDir: string;
  let outsideFile: string;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "scg-trust-"));
    scanDir = path.join(root, "repo");
    outsideDir = path.join(root, "outside");
    fs.mkdirSync(scanDir);
    fs.mkdirSync(outsideDir);
    outsideFile = path.join(outsideDir, "private-inventory.txt");
    // Line 3 cannot be compiled. That matters: if the loader ever opens this
    // file it announces the fact with INTERNAL_DENYLIST_INVALID_ENTRY, so the
    // absence of that finding is what proves the file was never read.
    fs.writeFileSync(
      outsideFile,
      ["# outside the scanned tree", SENTINEL, "sha256:this-is-not-a-digest", ""].join("\n"),
      "utf-8",
    );
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  function writePolicy(...lines: string[]): void {
    fs.writeFileSync(path.join(scanDir, ".supply-chain-guard.yml"), lines.join("\n"), "utf-8");
  }

  /** Load with an empty environment, so only the committed config is in play. */
  function loadFromCommittedConfig() {
    return loadInternalDisclosureConfig(
      scanDir,
      loadPolicyConfig(scanDir),
      {} as NodeJS.ProcessEnv,
    );
  }

  function loadFromOperatorFile(file: string) {
    return loadInternalDisclosureConfig(scanDir, null, {
      [INTERNAL_DISCLOSURE_ENV]: file,
    } as NodeJS.ProcessEnv);
  }

  function probeLine(): string {
    return `const probe = "${SENTINEL}";`;
  }

  it("refuses a committed externalFile that climbs out of the scanned tree", () => {
    // The portable vector: no knowledge of the host layout is needed.
    writePolicy("internalDisclosure:", "  externalFile: ../outside/private-inventory.txt");
    const runtime = loadFromCommittedConfig();

    const refused = runtime.loadFindings.filter((f) => f.rule === "INTERNAL_DENYLIST_REFUSED");
    expect(refused).toHaveLength(1);
    expect(refused[0].severity).toBe("medium");
    expect(refused[0].description).toContain("outside the scanned directory");

    expect(rules(runtime.loadFindings)).not.toContain("INTERNAL_DENYLIST_INVALID_ENTRY");
    expect(runtime.matchers).toHaveLength(0);
    expect(runtime.enabled).toBe(false);
    expect(rules(scanInternalDisclosure(probeLine(), "src/app.js", runtime))).not.toContain(
      "INTERNAL_DENYLIST_MATCH",
    );
  });

  it("refuses an absolute externalFile from the committed config", () => {
    writePolicy("internalDisclosure:", `  externalFile: ${outsideFile.replace(/\\/g, "/")}`);
    const runtime = loadFromCommittedConfig();

    const refused = runtime.loadFindings.filter((f) => f.rule === "INTERNAL_DENYLIST_REFUSED");
    expect(refused).toHaveLength(1);
    expect(refused[0].description).toContain(INTERNAL_DISCLOSURE_ENV);

    expect(rules(runtime.loadFindings)).not.toContain("INTERNAL_DENYLIST_INVALID_ENTRY");
    expect(runtime.matchers).toHaveLength(0);
  });

  it.skipIf(!directoryLinksSupported)(
    "refuses a committed externalFile that leaves the tree through a link",
    () => {
      fs.symlinkSync(
        outsideDir,
        path.join(scanDir, "linked"),
        process.platform === "win32" ? "junction" : "dir",
      );
      // Lexically this never leaves the scan directory. Only resolving the link
      // shows that it does.
      writePolicy("internalDisclosure:", "  externalFile: linked/private-inventory.txt");
      const runtime = loadFromCommittedConfig();

      const refused = runtime.loadFindings.filter((f) => f.rule === "INTERNAL_DENYLIST_REFUSED");
      expect(refused).toHaveLength(1);
      expect(refused[0].description).toContain("symbolic link");
      expect(runtime.matchers).toHaveLength(0);
    },
  );

  it("still reads a deny-list file that stays inside the scanned tree", () => {
    fs.mkdirSync(path.join(scanDir, "config"));
    fs.writeFileSync(path.join(scanDir, "config", "terms.txt"), `${SENTINEL}\n`, "utf-8");
    writePolicy("internalDisclosure:", "  externalFile: config/terms.txt");
    const runtime = loadFromCommittedConfig();

    expect(rules(runtime.loadFindings)).not.toContain("INTERNAL_DENYLIST_REFUSED");
    expect(rules(scanInternalDisclosure(probeLine(), "src/app.js", runtime))).toContain(
      "INTERNAL_DENYLIST_MATCH",
    );
  });

  it("reports an absent in-tree file as unavailable rather than refused", () => {
    // Containment must not swallow the ordinary absence this feature relies on.
    writePolicy("internalDisclosure:", "  externalFile: config/terms.txt");
    const runtime = loadFromCommittedConfig();
    expect(rules(runtime.loadFindings)).toEqual(["INTERNAL_DENYLIST_UNAVAILABLE"]);
  });

  it("leaves the operator's environment variable free to point outside the tree", () => {
    const runtime = loadFromOperatorFile(outsideFile);
    expect(rules(runtime.loadFindings)).not.toContain("INTERNAL_DENYLIST_REFUSED");
    expect(rules(scanInternalDisclosure(probeLine(), "src/app.js", runtime))).toContain(
      "INTERNAL_DENYLIST_MATCH",
    );
  });

  it("keeps per-line reporting for the operator's source, by decision", () => {
    // Recorded choice, not an oversight: the operator chose the file, and
    // per-line reporting is what makes a silently broken deny-list visible.
    const runtime = loadFromOperatorFile(outsideFile);
    const invalid = runtime.loadFindings.filter(
      (f) => f.rule === "INTERNAL_DENYLIST_INVALID_ENTRY",
    );
    expect(invalid).toHaveLength(1);
    expect(invalid[0].description).toContain("line 3");
    expect(invalid[0].description).toContain(INTERNAL_DISCLOSURE_ENV);
    expect(invalid[0].description).not.toContain(outsideDir);
  });

  it(
    "refuses a pathological committed pattern and finishes inside a stated budget",
    { timeout: performanceBudget(60_000) },
    () => {
      writePolicy("internalDisclosure:", "  patterns:", '    - "/(a+)+$/"');
      const runtime = loadFromCommittedConfig();

      // A line the deny-list pass is still willing to inspect, built so the
      // pattern can never match it. The wall clock is asserted FIRST and on
      // purpose: it is the assertion that fails if the refusal ever stops
      // happening, and a reviewer can confirm it is load-bearing by narrowing
      // the refusal to the wrong origin and watching this line, not the ones
      // below it, turn red after tens of seconds.
      const hostile = `const probe = "${"a".repeat(30)}b";`;
      const started = performance.now();
      const found = scanInternalDisclosure(hostile, "src/app.js", runtime);
      const elapsed = performance.now() - started;
      expect(elapsed).toBeLessThan(performanceBudget(5_000));
      expect(rules(found)).not.toContain("INTERNAL_DENYLIST_MATCH");

      const refused = runtime.loadFindings.filter((f) => f.rule === "INTERNAL_DENYLIST_REFUSED");
      expect(refused).toHaveLength(1);
      expect(refused[0].description).toContain("exponential");
      expect(runtime.matchers).toHaveLength(0);
    },
  );

  it("leaves an ordinary committed pattern alone", () => {
    // Precision half of the contract: over-refusing would get the feature
    // switched off, which is worse than the shape it guards against.
    writePolicy(
      "internalDisclosure:",
      "  patterns:",
      "    - /build-\\d{2}\\.corp/",
      "    - /(alpha|beta)-service/",
      "    - sample-service",
    );
    const runtime = loadFromCommittedConfig();
    expect(rules(runtime.loadFindings)).not.toContain("INTERNAL_DENYLIST_REFUSED");
    expect(runtime.matchers).toHaveLength(3);
  });

  it("refuses the ordinary domain-chain hostname shape, which is a behaviour change", () => {
    // The precision test above passes because neither of its patterns is the
    // shape most people reach for. This one IS: a chained label group is how
    // an internal hostname is normally written, it is linear in practice
    // because the inner class cannot match the dot that follows it, and the
    // shape check refuses it anyway.
    //
    // The consequence is not cosmetic. The refusal is a coverage finding, so
    // the scan becomes partial and the published Action exits 1 on a partial
    // scan independently of fail-on. A consumer upgrading with this pattern in
    // place gets a red build and stops matching their own term, which is why
    // README.md and CHANGELOG.md both state it and offer the rewrite. This
    // test is what keeps those two documents honest.
    writePolicy("internalDisclosure:", "  patterns:", "    - /(?:[a-z0-9-]+\\.)+corp\\.example/");
    const refusedRun = loadFromCommittedConfig();
    const refused = refusedRun.loadFindings.filter((f) => f.rule === "INTERNAL_DENYLIST_REFUSED");
    expect(refused).toHaveLength(1);
    expect(refused[0].description).toContain("exponential");
    expect(refusedRun.matchers).toHaveLength(0);
    expect(
      rules(scanInternalDisclosure('const h = "build-01.corp.example";', "src/app.js", refusedRun)),
    ).not.toContain("INTERNAL_DENYLIST_MATCH");

    // The rewrite the finding steers an author towards has to actually work,
    // or the recommendation is advice that leaves them stuck.
    writePolicy("internalDisclosure:", "  patterns:", "    - /[a-z0-9.-]+\\.corp\\.example/");
    const rewritten = loadFromCommittedConfig();
    expect(rules(rewritten.loadFindings)).not.toContain("INTERNAL_DENYLIST_REFUSED");
    expect(
      rules(scanInternalDisclosure('const h = "build-01.corp.example";', "src/app.js", rewritten)),
    ).toContain("INTERNAL_DENYLIST_MATCH");
  });

  it("does not bound a catastrophic shape the classifier fails to recognise", () => {
    // The limit of the shape check, stated as a test so it cannot be forgotten
    // by a reader of the passing suite. Overlapping alternation is ambiguity a
    // scan of the source cannot see, so /(a|a)+$/ compiles, and the wall-clock
    // budget is checked BETWEEN matcher invocations and cannot interrupt the
    // exec that follows. Deliberately asserted WITHOUT running the match: the
    // proof of cost belongs in the issue, not in a suite that has to stay fast.
    writePolicy("internalDisclosure:", "  patterns:", '    - "/(a|a)+$/"');
    const runtime = loadFromCommittedConfig();
    expect(rules(runtime.loadFindings)).not.toContain("INTERNAL_DENYLIST_REFUSED");
    expect(runtime.matchers).toHaveLength(1);
    expect(runtime.matchers[0].origin).toBe("scanned-tree");
  });

  it("caps the length of a committed regex but not of the operator's", () => {
    const long = `/${"a".repeat(MAX_SCANNED_TREE_REGEX_LENGTH + 1)}/`;
    writePolicy("internalDisclosure:", "  patterns:", `    - "${long}"`);
    const fromConfig = loadFromCommittedConfig();
    expect(rules(fromConfig.loadFindings)).toContain("INTERNAL_DENYLIST_REFUSED");
    expect(fromConfig.matchers).toHaveLength(0);

    const operatorFile = path.join(outsideDir, "long-pattern.txt");
    fs.writeFileSync(operatorFile, `${long}\n`, "utf-8");
    const fromOperator = loadFromOperatorFile(operatorFile);
    expect(rules(fromOperator.loadFindings)).not.toContain("INTERNAL_DENYLIST_REFUSED");
    expect(fromOperator.matchers).toHaveLength(1);
  });

  it("stops scanned-tree matchers once their budget is gone, and says so", () => {
    const runtime = emptyInternalDisclosureRuntime();
    runtime.matchers.push(
      {
        kind: "literal",
        literal: "operator-term",
        redact: false,
        label: `$${INTERNAL_DISCLOSURE_ENV} line 1`,
        origin: "operator",
      },
      {
        kind: "literal",
        literal: "tree-term",
        redact: false,
        label: "patterns[0]",
        origin: "scanned-tree",
      },
    );
    runtime.enabled = true;
    runtime.scannedTreeBudgetMs = 0;

    const found = scanInternalDisclosure(
      'const a = "operator-term tree-term";',
      "src/app.js",
      runtime,
    );
    expect(
      found.filter((f) => f.rule === "INTERNAL_DENYLIST_MATCH").map((f) => f.match),
    ).toEqual(["operator-term"]);
    expect(rules(found)).toContain("INTERNAL_DISCLOSURE_TRUNCATED");
  });

  it(
    "charges scanned-tree matchers for the time they spend",
    { timeout: performanceBudget(60_000) },
    () => {
      const slow = `const slow = "${"a".repeat(22)}b";`;
      const content = [
        ...Array.from({ length: 8 }, () => slow),
        'const late = "tree-term";',
      ].join("\n");

      function measure(budgetMs: number) {
        const runtime = emptyInternalDisclosureRuntime();
        runtime.matchers.push(
          // Built by hand on purpose. loadInternalDisclosureConfig refuses this
          // shape outright; what is under test here is the second layer, the
          // budget that catches a pattern the shape check would let through.
          {
            kind: "regex",
            regex: /(a+)+$/i,
            redact: false,
            label: "patterns[0]",
            origin: "scanned-tree",
          },
          {
            kind: "literal",
            literal: "tree-term",
            redact: false,
            label: "patterns[1]",
            origin: "scanned-tree",
          },
        );
        runtime.enabled = true;
        runtime.scannedTreeBudgetMs = budgetMs;

        const started = performance.now();
        const found = scanInternalDisclosure(content, "src/app.js", runtime);
        return { elapsed: performance.now() - started, found, runtime };
      }

      // The generous run goes first so the one-off cost of warming the pattern
      // is charged to the run that is allowed to do all the work. Comparing the
      // two runs, rather than asserting an absolute duration, keeps this
      // meaningful on a machine of any speed.
      const unbounded = measure(600_000);
      const bounded = measure(1);

      // Control: with a budget it cannot exhaust, the pass reaches the last
      // line and finds the term there. Without this the comparison below would
      // hold just as well for a deny-list that never ran at all.
      expect(rules(unbounded.found)).toContain("INTERNAL_DENYLIST_MATCH");

      // With a budget of one millisecond the first line spends it, and the pass
      // stops instead of working through the rest of the file.
      expect(bounded.runtime.scannedTreeBudgetMs).toBeLessThanOrEqual(0);
      expect(rules(bounded.found)).toContain("INTERNAL_DISCLOSURE_TRUNCATED");
      expect(bounded.found.filter((f) => f.rule === "INTERNAL_DENYLIST_MATCH")).toHaveLength(0);
      expect(bounded.elapsed).toBeLessThan(unbounded.elapsed / 3);
    },
  );
});

// ---------------------------------------------------------------------------
// Policy plumbing and end-to-end behaviour
// ---------------------------------------------------------------------------

describe("internal-disclosure: existing policy plumbing", () => {
  it("allowlist.domains answers the host-shaped rules", () => {
    const findings: Finding[] = [
      {
        rule: "INTERNAL_HOSTNAME",
        description: "internal host",
        severity: "medium",
        file: "src/config.ts",
        match: "vault.corp",
        recommendation: "x",
      },
      {
        rule: "INTERNAL_SERVICE_ENDPOINT",
        description: "internal endpoint",
        severity: "medium",
        file: "src/config.ts",
        match: "https://vault.corp:8443",
        recommendation: "x",
      },
      {
        rule: "INTERNAL_PRIVATE_IP",
        description: "private address",
        severity: "medium",
        file: "src/config.ts",
        match: "10.20.30.40",
        recommendation: "x",
      },
    ];
    const { findings: result, suppressedCount } = applyPolicy(findings, {
      allowlist: { domains: ["vault.corp"] },
    });
    expect(suppressedCount).toBe(2);
    expect(rules(result)).toEqual(["INTERNAL_PRIVATE_IP"]);
  });

  it("rules.disable and severityOverrides work on the new rule ids", () => {
    const base: Finding[] = [
      {
        rule: "INTERNAL_PRIVATE_IP",
        description: "private address",
        severity: "medium",
        recommendation: "x",
      },
    ];
    expect(applyPolicy(structuredClone(base), { rules: { disable: ["INTERNAL_PRIVATE_IP"] } }).findings)
      .toHaveLength(0);
    expect(
      applyPolicy(structuredClone(base), {
        rules: { severityOverrides: { INTERNAL_PRIVATE_IP: "info" } },
      }).findings[0].severity,
    ).toBe("info");
  });
});

describe("internal-disclosure: end to end", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-internal-e2e-"));
    delete process.env[INTERNAL_DISCLOSURE_ENV];
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("finds internal topology through scan() without turning the build red", async () => {
    fs.writeFileSync(
      path.join(tempDir, "deploy.yml"),
      [
        "target:",
        '  host: "10.20.30.40"',
        '  forge: "git@forge.corp:acme/sample-service.git"',
        '  metrics: "http://metrics.svc.internal:9090/api"',
      ].join("\n"),
      "utf-8",
    );

    const report = await scan({ target: tempDir, format: "json", noHistory: true });
    const found = rules(report.findings);
    expect(found).toContain("INTERNAL_PRIVATE_IP");
    expect(found).toContain("INTERNAL_GIT_REMOTE");
    expect(found).toContain("INTERNAL_SERVICE_ENDPOINT");

    // Warn-first: the default CLI gate exits non-zero on high/critical only.
    expect(report.summary.critical).toBe(0);
    expect(report.summary.high).toBe(0);
  });

  it("reports a Dockerfile FROM line even though it has no scannable extension", async () => {
    fs.writeFileSync(
      path.join(tempDir, "Dockerfile"),
      ["FROM registry.svc.corp:5000/acme/base:1.2.3", "RUN echo build"].join("\n"),
      "utf-8",
    );
    const report = await scan({ target: tempDir, format: "json", noHistory: true });
    const internal = report.findings.filter((f) => f.rule.startsWith("INTERNAL_"));
    expect(rules(internal)).toContain("INTERNAL_HOSTNAME");
    // Exactly once: Dockerfiles and package-manager configs are read in their
    // own branch of the scan loop, and some also carry a scannable extension.
    expect(internal.filter((f) => f.rule === "INTERNAL_HOSTNAME")).toHaveLength(1);
  });

  it("reports a .yarnrc.yml registry host exactly once (config plus scannable extension)", async () => {
    fs.writeFileSync(
      path.join(tempDir, ".yarnrc.yml"),
      'npmRegistryServer: "https://registry.svc.corp/npm/"\n',
      "utf-8",
    );
    const report = await scan({ target: tempDir, format: "json", noHistory: true });
    const internal = report.findings.filter((f) => f.rule === "INTERNAL_HOSTNAME");
    expect(internal).toHaveLength(1);
  });
});
