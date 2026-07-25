import { describe, it, expect, beforeEach, afterEach } from "vitest";
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
  INTERNAL_DISCLOSURE_PATTERNS,
  INTERNAL_DISCLOSURE_ENV,
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

  it("keeps documentation-prone rules quiet in a markdown file", () => {
    const found = shapeScan("README.md", ...docLeak);
    expect(rules(found)).not.toContain("INTERNAL_PRIVATE_IP");
    expect(rules(found)).not.toContain("INTERNAL_DEV_PATH");
  });

  it("suppresses matches inside a fenced code block, except the clone URL", () => {
    const found = shapeScan("README.md", ...docLeak);
    const fenced = found.filter((f) => f.line !== undefined && f.line >= 5 && f.line <= 9);
    expect(rules(fenced)).toEqual(["INTERNAL_GIT_REMOTE"]);
  });

  it("suppresses matches inside an inline code span", () => {
    const found = shapeScan("README.md", "The address is `192.168.7.12` in the lab.");
    expect(found).toHaveLength(0);
  });

  it("still reports an internal hostname written in documentation prose", () => {
    const found = shapeScan("README.md", "The staging box is api.svc.internal today.");
    expect(rules(found)).toEqual(["INTERNAL_HOSTNAME"]);
  });

  it("treats docs/, examples/ and *.example.* files as documentation", () => {
    expect(isDocumentationFile("docs/setup.md")).toBe(true);
    expect(isDocumentationFile("docs/deploy.yml")).toBe(true);
    expect(isDocumentationFile("examples/compose.yml")).toBe(true);
    expect(isDocumentationFile("config.example.yml")).toBe(true);
    expect(isDocumentationFile(".env.example")).toBe(true);
    expect(isDocumentationFile("src/config.ts")).toBe(false);
    expect(isDocumentationFile("src/sample-service.ts")).toBe(false);

    expect(shapeScan("docs/deploy.yml", 'host: "10.20.30.40"')).toHaveLength(0);
    expect(shapeScan("config.example.yml", 'host: "10.20.30.40"')).toHaveLength(0);
    // A hostname keeps its meaning even in an example file.
    expect(rules(shapeScan("config.example.yml", 'host: "vault.corp"'))).toContain(
      "INTERNAL_HOSTNAME",
    );
  });

  it("skips test fixtures and minified bundles", () => {
    expect(shapeScan("src/__tests__/proxy.test.ts", 'const ip = "10.20.30.40";')).toHaveLength(0);
    expect(shapeScan("assets/vendor.min.js", 'var h="10.20.30.40"')).toHaveLength(0);
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
