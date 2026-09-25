import { describe, it, expect, afterEach } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { scan } from "../scanner.js";
import { getBundledFeed, FEED_CACHE_FILE, type FeedIOC } from "../threat-intel.js";
import { scanActionMetadataReferences } from "../github-actions-scanner.js";
import { extractTerraformProviders } from "../terraform-scanner.js";
import { handleMcpMessage, lookupFeedIOC } from "../mcp-server.js";
import { planMigration } from "../../scripts/feed-migrate.mjs";
import { loadPartitionConfig } from "../../scripts/feed-partition.mjs";

// Detection gaps found by the review of 6.3.0 before its tag. Indicators come
// from the bundled feed or are synthetic, so no real IOC is written here.

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});
const tmp = () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "scg-review-"));
  dirs.push(d);
  return d;
};
const write = (root: string, rel: string, content: string) => {
  const file = path.join(root, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
};
const rulesOf = async (dir: string, cacheDir?: string) =>
  (await scan({ target: dir, format: "json", noHistory: true, cacheDir })).findings.map((f) => f.rule);

const bundled = (prefix: string, versioned: boolean): FeedIOC => {
  const hit = getBundledFeed().find((e) =>
    e.type === "package" && e.value.startsWith(prefix) && (e.value.lastIndexOf("@") > prefix.length) === versioned);
  if (!hit) throw new Error(`no bundled ${prefix} entry`);
  return hit;
};
const splitAt = (value: string, prefix: string) => {
  const body = value.slice(prefix.length);
  const at = body.lastIndexOf("@");
  return at > 0 ? { name: body.slice(0, at), version: body.slice(at + 1) } : { name: body, version: undefined };
};

const SHA = "a".repeat(39) + "b";
const feedEntry = (value: string): FeedIOC =>
  ({ type: "package", value, severity: "critical", confidence: 1, source: "test", firstSeen: "2026-09-26" }) as FeedIOC;

describe("compromised Action commits", () => {
  it("are matched against the scan's feed, so a refreshed cache reaches them", async () => {
    const dir = tmp();
    write(dir, ".github/workflows/ci.yml", `on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme/tool@${SHA}\n`);
    write(dir, "tools/composite/action.yml", `runs:\n  using: composite\n  steps:\n    - uses: acme/tool@${SHA}\n`);
    const cacheDir = tmp();
    fs.writeFileSync(path.join(cacheDir, FEED_CACHE_FILE),
      JSON.stringify({ timestamp: new Date().toISOString(), entries: [feedEntry(`actions:acme/tool@${SHA}`)] }));

    const withCache = (await rulesOf(dir, cacheDir)).filter((r) => r === "GHA_KNOWN_MALICIOUS_SHA");
    expect(withCache).toHaveLength(2); // the workflow and the composite action
    // Control: the same tree without that cache has no such finding.
    expect(await rulesOf(dir)).not.toContain("GHA_KNOWN_MALICIOUS_SHA");
  });

  it("are found when the uses: value is quoted", () => {
    const { name, version } = splitAt(bundled("actions:", true).value, "actions:");
    for (const q of ['"', "'"]) {
      const found = scanActionMetadataReferences(`runs:\n  steps:\n    - uses: ${q}${name}@${version}${q}\n`, "action.yml");
      expect(found.map((f) => f.rule), q).toContain("GHA_KNOWN_MALICIOUS_SHA");
    }
  });
});

describe("PyPI indicators carry their prefix", () => {
  it("flags a requirements.txt that depends on one, which the bare npm-namespace entry never did", async () => {
    const dir = tmp();
    write(dir, "requirements.txt", "colorinal==1.0.0\n");
    const findings = (await scan({ target: dir, format: "json", noHistory: true })).findings;
    expect(findings.some((f) => f.rule === "PYTHON_MALICIOUS_PACKAGE" && f.description.includes("colorinal"))).toBe(true);
    // Control: a clean requirement raises no such finding.
    const clean = tmp();
    write(clean, "requirements.txt", "requests==2.32.3\n");
    const cleanFindings = (await scan({ target: clean, format: "json", noHistory: true })).findings;
    expect(cleanFindings.some((f) => f.rule === "PYTHON_MALICIOUS_PACKAGE")).toBe(false);
  });

  it("keeps every PyPI-campaign package entry out of the bare (npm) namespace", () => {
    const bare = getBundledFeed().filter((e) =>
      e.type === "package" && !e.value.includes(":") && /pypi/i.test(`${e.campaign ?? ""} ${e.family ?? ""}`)
      && !/npm/i.test(e.campaign ?? ""));
    expect(bare.map((e) => e.value)).toEqual([]);
    for (const name of ["uuid32-utils", "colorinal", "termncolor", "parsimonius"]) {
      expect(getBundledFeed().some((e) => e.value === `pypi:${name}`), name).toBe(true);
      expect(getBundledFeed().some((e) => e.value === name), name).toBe(false);
    }
  });
});

describe("files that were never read", () => {
  it("scans Containerfile.<suffix> like Dockerfile.<suffix>", async () => {
    const { name, version } = splitAt(bundled("docker:", true).value, "docker:");
    const dir = tmp();
    write(dir, "Containerfile.prod", `FROM ${name}:${version}\nRUN echo hi\n`);
    expect(await rulesOf(dir)).toContain("DOCKER_MALICIOUS_IMAGE");
  });

  it("checks the extension recommendations of a .code-workspace file", async () => {
    const { name } = splitAt(bundled("vscode:", false).value, "vscode:");
    const dir = tmp();
    write(dir, "project.code-workspace", JSON.stringify({ folders: [{ path: "." }], extensions: { recommendations: [name] } }));
    expect(await rulesOf(dir)).toContain("VSCODE_MALICIOUS_EXTENSION");
    // Control: the same file without the recommendation.
    const clean = tmp();
    write(clean, "project.code-workspace", JSON.stringify({ folders: [{ path: "." }], extensions: { recommendations: [] } }));
    expect(await rulesOf(clean)).not.toContain("VSCODE_MALICIOUS_EXTENSION");
  });
});

describe("Terraform required_providers on one line", () => {
  it("reads a source inside a one-line block, and ignores one outside it", () => {
    const one = 'terraform { required_providers { docker = { source = "acme/prov" } } }\n';
    expect(extractTerraformProviders(one, "main.tf").map((p) => p.address)).toEqual(["acme/prov"]);
    const split = 'terraform {\n  required_providers { docker = { source = "acme/prov" } }\n}\n';
    expect(extractTerraformProviders(split, "main.tf").map((p) => p.address)).toEqual(["acme/prov"]);
    // Control: a `source` after the block closed on the same line is a module
    // or file source, not a provider.
    const after = 'terraform { required_providers { } } module "m" { source = "acme/prov" }\n';
    expect(extractTerraformProviders(after, "main.tf")).toEqual([]);
  });

  it("is reported through a scan", async () => {
    const { name } = splitAt(bundled("terraform:", false).value, "terraform:");
    const dir = tmp();
    write(dir, "main.tf", `terraform { required_providers { x = { source = "${name}" } } }\n`);
    expect(await rulesOf(dir)).toContain("TERRAFORM_MALICIOUS_PROVIDER");
  });
});

describe("the 2026-09-22 daily intelligence", () => {
  // The catalog window for that day was set for one ReversingLabs batch
  // (MAL-2026-16487 to 17152); a window covers the whole day, so it also moved
  // that day's other, fresh records out of the offline bundle.
  const malIn = (e: FeedIOC, lo: number, hi: number) =>
    [...String(e.source ?? "").matchAll(/MAL-2026-(\d+)/g)].some((m) => Number(m[1]) >= lo && Number(m[1]) <= hi);
  const batch = (e: FeedIOC) => malIn(e, 16487, 17152);
  const day = () => getBundledFeed().filter((e) => e.type === "package" && e.firstSeen === "2026-09-22");

  it("ships the records outside the bulk batch in the bundle", () => {
    const fresh = day().filter((e) => malIn(e, 16374, 16466));
    expect(fresh).toHaveLength(58);
    expect(fresh.map((e) => e.value)).toContain("ubiquiti-agents-link-mcp");
    // Control: the bulk batch itself stays out of the bundle.
    expect(day().filter(batch)).toEqual([]);
  });

  it("stays in the bundle at the next release's migration", () => {
    // check:feed-partition does not evaluate the curated-comment rule; only the
    // migration does. So ask the migration: with the committed cutoff and
    // windows, none of the 58 may be planned to move.
    const root = path.resolve(__dirname, "..", "..");
    const source = fs.readFileSync(path.join(root, "src", "threat-intel.ts"), "utf8");
    const moves = new Set(
      (planMigration(source, loadPartitionConfig(root)) as { move: Array<{ value: string }> }).move.map((m) => m.value),
    );
    const fresh = day().filter((e) => malIn(e, 16374, 16466)).map((e) => e.value);
    expect(fresh).toHaveLength(58);
    expect(fresh.filter((v) => moves.has(v))).toEqual([]);
  });

  it("is found by a default offline scan, without the catalog", async () => {
    const dir = tmp();
    write(dir, "package.json", JSON.stringify({ name: "x", version: "1.0.0", dependencies: { "ubiquiti-agents-link-mcp": "0.2.1" } }));
    const findings = (await scan({ target: dir, format: "json", noHistory: true })).findings;
    expect(findings.some((f) => f.severity === "critical" && f.description.includes("ubiquiti-agents-link-mcp"))).toBe(true);
  });
});

describe("MCP scan_directory", () => {
  it("states whether the historical catalog was consulted, whatever the severity filter", async () => {
    const dir = tmp();
    write(dir, "index.js", "module.exports = 1;\n");
    const res = (await handleMcpMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "scan_directory", arguments: { path: dir, minSeverity: "critical" } },
    })) as { result: { content: Array<{ text: string }> } };
    const body = JSON.parse(res.result.content[0]!.text) as { catalog: unknown };
    expect(body.catalog).toMatchObject({ consulted: expect.any(Boolean), entryCount: expect.any(Number) });
  });
});

describe("MCP ioc_lookup finds entries the way the scanners do", () => {
  const DIGEST = "sha256:" + "c".repeat(64);
  const feed = [
    feedEntry("docker:acme/app@1.2.3"),
    feedEntry(`docker:acme/app@${DIGEST}`),
    feedEntry("terraform:acme/prov"),
    feedEntry("tfmodule:acme/mod/aws"),
    feedEntry("swift:github.com/acme/kit"),
    feedEntry(`actions:acme/act@${SHA}`),
    feedEntry("bare-only-name"),
  ];
  const hit = (eco: Parameters<typeof lookupFeedIOC>[0], name: string, version?: string) =>
    lookupFeedIOC(eco, name, version, feed)?.value ?? null;

  it("resolves the forms a scan resolves", () => {
    expect(hit("docker", "docker.io/acme/app", "1.2.3")).toBe("docker:acme/app@1.2.3");
    expect(hit("docker", "ghcr.io/someone/else", DIGEST)).toBe(`docker:acme/app@${DIGEST}`);
    expect(hit("terraform", "registry.terraform.io/acme/prov")).toBe("terraform:acme/prov");
    expect(hit("tfmodule", "registry.terraform.io/acme/mod/aws")).toBe("tfmodule:acme/mod/aws");
    expect(hit("swift", "https://github.com/Acme/Kit.git")).toBe("swift:github.com/acme/kit");
    expect(hit("actions", "someone/fork", SHA.toUpperCase())).toBe(`actions:acme/act@${SHA}`);
  });

  it("does not answer a PyPI lookup with an npm entry", () => {
    expect(hit("npm", "bare-only-name")).toBe("bare-only-name");
    expect(hit("pypi", "bare-only-name")).toBeNull();
  });

  it("still answers the plain forms", () => {
    expect(hit("docker", "acme/app", "1.2.3")).toBe("docker:acme/app@1.2.3");
    expect(hit("terraform", "acme/prov")).toBe("terraform:acme/prov");
    expect(hit("docker", "acme/app", "9.9.9")).toBeNull();
  });
});
