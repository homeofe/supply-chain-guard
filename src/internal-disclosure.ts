/**
 * Internal-disclosure scanner.
 *
 * Credential scanners answer "did a secret get committed?". This one answers a
 * different question: "did our internal TOPOLOGY get committed?". Internal
 * hostnames, private LAN addresses, self-hosted forge URLs, developer
 * filesystem paths and private repository names are not credentials, so no
 * secret scanner reports them, yet together they are the reconnaissance map an
 * attacker builds before touching anything: what exists, what it is called,
 * where it listens, and who works on it.
 *
 * Design constraints, in order of importance:
 *
 * 1. SHAPE FIRST. Every built-in rule detects a STRUCTURE (RFC1918 address,
 *    internal-only TLD, non-public forge URL, home-directory path), never a
 *    name. Nobody has to write down what their infrastructure is called to be
 *    protected by them, and nothing in this file has to be kept secret.
 *
 * 2. HONEST SEVERITY. Topology is reconnaissance value, not compromise. The
 *    family reports `medium` (weakest signal: `low`). `high` and `critical`
 *    stay reserved for credential-shaped findings, which the existing rules
 *    already own. The default CLI gate only fails on high/critical, so
 *    upgrading to a release that carries these rules cannot turn a build red.
 *
 * 3. FALSE POSITIVES DECIDE ADOPTION. Documentation legitimately teaches with
 *    addresses and paths. Two independent layers keep it quiet:
 *      - VALUE layer: the reserved documentation space never fires. RFC5737
 *        addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), RFC2606
 *        names (example.com and friends, the `.example` TLD, `.invalid`,
 *        `.test`), loopback, and placeholder or CI account names are all
 *        rejected by `valueFilter` before a finding exists.
 *      - CONTEXT layer: see DOC_SURVIVING_RULES / FENCE_SURVIVING_RULES below.
 *        Documentation files, `docs/` and `examples/` trees, `*.example.*`
 *        artifacts, markdown fenced code blocks and inline code spans each
 *        narrow the family down to the rules that stay meaningful there.
 *
 * 4. THE DENY-LIST PARADOX. A list of your internal hostnames committed to a
 *    public repository IS the leak it was meant to prevent. `hashedTerms`
 *    therefore stores only sha256 digests of normalised terms: publishable,
 *    reveals nothing, and (honestly) only ever matches whole tokens.
 *    `externalFile` keeps full regex/plaintext patterns outside the repository,
 *    and `patterns` exists for repositories that are private anyway. Matches
 *    from the two unpublished sources are reported REDACTED, so a finding can
 *    never expose more than the user already published.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, PatternEntry, PolicyConfig } from "./types.js";
import { isPatternMatchAccepted } from "./patterns.js";

// ---------------------------------------------------------------------------
// Reserved documentation space (the value layer)
// ---------------------------------------------------------------------------

/**
 * Reserved names that exist so documentation can use them: RFC2606 example
 * domains and reserved TLDs, plus loopback names. A host in this space is a
 * teaching aid, never infrastructure.
 */
const RESERVED_DOC_SUFFIXES = [
  "example.com",
  "example.org",
  "example.net",
  "example.edu",
  "example",
  "invalid",
  "test",
  "localhost",
];

/** Loopback / unspecified hosts. Never a topology leak. */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]"]);

/** True when a host sits in the reserved documentation namespace. */
export function isReservedDocHost(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, "");
  if (h === "") return true;
  return RESERVED_DOC_SUFFIXES.some((s) => h === s || h.endsWith("." + s));
}

/** True when a host is loopback or the unspecified address. */
export function isLoopbackHost(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (LOOPBACK_HOSTS.has(h) || LOOPBACK_HOSTS.has(host.trim().toLowerCase())) return true;
  const octets = parseIPv4(h);
  return octets !== null && octets[0] === 127;
}

// ---------------------------------------------------------------------------
// IPv4 classification
// ---------------------------------------------------------------------------

/**
 * Parse a dotted-quad into octets, or null when the text only looks like one.
 * Leading zeros are rejected: `010.0.0.1` is not how an address is written and
 * is far more often a serial number or an identifier.
 */
export function parseIPv4(value: string): number[] | null {
  const parts = value.trim().split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith("0")) return null;
    const n = Number(part);
    if (n > 255) return null;
    octets.push(n);
  }
  return octets;
}

export type IPv4Class = "private" | "loopback" | "documentation" | "public" | "invalid";

/**
 * Classify an IPv4 address.
 *
 * `private` covers everything that only exists inside somebody's network:
 * RFC1918 (10/8, 172.16/12, 192.168/16), CGNAT (100.64/10) and link-local
 * (169.254/16). The documentation ranges from RFC5737 are called out
 * separately so they can never be reported.
 */
export function classifyIPv4(value: string): IPv4Class {
  const o = parseIPv4(value);
  if (!o) return "invalid";

  // RFC5737 documentation ranges. Written octet by octet on purpose: this
  // source file must not contain anything shaped like a real address.
  if (o[0] === 192 && o[1] === 0 && o[2] === 2) return "documentation";
  if (o[0] === 198 && o[1] === 51 && o[2] === 100) return "documentation";
  if (o[0] === 203 && o[1] === 0 && o[2] === 113) return "documentation";

  if (o[0] === 127) return "loopback";
  if (o[0] === 0) return "loopback";

  if (o[0] === 10) return "private";
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return "private";
  if (o[0] === 192 && o[1] === 168) return "private";
  if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return "private";
  if (o[0] === 169 && o[1] === 254) return "private";

  return "public";
}

/**
 * Value guard for INTERNAL_PRIVATE_IP. The match may carry a CIDR suffix.
 *
 * Two shapes are deliberately NOT reported:
 *   - a network range (`/8`, `/16`, `/24`): that describes a subnet layout and
 *     is boilerplate in every IaC file. A `/32` is a single host and stays.
 *   - an address whose host octet is 0: that is how a range is written in
 *     prose and in configuration defaults, not a machine anybody can reach.
 */
export function isPrivateAddressLeak(value: string): boolean {
  const [addr, suffix] = value.trim().split("/");
  if (suffix !== undefined) {
    if (!/^\d{1,2}$/.test(suffix)) return false;
    if (Number(suffix) !== 32) return false;
  }
  if (classifyIPv4(addr) !== "private") return false;
  const octets = parseIPv4(addr);
  return octets !== null && octets[3] !== 0;
}

/**
 * Value guard for INTERNAL_PRIVATE_IPV6: IPv6 Unique Local Addresses
 * (fc00::/7, in practice fd00::/8). A bare prefix ending in `::` describes a
 * range rather than a host and is not reported.
 */
export function isUniqueLocalIPv6(value: string): boolean {
  const v = value.trim().toLowerCase();
  if (!/^f[cd][0-9a-f]{2}:/.test(v)) return false;
  if (v.endsWith("::")) return false;
  if (v.endsWith(":")) return false;
  if ((v.match(/::/g) ?? []).length > 1) return false;
  const groups = v.split("::").join(":").split(":").filter((g) => g !== "");
  if (groups.length < 2) return false;
  return groups.every((g) => /^[0-9a-f]{1,4}$/.test(g));
}

// ---------------------------------------------------------------------------
// Host classification
// ---------------------------------------------------------------------------

/** TLDs that only resolve inside a private network. */
const INTERNAL_TLDS = ["internal", "local", "lan", "corp", "home", "intranet"];

/**
 * Single-label hosts that are container or compose service aliases rather than
 * machine names. They share the shape of an internal hostname, they appear in
 * an enormous number of perfectly public projects, and reporting them is the
 * fastest way to get a rule switched off.
 */
const SERVICE_ALIAS_HOSTS = new Set([
  "localhost", "host", "hostname", "server", "service", "services", "example",
  "db", "database", "postgres", "postgresql", "pg", "mysql", "mariadb", "redis",
  "valkey", "mongo", "mongodb", "couchdb", "cassandra", "clickhouse", "sqlite",
  "rabbitmq", "kafka", "zookeeper", "nats", "broker", "queue", "worker",
  "elasticsearch", "opensearch", "solr", "memcached", "cache", "minio", "s3",
  "nginx", "traefik", "envoy", "haproxy", "proxy", "gateway", "router",
  "api", "web", "www", "app", "frontend", "backend", "ui", "client", "admin",
  "auth", "sso", "keycloak", "vault", "consul", "etcd", "registry", "mailhog",
  "mailpit", "smtp", "mail", "grafana", "prometheus", "loki", "jaeger", "otel",
  "selenium", "chrome", "firefox", "test", "tests", "e2e", "mock", "mockserver",
  "wiremock", "localstack", "jenkins", "sonarqube", "runner", "node", "python",
]);

/**
 * Account names that denote a placeholder, a shared system account or a CI
 * runner rather than a person. `/home/runner/` is on every GitHub Actions log
 * line ever written and discloses nothing.
 */
const GENERIC_ACCOUNT_NAMES = new Set([
  "user", "users", "username", "name", "you", "your", "yourname", "yourusername",
  "me", "myname", "myuser", "dev", "developer", "devuser", "admin", "administrator",
  "example", "sample", "someone", "somebody", "person", "john", "jane", "johndoe",
  "janedoe", "jdoe", "foo", "bar", "baz", "test", "tester", "testuser", "demo",
  "runner", "node", "vscode", "codespace", "gitpod", "ubuntu", "debian", "alpine",
  "jenkins", "circleci", "travis", "buildkite", "teamcity", "azureuser", "vsts",
  "ec2-user", "docker", "container", "containeradministrator", "builder", "build",
  "ci", "cicd", "app", "appuser", "application", "service", "svc", "deploy",
  "deployer", "git", "www-data", "nobody", "root", "public", "default", "guest",
  "all users", "defaultuser", "linuxbrew", "homebrew", "opt", "shared", "temp",
]);

/**
 * Forges that anybody can reach. A clone URL pointing at one of these is not a
 * topology leak, it is how open source works. Subdomains count (ssh.github.com,
 * altssh.gitlab.com, a-team.git.sr.ht).
 */
const PUBLIC_FORGE_HOSTS = [
  "github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sr.ht",
  "git.sr.ht", "gitee.com", "sourceforge.net", "sourcehut.org", "launchpad.net",
  "salsa.debian.org", "invent.kde.org", "gitlab.gnome.org", "gitlab.freedesktop.org",
  "git.kernel.org", "git.savannah.gnu.org", "gitlab.haskell.org", "huggingface.co",
  "dev.azure.com", "visualstudio.com", "azure.com", "amazonaws.com",
  "googlesource.com", "source.developers.google.com", "git.eclipse.org",
  "gerrit.googlesource.com", "opendev.org", "pagure.io", "gitea.com", "gitflic.ru",
];

/** True when `host` is one of the public forges (exact host or a subdomain). */
export function isPublicForgeHost(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, "");
  return PUBLIC_FORGE_HOSTS.some((f) => h === f || h.endsWith("." + f));
}

/** True when the host ends in a TLD that only resolves inside a network. */
export function hasInternalTld(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.$/, "");
  const lastDot = h.lastIndexOf(".");
  if (lastDot <= 0) return false;
  return INTERNAL_TLDS.includes(h.slice(lastDot + 1));
}

/**
 * True when a host is internal in any of the senses this family understands:
 * a private address, an internal-only TLD, or a single-label machine name that
 * is not a container service alias.
 */
export function isInternalHost(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (h === "") return false;
  if (isLoopbackHost(h) || isReservedDocHost(h)) return false;
  if (parseIPv4(h) !== null) return classifyIPv4(h) === "private";
  if (h.includes(":")) return isUniqueLocalIPv6(h);
  if (hasInternalTld(h)) return !h.split(".").includes("example");
  if (!h.includes(".")) return !SERVICE_ALIAS_HOSTS.has(h);
  return false;
}

/** Value guard for INTERNAL_HOSTNAME. */
export function isInternalHostname(value: string): boolean {
  const h = value.trim().toLowerCase().replace(/\.$/, "");
  if (!hasInternalTld(h)) return false;
  if (isReservedDocHost(h)) return false;
  // A label of "example" marks a teaching name (`svc.example.corp`).
  return !h.split(".").includes("example");
}

/** Value guard for INTERNAL_SINGLE_LABEL_URL (the captured host). */
export function isSingleLabelInternalHost(value: string): boolean {
  const h = value.trim().toLowerCase();
  if (h === "" || h.includes(".") || h.includes(":")) return false;
  if (SERVICE_ALIAS_HOSTS.has(h)) return false;
  if (/^\d+$/.test(h)) return false;
  return true;
}

/** Value guard for INTERNAL_SERVICE_ENDPOINT (the captured host). */
export function isInternalEndpointHost(value: string): boolean {
  return isInternalHost(value);
}

/**
 * Value guard for INTERNAL_GIT_REMOTE (the captured host): a forge that is not
 * one of the known public ones. This is the shape that finds a self-hosted
 * forge without anybody having to name it in a configuration file.
 */
export function isNonPublicForgeHost(value: string): boolean {
  const h = value.trim().toLowerCase().replace(/\.$/, "");
  if (h === "") return false;
  if (isLoopbackHost(h) || isReservedDocHost(h)) return false;
  if (isPublicForgeHost(h)) return false;
  if (parseIPv4(h) !== null) return classifyIPv4(h) === "private";
  return true;
}

/** Value guard for INTERNAL_DEV_PATH (the captured account name). */
export function isPersonalAccountName(value: string): boolean {
  const name = value.trim().toLowerCase().replace(/[._-]+$/, "");
  if (name.length < 2 || name.length > 64) return false;
  if (GENERIC_ACCOUNT_NAMES.has(name)) return false;
  if (/^(?:your|my)[._-]?/.test(name)) return false;
  if (/^(?:x{2,}|\.{2,})$/.test(name)) return false;
  // Version-like or purely numeric segments are not account names.
  if (/^[\d.]+$/.test(name)) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Built-in shape rules
// ---------------------------------------------------------------------------

/** Minified bundles and source maps are machine output, not authored content. */
const MINIFIED_OR_MAP = /\.(?:min\.(?:js|css)|map)$/i;

/**
 * The built-in rule family. Every entry is pure shape plus a value guard, so
 * it is useful on a repository whose owner has configured nothing at all.
 */
export const INTERNAL_DISCLOSURE_PATTERNS: PatternEntry[] = [
  {
    name: "internal-private-ipv4",
    pattern: "(?<![\\w.-])(?:\\d{1,3}\\.){3}\\d{1,3}(?:/\\d{1,2})?(?![\\w.-])",
    description:
      "Private, non-routable IPv4 address committed to the repository. RFC1918, CGNAT and link-local addresses only exist inside a network, so publishing one describes that network's internal layout.",
    severity: "medium",
    rule: "INTERNAL_PRIVATE_IP",
    valueGroup: 0,
    valueFilter: isPrivateAddressLeak,
    notFilePattern: MINIFIED_OR_MAP,
    notTestFile: true,
  },
  {
    name: "internal-private-ipv6",
    pattern: "(?<![:\\w.-])f[cd][0-9a-f]{2}:[0-9a-f:]{2,45}(?![\\w.-])",
    description:
      "IPv6 Unique Local Address (fc00::/7) committed to the repository. ULA addresses are only reachable inside a private network and disclose its internal addressing plan.",
    severity: "medium",
    rule: "INTERNAL_PRIVATE_IPV6",
    valueGroup: 0,
    valueFilter: isUniqueLocalIPv6,
    notFilePattern: MINIFIED_OR_MAP,
    notTestFile: true,
  },
  {
    name: "internal-hostname",
    // The trailing `(?!\.[a-z0-9])` is what separates a hostname from a
    // namespace or a filename: an internal-only TLD is the LAST label of a
    // host, so `config.internal.timeout`, `com.acme.internal.util` and
    // `settings.local.json` are not hosts and never match. A trailing full
    // stop at the end of a sentence still does.
    pattern:
      "(?<![\\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+(?:internal|local|lan|corp|home|intranet)(?![\\w-])(?!\\.[a-z0-9])",
    description:
      "Hostname in an internal-only TLD (.internal, .local, .lan, .corp, .home, .intranet) committed to the repository. Such a name never resolves publicly, so its presence names a machine on a private network.",
    severity: "medium",
    rule: "INTERNAL_HOSTNAME",
    valueGroup: 0,
    valueFilter: isInternalHostname,
    notFilePattern: MINIFIED_OR_MAP,
    notTestFile: true,
  },
  {
    name: "internal-single-label-url",
    pattern:
      "\\bhttps?://([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)(?::\\d{2,5})?(?=[/\\s\"'`)\\],;]|$)",
    description:
      "URL pointing at a single-label host. A host name with no domain only resolves through internal DNS, a hosts file or a container network, so the URL describes an internal service.",
    severity: "low",
    rule: "INTERNAL_SINGLE_LABEL_URL",
    valueGroup: 1,
    valueFilter: isSingleLabelInternalHost,
    notFilePattern: MINIFIED_OR_MAP,
    notTestFile: true,
  },
  {
    name: "internal-service-endpoint",
    pattern:
      "\\bhttps?://(?:[\\w.%+-]+(?::[^@\\s/]*)?@)?([a-z0-9.-]+|\\[[0-9a-f:]+\\]):(\\d{2,5})(?![\\d])",
    description:
      "Service endpoint (host plus port) on an internal or private host. Endpoint plus port is the most directly actionable piece of reconnaissance in a repository: it names a service, where it runs and how to reach it.",
    severity: "medium",
    rule: "INTERNAL_SERVICE_ENDPOINT",
    valueGroup: 1,
    valueFilter: isInternalEndpointHost,
    notFilePattern: MINIFIED_OR_MAP,
    notTestFile: true,
  },
  {
    name: "internal-git-remote-ssh",
    pattern: "\\bssh://(?:[\\w.%+-]+@)?([a-z0-9.-]+)(?::\\d{2,5})?/[\\w./~+-]+",
    description:
      "Git or SSH URL pointing at a host that is not a known public forge. A clone URL for a self-hosted forge discloses the forge hostname, its SSH port and the internal project path.",
    severity: "medium",
    rule: "INTERNAL_GIT_REMOTE",
    valueGroup: 1,
    valueFilter: isNonPublicForgeHost,
    notFilePattern: MINIFIED_OR_MAP,
    notTestFile: true,
  },
  {
    name: "internal-git-remote-scp",
    pattern: "(?<![\\w@.+-])git@([a-z0-9.-]+):(?![/\\\\])[\\w./~+-]+",
    description:
      "scp-style git remote pointing at a host that is not a known public forge. A clone URL for a self-hosted forge discloses the forge hostname and the internal project path.",
    severity: "medium",
    rule: "INTERNAL_GIT_REMOTE",
    valueGroup: 1,
    valueFilter: isNonPublicForgeHost,
    notFilePattern: MINIFIED_OR_MAP,
    notTestFile: true,
  },
  {
    name: "internal-dev-path-windows",
    pattern: "[A-Za-z]:[\\\\/]{1,2}Users[\\\\/]{1,2}([A-Za-z0-9 ._-]{2,64})[\\\\/]",
    description:
      "Developer filesystem path committed to the repository. A home-directory path discloses an account name and the local layout of a workstation, and usually means a machine-specific value was committed by accident.",
    severity: "medium",
    rule: "INTERNAL_DEV_PATH",
    valueGroup: 1,
    valueFilter: isPersonalAccountName,
    notFilePattern: MINIFIED_OR_MAP,
    notTestFile: true,
  },
  {
    name: "internal-dev-path-unix",
    pattern: "(?<![\\w.-])/(?:home|Users)/([A-Za-z0-9._-]{2,64})/",
    description:
      "Developer filesystem path committed to the repository. A home-directory path discloses an account name and the local layout of a workstation, and usually means a machine-specific value was committed by accident.",
    severity: "medium",
    rule: "INTERNAL_DEV_PATH",
    valueGroup: 1,
    valueFilter: isPersonalAccountName,
    notFilePattern: MINIFIED_OR_MAP,
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Context layer
// ---------------------------------------------------------------------------

/** Prose files. Documentation teaches with addresses and paths. */
const DOC_FILE = /\.(?:md|markdown|mdx|rst|txt|adoc)$/i;

/** Trees whose whole purpose is to show examples. */
const DOC_DIR = /(?:^|\/)(?:docs?|examples?|samples?|fixtures?|man)\//i;

/** Template artifacts: `config.example.yml`, `.env.example`, `values.sample.yaml`. */
const EXAMPLE_ARTIFACT = /(?:^|[./])(?:example|sample|template|dist|tpl)(?:\.[^/]*)?$/i;

/** Markdown-family files, where fenced blocks and inline code exist. */
const MARKDOWN_FILE = /\.(?:md|markdown|mdx)$/i;

/**
 * Rules that keep firing inside a documentation FILE.
 *
 * An internal-only hostname, a non-public clone URL and an internal service
 * endpoint are exactly what a README leaks in the real world ("clone it from
 * here", "the staging box is over there"), and the reserved documentation
 * namespace is excluded by value, so a writer following RFC2606 and RFC5737
 * is never interrupted. The example-prone rules (private addresses, developer
 * paths, single-label URLs) are the ones documentation genuinely uses, so they
 * stay silent there.
 */
const DOC_SURVIVING_RULES = new Set([
  "INTERNAL_HOSTNAME",
  "INTERNAL_GIT_REMOTE",
  "INTERNAL_SERVICE_ENDPOINT",
]);

/**
 * Rules that keep firing inside a markdown fenced code block or an inline code
 * span. A fenced block is a literal example, with one exception worth keeping:
 * the copy-and-paste clone command is where a self-hosted forge URL actually
 * ends up, and its public form (github.com and friends) is already excluded.
 */
const FENCE_SURVIVING_RULES = new Set(["INTERNAL_GIT_REMOTE"]);

/**
 * Programming-language sources, where a dotted name is far more likely to be a
 * property access (an object with a field named `internal` or `local`) than a
 * host. See isHostnameContextOk().
 */
const CODE_FILE = /\.(?:[cm]?[jt]sx?|py|rb|rs|go|java|kt|php|cs|swift|scala|dart|c|h|cpp|hpp)$/i;

/** Test / spec / fixture files. Mirrors TEST_FILE_REGEX in scanner.ts. */
const TEST_FILE = /[._-](test|spec|mock|fixture|stub|fake)\.|__tests__|\/tests?\/|conftest\.py/i;

/** True when the file itself is a documentation or example surface. */
export function isDocumentationFile(relativePath: string): boolean {
  const p = relativePath.replace(/\\/g, "/");
  const base = p.slice(p.lastIndexOf("/") + 1);
  return DOC_FILE.test(base) || DOC_DIR.test(p) || EXAMPLE_ARTIFACT.test(base);
}

/**
 * Per-line markdown code state: which lines sit inside a fenced block, and
 * which column ranges of a line are inline code spans.
 */
interface MarkdownCodeMap {
  fenced: boolean[];
  inline: Array<Array<[number, number]>>;
}

/**
 * Column ranges of quoted string literals on a line. Naive pairing of the same
 * quote character, which is all that is needed to answer "is this token inside
 * a string?".
 */
export function quotedRanges(line: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  let open: { char: string; start: number } | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c !== '"' && c !== "'" && c !== "`") continue;
    if (line[i - 1] === "\\") continue;
    if (open === null) {
      open = { char: c, start: i };
    } else if (open.char === c) {
      ranges.push([open.start, i + 1]);
      open = null;
    }
  }
  return ranges;
}

/**
 * Decide whether a bare hostname match sits somewhere a HOST can plausibly be.
 *
 * In a data or documentation file, anywhere is plausible: `host: db.internal.example`
 * needs no quotes. In a programming-language source, a bare dotted name is
 * usually a property access, and reporting an object field named `internal` or
 * `local` as infrastructure is exactly the noise that gets a rule switched off.
 * There it must be inside a string literal, inside a comment (prose, where the
 * leak often is), or attached to a URL or user prefix.
 */
export function isHostnameContextOk(
  line: string,
  index: number,
  isCodeFile: boolean,
): boolean {
  if (!isCodeFile) return true;
  if (quotedRanges(line).some(([a, b]) => index >= a && index < b)) return true;

  const before = line.slice(Math.max(0, index - 3), index);
  if (before.endsWith("://") || before.endsWith("@")) return true;

  const commentAt = [line.indexOf("//"), line.indexOf("#"), line.indexOf("/*")]
    .filter((p) => p >= 0)
    .sort((a, b) => a - b)[0];
  if (commentAt !== undefined && index > commentAt) return true;
  // A continuation line of a block comment (" * text").
  if (/^\s*\*/.test(line)) return true;

  return false;
}

/** Backtick-run pairing, good enough for `code` spans and ``code with ` `` spans. */
function inlineCodeRanges(line: string): Array<[number, number]> {
  const runs: Array<{ start: number; len: number }> = [];
  for (let i = 0; i < line.length; ) {
    if (line[i] === "`") {
      let j = i;
      while (j < line.length && line[j] === "`") j++;
      runs.push({ start: i, len: j - i });
      i = j;
    } else {
      i++;
    }
  }
  const ranges: Array<[number, number]> = [];
  const used = new Set<number>();
  for (let a = 0; a < runs.length; a++) {
    if (used.has(a)) continue;
    for (let b = a + 1; b < runs.length; b++) {
      if (used.has(b) || runs[b].len !== runs[a].len) continue;
      ranges.push([runs[a].start, runs[b].start + runs[b].len]);
      used.add(a);
      used.add(b);
      break;
    }
  }
  return ranges;
}

/** Build the fenced/inline code map for a markdown document. */
export function buildMarkdownCodeMap(lines: string[]): MarkdownCodeMap {
  const fenced: boolean[] = [];
  const inline: Array<Array<[number, number]>> = [];
  let openFence: string | null = null;

  for (const line of lines) {
    const fenceMatch = /^\s{0,3}(`{3,}|~{3,})/.exec(line);
    if (openFence === null && fenceMatch) {
      openFence = fenceMatch[1][0];
      fenced.push(true); // the fence line itself counts as code
      inline.push([]);
      continue;
    }
    if (openFence !== null) {
      fenced.push(true);
      inline.push([]);
      if (fenceMatch && fenceMatch[1][0] === openFence) openFence = null;
      continue;
    }
    fenced.push(false);
    inline.push(inlineCodeRanges(line));
  }

  return { fenced, inline };
}

// ---------------------------------------------------------------------------
// Configurable deny-list
// ---------------------------------------------------------------------------

/**
 * Normalisation applied before hashing, and to every candidate token found in
 * a scanned file. Documented in the README so a user can reproduce a digest
 * with any tool: trim, then lowercase. Nothing else.
 */
export function normalizeInternalTerm(term: string): string {
  return term.trim().toLowerCase();
}

/** sha256 of the normalised term, lowercase hex. The publishable form. */
export function hashInternalTerm(term: string): string {
  return crypto.createHash("sha256").update(normalizeInternalTerm(term), "utf8").digest("hex");
}

/** A compiled deny-list entry. */
export interface DenyMatcher {
  kind: "literal" | "regex";
  literal?: string;
  regex?: RegExp;
  /**
   * True when the term itself was never published (external file). The finding
   * then reports a redacted match, so the report cannot leak what the config
   * deliberately kept out of the repository.
   */
  redact: boolean;
  /** Safe label for the finding. Never the term when `redact` is true. */
  label: string;
}

/** Everything the scan needs to evaluate the configured deny-list. */
export interface InternalDisclosureRuntime {
  /** sha256 digests from the committed config. */
  hashes: Set<string>;
  /** Compiled literal / regex matchers from the committed config and the external file. */
  matchers: DenyMatcher[];
  /** Findings raised while loading (a configured source that is not available). */
  loadFindings: Finding[];
  /** True when any deny-list source produced at least one usable entry. */
  enabled: boolean;
}

/** Environment variable holding the path to the unpublished deny-list file. */
export const INTERNAL_DISCLOSURE_ENV = "SCG_INTERNAL_DISCLOSURE_FILE";

/** An empty runtime: the built-in shape rules still run against it. */
export function emptyInternalDisclosureRuntime(): InternalDisclosureRuntime {
  return { hashes: new Set(), matchers: [], loadFindings: [], enabled: false };
}

/**
 * Compile one deny-list entry.
 *
 *   `sha256:<64 hex>`  a hashed term (accepted in the external file too)
 *   `/pattern/flags`   a regular expression
 *   anything else      a case-insensitive literal
 */
function compileDenyEntry(
  raw: string,
  redact: boolean,
  label: string,
  hashes: Set<string>,
): { matcher?: DenyMatcher; error?: string } {
  const entry = raw.trim();
  if (entry === "") return {};

  // Error messages never quote the entry: an entry from the unpublished file
  // is exactly the text that must not travel into a report.
  const hashMatch = /^sha256:([0-9a-fA-F]{64})$/.exec(entry);
  if (hashMatch) {
    hashes.add(hashMatch[1].toLowerCase());
    return {};
  }
  if (/^sha256:/i.test(entry)) {
    return { error: "not a sha256 digest (expected sha256: followed by 64 hex characters)" };
  }

  const regexMatch = /^\/(.+)\/([gimsuy]*)$/.exec(entry);
  if (regexMatch) {
    const flags = regexMatch[2].includes("i") ? regexMatch[2] : regexMatch[2] + "i";
    try {
      return {
        matcher: {
          kind: "regex",
          regex: new RegExp(regexMatch[1], flags.replace(/g/g, "")),
          redact,
          label,
        },
      };
    } catch {
      return { error: "not a valid regular expression" };
    }
  }

  if (entry.length < 3) {
    return {
      error:
        "shorter than 3 characters; a literal that short would match almost every file",
    };
  }
  return { matcher: { kind: "literal", literal: entry.toLowerCase(), redact, label } };
}

/** Transparency finding: a configured deny-list source could not be used. */
function unavailableFinding(source: string, detail: string): Finding {
  return {
    rule: "INTERNAL_DENYLIST_UNAVAILABLE",
    description: `Internal-disclosure deny-list source ${source} is configured but not available (${detail}). The deny-list rules are inactive for this scan; the built-in shape rules are unaffected.`,
    severity: "info",
    confidence: 1.0,
    category: "disclosure",
    recommendation:
      "This is expected where the unpublished pattern file is deliberately absent, for example on a shared CI runner. Provide the file (or the SCG_INTERNAL_DISCLOSURE_FILE environment variable) wherever the deny-list is meant to be enforced.",
  };
}

/**
 * Fail-closed finding: an entry in the unpublished pattern file could not be
 * compiled, so a term the project marked as internal is not being looked for.
 * Names the source and the line number, never the entry itself.
 */
function invalidEntryFinding(source: string, line: number, reason: string): Finding {
  return {
    rule: "INTERNAL_DENYLIST_INVALID_ENTRY",
    description: `Internal-disclosure deny-list entry at ${source} line ${line} cannot be compiled (${reason}). The entry is ignored, so that term is NOT being looked for.`,
    severity: "medium",
    confidence: 1.0,
    category: "disclosure",
    recommendation:
      "Fix the entry. Hashed entries are \"sha256:\" plus 64 hex characters (generate them with \"supply-chain-guard internal-hash <term>\"), regular expressions use the /pattern/flags form, and anything else is a literal of at least 3 characters.",
  };
}

/**
 * Load the deny-list from all three supported sources:
 *
 *   a) `internalDisclosure.hashedTerms` in the committed policy file (hashed,
 *      publishable, exact-token matching only)
 *   b) an unpublished file, from `internalDisclosure.externalFile` or the
 *      SCG_INTERNAL_DISCLOSURE_FILE environment variable (full patterns,
 *      matches reported redacted)
 *   c) `internalDisclosure.patterns` in the committed policy file (plaintext,
 *      for repositories that are private anyway)
 */
export function loadInternalDisclosureConfig(
  scanDir: string,
  policy: PolicyConfig | null,
  env: NodeJS.ProcessEnv = process.env,
): InternalDisclosureRuntime {
  const runtime = emptyInternalDisclosureRuntime();
  const section = policy?.internalDisclosure;

  for (const term of section?.hashedTerms ?? []) {
    const digest = term.trim().replace(/^sha256:/i, "").toLowerCase();
    if (/^[0-9a-f]{64}$/.test(digest)) runtime.hashes.add(digest);
    // Malformed digests are reported by the policy parser (POLICY_INVALID_INTERNAL_TERM).
  }

  (section?.patterns ?? []).forEach((raw, index) => {
    const { matcher } = compileDenyEntry(raw, false, `patterns[${index}]`, runtime.hashes);
    if (matcher) runtime.matchers.push(matcher);
  });

  // The env-var source is described by the variable NAME, never by its value:
  // that value is a local path, and printing it into a report would be the
  // very disclosure this feature exists to prevent. A path from the committed
  // config is already published, so it can be named.
  const externalSources: Array<{ configured: string; label: string }> = [];
  const fromEnv = env[INTERNAL_DISCLOSURE_ENV];
  if (fromEnv) externalSources.push({ configured: fromEnv, label: `$${INTERNAL_DISCLOSURE_ENV}` });
  if (section?.externalFile) {
    externalSources.push({ configured: section.externalFile, label: section.externalFile });
  }

  for (const { configured, label: source } of externalSources) {
    const resolved = path.isAbsolute(configured) ? configured : path.join(scanDir, configured);
    let content: string;
    try {
      if (!fs.existsSync(resolved)) {
        runtime.loadFindings.push(unavailableFinding(source, "file not found"));
        continue;
      }
      content = fs.readFileSync(resolved, "utf-8");
    } catch {
      runtime.loadFindings.push(unavailableFinding(source, "file could not be read"));
      continue;
    }

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].replace(/\r$/, "").trim();
      if (line === "" || line.startsWith("#")) continue;
      const { matcher, error } = compileDenyEntry(
        line,
        true,
        `${source} line ${i + 1}`,
        runtime.hashes,
      );
      if (matcher) runtime.matchers.push(matcher);
      // Fail closed: an entry that cannot be compiled is a term nobody is
      // looking for. The message names the line, never its content.
      if (error) runtime.loadFindings.push(invalidEntryFinding(source, i + 1, error));
    }
  }

  runtime.enabled = runtime.hashes.size > 0 || runtime.matchers.length > 0;
  return runtime;
}

// ---------------------------------------------------------------------------
// Hashed matching
// ---------------------------------------------------------------------------

/** Longest line the deny-list pass inspects. Beyond this a line is generated. */
const MAX_DENYLIST_LINE = 2000;

/** Upper bound on tokens hashed per line. */
const MAX_TOKENS_PER_LINE = 400;

/**
 * Candidate tokens for hashed matching.
 *
 * Hashing can only ever compare whole tokens, so the tokenizer defines exactly
 * what "a token" means, and the README states it: a maximal run of letters,
 * digits, dot, underscore and hyphen, trimmed of leading and trailing
 * punctuation, lowercased. A trailing `.git` is also offered without the
 * suffix, and two tokens separated by a single slash are offered joined, so an
 * `org/repo` inventory entry can be matched.
 */
export function candidateTokens(line: string): string[] {
  const tokens = new Set<string>();
  const found: Array<{ text: string; start: number; end: number }> = [];

  const re = /[A-Za-z0-9][A-Za-z0-9._-]*/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(line)) !== null && found.length < MAX_TOKENS_PER_LINE) {
    found.push({ text: match[0], start: match.index, end: match.index + match[0].length });
  }

  const add = (value: string): void => {
    const t = value.replace(/^[._-]+/, "").replace(/[._-]+$/, "").toLowerCase();
    if (t.length >= 2 && t.length <= 200) tokens.add(t);
  };

  for (const token of found) {
    add(token.text);
    if (/\.git$/i.test(token.text)) add(token.text.slice(0, -4));
  }

  for (let i = 0; i + 1 < found.length; i++) {
    if (line.slice(found[i].end, found[i + 1].start) !== "/") continue;
    const left = found[i].text.replace(/^[._-]+/, "").replace(/[._-]+$/, "");
    const right = found[i + 1].text.replace(/[._-]+$/, "");
    add(`${left}/${right}`);
    if (/\.git$/i.test(right)) add(`${left}/${right.slice(0, -4)}`);
  }

  return [...tokens];
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

function truncate(value: string, maxLen = 120): string {
  return value.length <= maxLen ? value : value.substring(0, maxLen) + "...";
}

/**
 * How specific a rule is about the same piece of text. A clone URL says more
 * than an endpoint, an endpoint says more than the bare host or address inside
 * it, and a single-label URL is the weakest reading of all.
 */
const RULE_SPECIFICITY: Record<string, number> = {
  INTERNAL_GIT_REMOTE: 4,
  INTERNAL_SERVICE_ENDPOINT: 3,
  INTERNAL_HOSTNAME: 2,
  INTERNAL_PRIVATE_IP: 2,
  INTERNAL_PRIVATE_IPV6: 2,
  INTERNAL_SINGLE_LABEL_URL: 1,
};

/**
 * Drop a finding when another finding on the same line covers the same text
 * with a longer or more specific reading. `https://svc.internal.example:8443/`
 * must be reported once as an internal endpoint, not three times as an
 * endpoint, a hostname and a single-label URL, and an ssh:// clone URL must not
 * also be reported as the scp-style remote hiding inside it.
 *
 * (The examples in this comment use the reserved documentation namespace on
 * purpose. An earlier draft wrote them as plausible internal names and this
 * scanner reported its own source file, which is the feature working.)
 */
function dedupeOverlaps(findings: Finding[]): Finding[] {
  const specificity = (rule: string): number => RULE_SPECIFICITY[rule] ?? 0;

  // The same value repeated on one line is one leak. (Findings carry no
  // column, and the baseline keys on rule|file|line, so repeats are not even
  // distinguishable downstream.)
  const seen = new Set<string>();
  findings = findings.filter((f) => {
    const key = `${f.rule}|${f.line}|${f.match}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return findings.filter((f, i) =>
    !findings.some((other, j) => {
      if (j === i || other.line !== f.line) return false;
      const outer = other.match ?? "";
      const inner = f.match ?? " ";
      if (!outer.includes(inner)) return false;
      return outer.length > inner.length || specificity(other.rule) > specificity(f.rule);
    }),
  );
}

/**
 * Scan one file for internal-topology disclosure.
 *
 * `runtime` carries the configured deny-list; pass
 * `emptyInternalDisclosureRuntime()` to run the built-in shape rules alone.
 */
export function scanInternalDisclosure(
  content: string,
  relativePath: string,
  runtime: InternalDisclosureRuntime = emptyInternalDisclosureRuntime(),
): Finding[] {
  const findings: Finding[] = [];
  const normalizedPath = relativePath.replace(/\\/g, "/");
  const isTestFile = TEST_FILE.test(normalizedPath);
  const isDocFile = isDocumentationFile(normalizedPath);
  const isMarkdown = MARKDOWN_FILE.test(normalizedPath);
  const isCodeFile = CODE_FILE.test(normalizedPath);
  const lines = content.split("\n");
  const codeMap = isMarkdown ? buildMarkdownCodeMap(lines) : null;

  // Extension of the basename, or "" for extension-less files such as a
  // Dockerfile (lastIndexOf on the whole path would slice from a directory dot).
  const basename = normalizedPath.slice(normalizedPath.lastIndexOf("/") + 1);
  const dotAt = basename.lastIndexOf(".");
  const fileExt = dotAt > 0 ? basename.slice(dotAt).toLowerCase() : "";

  for (const pattern of INTERNAL_DISCLOSURE_PATTERNS) {
    // Mirrors checkFilePatterns() in scanner.ts, so a PatternEntry behaves the
    // same way whichever loop consumes it.
    if (pattern.onlyExtensions && !pattern.onlyExtensions.includes(fileExt)) continue;
    if (pattern.onlyFilePattern && !pattern.onlyFilePattern.test(normalizedPath)) continue;
    if (pattern.notFilePattern && pattern.notFilePattern.test(normalizedPath)) continue;
    if (pattern.notTestFile && isTestFile) continue;
    if (isDocFile && !DOC_SURVIVING_RULES.has(pattern.rule)) continue;

    const regex = new RegExp(pattern.pattern, "gi");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = regex.exec(line)) !== null) {
        if (match[0] === "") {
          regex.lastIndex++;
          continue;
        }
        if (!isPatternMatchAccepted(pattern, match)) continue;
        if (
          pattern.rule === "INTERNAL_HOSTNAME" &&
          !isHostnameContextOk(line, match.index, isCodeFile)
        ) {
          continue;
        }
        if (codeMap && !FENCE_SURVIVING_RULES.has(pattern.rule)) {
          if (codeMap.fenced[i]) continue;
          const start = match.index;
          const end = match.index + match[0].length;
          if (codeMap.inline[i].some(([a, b]) => start >= a && end <= b)) continue;
        }
        findings.push({
          rule: pattern.rule,
          description: pattern.description,
          severity: pattern.severity,
          file: relativePath,
          line: i + 1,
          match: truncate(match[0]),
          confidence: 0.7,
          category: "disclosure",
          recommendation: getInternalDisclosureRecommendation(pattern.rule),
        });
      }
    }
  }

  const deduped = dedupeOverlaps(findings);

  if (runtime.enabled) {
    deduped.push(...scanDenyList(lines, relativePath, runtime));
  }

  return deduped;
}

/** Deny-list pass: hashed tokens first, then literal and regex matchers. */
function scanDenyList(
  lines: string[],
  relativePath: string,
  runtime: InternalDisclosureRuntime,
): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  const push = (line: number, label: string, matchText: string, redact: boolean): void => {
    const key = `${line}|${label}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({
      rule: "INTERNAL_DENYLIST_MATCH",
      description: `Configured internal term matched (${label}). The repository contains a value the project marked as internal, which is reconnaissance material once published.`,
      severity: "medium",
      file: relativePath,
      line,
      match: redact ? `[redacted internal term: ${label}]` : truncate(matchText),
      confidence: 0.9,
      category: "disclosure",
      recommendation: getInternalDisclosureRecommendation("INTERNAL_DENYLIST_MATCH"),
    });
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > MAX_DENYLIST_LINE) continue;
    const lineNo = i + 1;

    if (runtime.hashes.size > 0) {
      for (const token of candidateTokens(line)) {
        const digest = crypto.createHash("sha256").update(token, "utf8").digest("hex");
        if (runtime.hashes.has(digest)) {
          push(lineNo, `sha256:${digest.slice(0, 12)}`, "", true);
        }
      }
    }

    for (const matcher of runtime.matchers) {
      if (matcher.kind === "literal") {
        const index = line.toLowerCase().indexOf(matcher.literal ?? "");
        if (index >= 0) {
          push(lineNo, matcher.label, line.slice(index, index + (matcher.literal?.length ?? 0)), matcher.redact);
        }
      } else if (matcher.regex) {
        matcher.regex.lastIndex = 0;
        const m = matcher.regex.exec(line);
        if (m) push(lineNo, matcher.label, m[0], matcher.redact);
      }
    }
  }

  return findings;
}

/** Remediation text per rule id. */
export function getInternalDisclosureRecommendation(rule: string): string {
  const map: Record<string, string> = {
    INTERNAL_PRIVATE_IP:
      "Replace the address with a configuration value, an environment variable, or a documentation address from RFC5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Remember that git history keeps the old value.",
    INTERNAL_PRIVATE_IPV6:
      "Replace the address with a configuration value or a documentation prefix. ULA addresses describe a private addressing plan that does not belong in a public repository.",
    INTERNAL_HOSTNAME:
      "Move the hostname into configuration that is not published, or replace it with a name in the reserved documentation space (example.com, or a .example subdomain). Internal-only TLDs never resolve publicly, so a reader learns only what your network contains.",
    INTERNAL_SINGLE_LABEL_URL:
      "Confirm this is a container service alias rather than a machine on an internal network. If it names a real host, move it into unpublished configuration.",
    INTERNAL_SERVICE_ENDPOINT:
      "Move the endpoint into unpublished configuration. Host plus port tells a reader which service runs where, which is the first step of an intrusion, and it stays in git history after the file is changed.",
    INTERNAL_GIT_REMOTE:
      "Confirm this forge is meant to be public. A clone URL for a self-hosted forge discloses the forge hostname, its SSH port and internal project names; keep those in a local remote or in unpublished configuration.",
    INTERNAL_DEV_PATH:
      "Replace the absolute path with a relative path or a variable. A home-directory path discloses an account name and usually means a machine-specific value was committed by mistake.",
    INTERNAL_DENYLIST_MATCH:
      "Remove the term or move it into unpublished configuration. It matched an entry your project explicitly marked as internal.",
    INTERNAL_DENYLIST_UNAVAILABLE:
      "Provide the unpublished pattern file wherever the deny-list should be enforced, or remove the setting if it is no longer used.",
    INTERNAL_DENYLIST_INVALID_ENTRY:
      "Fix the entry in the unpublished pattern file. An entry that cannot be compiled is silently doing nothing, which looks exactly like a repository with no leaks.",
  };
  return map[rule] ?? "Review whether this value describes internal infrastructure that should not be published.";
}
