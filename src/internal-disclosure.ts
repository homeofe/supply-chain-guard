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
 *    family reports `medium` (weak signals: `low`). `high` and `critical`
 *    stay reserved for credential-shaped findings, which the existing rules
 *    already own. The default CLI gate only fails on high/critical, so
 *    upgrading to a release that carries these rules cannot turn a build red.
 *    Severity follows the VALUE, not the rule that happened to match it: a
 *    single-label host stays `low` whether the single-label-URL rule or the
 *    service-endpoint rule reported it.
 *
 * 3. FALSE POSITIVES DECIDE ADOPTION. Three layers keep it quiet:
 *      - VALUE layer: the reserved documentation space never fires. RFC5737
 *        addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), RFC2606
 *        names (example.com and friends, the `.example` TLD, `.invalid`,
 *        `.test`), loopback, placeholder or CI account names, and the
 *        WELL_KNOWN_INFRA constants below (cloud metadata, Kubernetes and
 *        Docker defaults) are all rejected before a finding exists.
 *      - LEXICAL layer: a match has to sit somewhere its rule can plausibly
 *        mean what it claims. A dotted name in program source has to be in a
 *        string, a comment or a URL; a `.local` name preceded by a path
 *        separator is a module specifier, not a host; `/Users/` is a macOS
 *        home directory and `/users/` is a REST route.
 *      - SURFACE layer: see PROSE_SILENT_RULES / EXAMPLE_SURVIVING_RULES.
 *        Files that exist to BE examples (`examples/`, `*.example.*`) narrow
 *        to the rules that stay meaningful there. Documentation prose does
 *        NOT: a private address or a developer path in a README is the exact
 *        leak this family exists to catch.
 *
 * 4. BOUNDED COST. A generated bundle is one 800 KB line, and a rule family
 *    that takes three minutes on it is a rule family that gets switched off.
 *    Line offsets are computed once per file and binary-searched, per-line
 *    lexical context is computed once per line rather than once per match,
 *    over-long lines are skipped the way the size limit skips over-large
 *    files, and match counts are capped per rule and per file. Every one of
 *    those limits reports INTERNAL_DISCLOSURE_TRUNCATED rather than going
 *    quiet, because a scanner that silently stopped looking is indistinguishable
 *    from a repository with nothing to find.
 *
 * 5. THE DENY-LIST PARADOX. A list of your internal hostnames committed to a
 *    public repository IS the leak it was meant to prevent. `hashedTerms`
 *    therefore stores only sha256 digests of normalised terms. That is worth
 *    exactly what it is worth: it stops casual reading and grep, and with
 *    SCG_INTERNAL_HASH_SALT (a salt held outside the repository) it also
 *    stops the dictionary attack that an unsalted digest of a low-entropy
 *    value invites. `externalFile` keeps full regex/plaintext patterns
 *    outside the repository, and `patterns` exists for repositories that are
 *    private anyway. Matches from the two unpublished sources are reported
 *    REDACTED.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type { Finding, PatternEntry, PolicyConfig, Severity } from "./types.js";
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

/**
 * Addresses that are the same everywhere, documented by the vendor, and
 * therefore describe nobody's topology. Reporting one of these is how the
 * family loses its credibility on the first Kubernetes or cloud repository it
 * meets. Each entry names what it is; nothing goes in here without one.
 */
const WELL_KNOWN_INFRA_ADDRESSES = new Set([
  // Cloud instance metadata service (IMDS). Identical on AWS, Azure, GCP,
  // OpenStack, Oracle and DigitalOcean; appears in every SSRF test and every
  // credential-provider implementation.
  "169.254.169.254",
  // AWS ECS task metadata / task IAM credentials endpoint.
  "169.254.170.2",
  // AWS ECS task metadata v4 (Fargate) alternate endpoint.
  "169.254.170.23",
  // Amazon Time Sync Service (NTP on link-local).
  "169.254.169.123",
  // Alibaba Cloud instance metadata service.
  "100.100.100.200",
  // Kubernetes: first address of the 10.96.0.0/12 default service CIDR, which
  // kubeadm assigns to the `kubernetes.default.svc` API service.
  "10.96.0.1",
  // Kubernetes: the kubeadm default cluster DNS (CoreDNS / kube-dns) ClusterIP.
  "10.96.0.10",
  // k3s: first address and cluster DNS of its 10.43.0.0/16 default service CIDR.
  "10.43.0.1",
  "10.43.0.10",
  // Docker: default gateway of the built-in `docker0` bridge network.
  "172.17.0.1",
  // Docker Desktop: the gateway the VM presents to containers on macOS.
  "192.168.65.1",
  "192.168.65.2",
]);

/**
 * Networks written in CIDR form that are documented defaults rather than
 * anybody's addressing plan. A network address already fails
 * isPrivateAddressLeak (its host octet is 0), so these exist for the
 * host-shaped rules and for readability of the intent.
 *
 *   10.96.0.0/12   kubeadm default service CIDR
 *   10.244.0.0/16  kubeadm / Flannel default pod CIDR
 *   10.42.0.0/16   k3s default pod CIDR
 *   10.43.0.0/16   k3s default service CIDR
 *   172.17.0.0/16  Docker default bridge network
 *   10.1.0.0/16    Docker Desktop Kubernetes default pod CIDR
 */
const WELL_KNOWN_INFRA_CIDRS = new Set([
  "10.96.0.0/12",
  "10.244.0.0/16",
  "10.42.0.0/16",
  "10.43.0.0/16",
  "172.17.0.0/16",
  "10.1.0.0/16",
]);

/**
 * Hostnames in an internal-only TLD that every Docker Desktop installation
 * has. They resolve on the developer's machine, they are in the vendor's
 * documentation, and they name nothing that belongs to the project.
 */
const WELL_KNOWN_INFRA_HOSTS = new Set([
  "host.docker.internal",
  "gateway.docker.internal",
  "kubernetes.docker.internal",
  "vm.docker.internal",
  "host.containers.internal",
  "docker.for.mac.host.internal",
  "docker.for.mac.localhost",
  "docker.for.win.host.internal",
  "docker.for.win.localhost",
]);

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

/**
 * True when the value is a documented, vendor-fixed constant: a cloud metadata
 * endpoint, a Kubernetes or Docker default. Accepts an address, an address
 * with a CIDR suffix, or a hostname.
 */
export function isWellKnownInfraValue(value: string): boolean {
  const v = value.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (WELL_KNOWN_INFRA_ADDRESSES.has(v)) return true;
  if (WELL_KNOWN_INFRA_CIDRS.has(v)) return true;
  if (WELL_KNOWN_INFRA_HOSTS.has(v)) return true;
  // `169.254.169.254/32` and friends: the suffix does not make it somebody's host.
  const slash = v.indexOf("/");
  if (slash > 0 && WELL_KNOWN_INFRA_ADDRESSES.has(v.slice(0, slash))) return true;
  return false;
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
 * Three shapes are deliberately NOT reported:
 *   - a network range (`/8`, `/16`, `/24`): that describes a subnet layout and
 *     is boilerplate in every IaC file. A `/32` is a single host and stays.
 *   - an address whose host octet is 0: that is how a range is written in
 *     prose and in configuration defaults, not a machine anybody can reach.
 *   - a documented vendor constant (WELL_KNOWN_INFRA_ADDRESSES): the cloud
 *     metadata endpoint and the Kubernetes cluster DNS are the same address in
 *     every cluster on earth and describe nobody's topology.
 */
export function isPrivateAddressLeak(value: string): boolean {
  const [addr, suffix] = value.trim().split("/");
  if (isWellKnownInfraValue(value)) return false;
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
  // `http://unix/...` and `http+unix://...` are the conventional pseudo-hosts
  // for a request over a UNIX domain socket (got, axios, dockerode, the Docker
  // Engine API). No DNS is involved and no machine is named.
  "unix", "socket", "npipe",
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
  if (isWellKnownInfraValue(h)) return false;
  if (parseIPv4(h) !== null) return classifyIPv4(h) === "private";
  if (h.includes(":")) return isUniqueLocalIPv6(h);
  if (hasInternalTld(h)) return !h.split(".").includes("example");
  if (!h.includes(".")) return !SERVICE_ALIAS_HOSTS.has(h);
  return false;
}

/**
 * True when a host has no domain part at all: a container alias, a compose or
 * Kubernetes service name, or a machine reachable only through internal DNS.
 * This is the WEAKEST reading in the family and drives severity (see
 * severityForHost): whichever rule reports it, a dotless host stays `low`.
 */
export function isSingleLabelHost(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (h === "" || h.includes(".") || h.includes(":")) return false;
  return parseIPv4(h) === null;
}

/**
 * Severity for a host-shaped finding. It follows the SHAPE OF THE HOST, never
 * the rule that happened to match first: a dotless `payments` host with a
 * port is the same weak signal as one without, and before this the endpoint rule
 * quietly promoted every compose and Kubernetes service name to medium.
 */
export function severityForHost(host: string, ruleDefault: Severity): Severity {
  return isSingleLabelHost(host) ? "low" : ruleDefault;
}

/** Value guard for INTERNAL_HOSTNAME. */
export function isInternalHostname(value: string): boolean {
  const h = value.trim().toLowerCase().replace(/\.$/, "");
  if (!hasInternalTld(h)) return false;
  if (isReservedDocHost(h)) return false;
  if (isWellKnownInfraValue(h)) return false;
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
  if (isWellKnownInfraValue(h)) return false;
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
// Lexical guards (the second false-positive layer)
// ---------------------------------------------------------------------------

/**
 * Characters that introduce a route or template PARAMETER rather than a path
 * segment: `:id` (Express, Rails), `{id}` (OpenAPI, Spring), `<id>` (Flask,
 * Django), `${user}`, `%USERNAME%`, `*` (glob).
 */
const PARAMETER_LEAD = /[:{<$%*]/;

/**
 * Decide whether a `/home/<name>/` or `C:\Users\<name>\` match is really a
 * filesystem path.
 *
 * The dominant false positive was a REST route: `/users/:id`, `/users/{id}`
 * and `app.get("/users/profile/edit")` all used to be read as macOS home
 * directories, because the rule was compiled case-insensitively. The macOS
 * directory is `/Users` with a capital U and a route is `/users`, so the
 * regex is now case-sensitive, which removes the whole class. This guard is
 * the second half: whatever follows the account segment must look like the
 * next path component and not like a route or template parameter.
 */
export function isDevPathContextOk(content: string, matchEnd: number): boolean {
  const next = content.slice(matchEnd, matchEnd + 1);
  if (next !== "" && PARAMETER_LEAD.test(next)) return false;
  return true;
}

/**
 * Decide whether a bare hostname match is in a position where a HOST can be.
 *
 * A name ending in an internal-only TLD is a host when it is written as one
 * and a FILE when it is written as a path: `./config.local`, `src/config.local`
 * and `../lib/settings.local` are module specifiers, not machines. The
 * discriminator is the character in front of the name: a path separator means
 * a file, unless the separator is part of `://` (a URL) or follows `@` (a user
 * prefix), in which case it is exactly a host.
 *
 * A following file extension is already excluded by the pattern itself (the
 * trailing `(?!\.[a-z0-9])`), which is why `settings.local.json` and
 * `vite.config.local.ts` never reach this function.
 *
 * A following `(` is a method call, not a host. That one matters outside
 * program sources, where the string/comment discipline of isHostnameContextOk
 * does not apply: a changelog line reading "Added `res.local(name, val)`" was
 * being reported as a machine on a private network.
 */
export function isHostnameLexicalContextOk(
  content: string,
  matchStart: number,
  matchEnd?: number,
): boolean {
  if (matchEnd !== undefined && content[matchEnd] === "(") return false;
  if (matchStart === 0) return true;
  const prev = content[matchStart - 1];
  if (prev !== "/" && prev !== "\\") return true;
  // `https://db.example.corp/`, `git@forge.internal.example:...`, `//forge.example.corp/x`.
  const before = content.slice(Math.max(0, matchStart - 3), matchStart);
  return before.endsWith("://") || before.endsWith("//") || before.endsWith("@/");
}

// ---------------------------------------------------------------------------
// Built-in shape rules
// ---------------------------------------------------------------------------

/**
 * Machine output rather than authored content: minified bundles, source maps
 * and the single-line bundles a build step emits. The content-based guard
 * (MAX_LINE_LENGTH) catches the rest, whatever the file happens to be called.
 */
const MINIFIED_OR_MAP = /(?:\.min\.(?:js|mjs|cjs|css)|[.-]bundle\.(?:js|mjs|cjs)|\.map)$/i;

/**
 * A built-in rule. Extends the shared PatternEntry with the three things this
 * family needs and no other pattern list does.
 */
export interface InternalPatternEntry extends PatternEntry {
  /**
   * Compile the pattern case-SENSITIVELY. Only `/Users/` needs it, and it
   * needs it badly: `/users/` is a REST route.
   */
  caseSensitive?: boolean;
  /** Severity derived from the matched value (see severityForHost). */
  severityFor?: (match: RegExpExecArray) => Severity;
  /** Guard on the text AROUND the match, not the match itself. */
  contextFilter?: (content: string, match: RegExpExecArray) => boolean;
}

/**
 * The built-in rule family. Every entry is pure shape plus a value guard, so
 * it is useful on a repository whose owner has configured nothing at all.
 */
export const INTERNAL_DISCLOSURE_PATTERNS: InternalPatternEntry[] = [
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
    contextFilter: (content, match) =>
      isHostnameLexicalContextOk(content, match.index, match.index + match[0].length),
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
    // A compose or Kubernetes service name with a port is still just a service
    // name: the port does not make a dotless `payments` host a stronger
    // signal than the same host without one.
    severityFor: (match) => severityForHost(match[1] ?? "", "medium"),
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
    severityFor: (match) => severityForHost(match[1] ?? "", "medium"),
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
    severityFor: (match) => severityForHost(match[1] ?? "", "medium"),
    notFilePattern: MINIFIED_OR_MAP,
    notTestFile: true,
  },
  {
    name: "internal-dev-path-windows",
    // `[Uu]sers` rather than a case-insensitive compile: a Windows path is
    // unambiguous because of the drive letter, so both spellings are accepted,
    // but the ACCOUNT name keeps its case so the value guard sees what was
    // actually written.
    pattern: "[A-Za-z]:[\\\\/]{1,2}[Uu]sers[\\\\/]{1,2}([A-Za-z0-9 ._-]{2,64})[\\\\/]",
    description:
      "Developer filesystem path committed to the repository. A home-directory path discloses an account name and the local layout of a workstation, and usually means a machine-specific value was committed by accident.",
    severity: "medium",
    rule: "INTERNAL_DEV_PATH",
    valueGroup: 1,
    valueFilter: isPersonalAccountName,
    contextFilter: (content, match) => isDevPathContextOk(content, match.index + match[0].length),
    caseSensitive: true,
    notFilePattern: MINIFIED_OR_MAP,
    notTestFile: true,
  },
  {
    name: "internal-dev-path-unix",
    // CASE-SENSITIVE, and that is the whole point. `/Users/` is the macOS home
    // directory; `/users/` is a REST route, and matching it case-insensitively
    // produced the most embarrassing false positive this family had
    // (`app.get("/users/profile/edit")` reported as a developer path).
    pattern: "(?<![\\w.-])/(?:home|Users)/([A-Za-z0-9._-]{2,64})/",
    description:
      "Developer filesystem path committed to the repository. A home-directory path discloses an account name and the local layout of a workstation, and usually means a machine-specific value was committed by accident.",
    severity: "medium",
    rule: "INTERNAL_DEV_PATH",
    valueGroup: 1,
    valueFilter: isPersonalAccountName,
    contextFilter: (content, match) => isDevPathContextOk(content, match.index + match[0].length),
    caseSensitive: true,
    notFilePattern: MINIFIED_OR_MAP,
    notTestFile: true,
  },
];

// ---------------------------------------------------------------------------
// Surface layer (which rules stay armed in which kind of file)
// ---------------------------------------------------------------------------

/** Prose files. Documentation describes systems, and sometimes names them. */
const DOC_FILE = /\.(?:md|markdown|mdx|rst|txt|adoc)$/i;

/** Trees that hold documentation about the project. */
const DOC_DIR = /(?:^|\/)(?:docs?|documentation|man|manual)\//i;

/** Trees whose whole purpose is to show a shape rather than a system. */
const EXAMPLE_DIR = /(?:^|\/)(?:examples?|samples?|fixtures?|testdata|test-data)\//i;

/** Template artifacts: `config.example.yml`, `.env.example`, `values.sample.yaml`. */
const EXAMPLE_ARTIFACT = /(?:^|[./])(?:example|sample|template|tpl)(?:\.[^/]*)?$/i;

/** Markdown-family files, where fenced blocks exist. */
const MARKDOWN_FILE = /\.(?:md|markdown|mdx)$/i;

/**
 * Programming-language sources, where a dotted name is far more likely to be a
 * property access (an object with a field named `internal` or `local`) than a
 * host. See isHostnameContextOk().
 */
const CODE_FILE = /\.(?:[cm]?[jt]sx?|py|rb|rs|go|java|kt|php|cs|swift|scala|dart|c|h|cpp|hpp)$/i;

/** C-family sources, where `#` is not a comment. */
const C_FAMILY_FILE = /\.(?:[cm]?[jt]sx?|java|kt|cs|swift|scala|dart|go|rs|c|h|cpp|hpp|php)$/i;

/**
 * Test / spec / fixture files.
 *
 * The leading `(?:^|/)` alternative is load-bearing and its absence was a real
 * bug: the previous `/tests?/` required a LEADING SLASH, so a top-level
 * `test/` or `tests/` directory - the dominant JavaScript layout - never
 * matched, and 28 of 35 findings on a four-repository sample came from test
 * directories that were supposed to be excluded.
 *
 * `spec/` is deliberately NOT in the directory list. It is the conventional
 * OpenAPI and AsyncAPI location as often as it is an RSpec one, and a
 * `servers[].url` in an API spec is exactly the endpoint-plus-port shape this
 * family exists to catch. RSpec files are still excluded by the `_spec.` suffix
 * alternative below, which is the part that actually identifies a test.
 */
const TEST_FILE =
  /(?:^|\/)(?:tests?|__tests__|__fixtures__|__mocks__|__snapshots__|e2e|integration-tests?|fixtures?|testdata|test-data)\/|[._-](?:test|spec|mock|fixture|stub|fake)\.|(?:^|\/)conftest\.py$/i;

/** What kind of surface a file is, which decides which rules stay armed. */
export type FileSurface = "source" | "prose" | "example";

/**
 * Rules that go quiet in documentation PROSE.
 *
 * Only the weakest one. Everything else stays armed, and that is a deliberate
 * reversal: excluding private addresses and developer paths from markdown
 * silenced precisely the case this family exists for (a README that names the
 * staging box and the path it was built from). The reserved documentation
 * space - RFC5737, RFC2606, loopback - is what keeps a writer following the
 * RFCs from ever seeing a finding, and it works on any surface. A single-label
 * URL is the one rule with no such backstop: a bare `myapp` host in a quickstart is
 * noise, not a leak.
 */
const PROSE_SILENT_RULES = new Set(["INTERNAL_SINGLE_LABEL_URL"]);

/**
 * Rules that keep firing in a file that exists to BE an example: `examples/`,
 * `fixtures/`, `config.example.yml`. An address or a path there is a shape
 * being demonstrated. A hostname, a clone URL and a service endpoint are not:
 * an `.env.example` that kept the real staging host is one of the most common
 * ways this leaks.
 */
const EXAMPLE_SURVIVING_RULES = new Set([
  "INTERNAL_HOSTNAME",
  "INTERNAL_GIT_REMOTE",
  "INTERNAL_SERVICE_ENDPOINT",
]);

/**
 * The example-prone rules, and the two markdown constructs where they stay
 * silent because measurement says they are noise there:
 *
 *   - an INLINE CODE SPAN. A span is a short literal quoted inside a sentence
 *     ("`app.set('trust proxy', '192.0.2.10')` trusts a single IP"). On the
 *     four-repository sample used to tune this family, inline spans produced
 *     eight findings and every one of them was an API signature or a
 *     documented example - no leak at all.
 *   - a fenced block tagged as placeholder text (```text, ```plaintext).
 *
 * Everything else in a markdown file reports, fenced blocks included, and that
 * is where the leaks actually are: the same sample turned up a real developer
 * home directory inside a ```js block holding a pasted stack trace, which the
 * previous wholesale exclusion of documentation never saw.
 */
const ILLUSTRATIVE_FENCE_LANGS = new Set(["text", "plaintext", "plain", "txt", "placeholder"]);
const MARKDOWN_LITERAL_SILENT_RULES = new Set([
  "INTERNAL_PRIVATE_IP",
  "INTERNAL_PRIVATE_IPV6",
  "INTERNAL_DEV_PATH",
]);

/** Classify a file into the surface that decides its rule set. */
export function classifyFileSurface(relativePath: string): FileSurface {
  const p = relativePath.replace(/\\/g, "/");
  const base = p.slice(p.lastIndexOf("/") + 1);
  // An example wins over prose: `docs/config.example.yml` is an example.
  if (EXAMPLE_DIR.test(p) || EXAMPLE_ARTIFACT.test(base)) return "example";
  if (DOC_FILE.test(base) || DOC_DIR.test(p)) return "prose";
  return "source";
}

/**
 * True when the file is a documentation or example surface of any kind.
 * Retained for callers that only need the coarse answer.
 */
export function isDocumentationFile(relativePath: string): boolean {
  return classifyFileSurface(relativePath) !== "source";
}

/** True when `rule` is allowed to report on `surface`. */
export function isRuleArmedOnSurface(rule: string, surface: FileSurface): boolean {
  if (surface === "example") return EXAMPLE_SURVIVING_RULES.has(rule);
  if (surface === "prose") return !PROSE_SILENT_RULES.has(rule);
  return true;
}

// ---------------------------------------------------------------------------
// Line index and per-line lexical context (the bounded-cost layer)
// ---------------------------------------------------------------------------

/**
 * Longest line the scan inspects. Beyond this a line is generated: a minified
 * bundle, an embedded data blob, a base64 asset. The existing scanners skip an
 * over-large FILE the same way (MAX_FILE_SIZE / FILE_TOO_LARGE_SKIPPED) and,
 * like them, this never goes silent: INTERNAL_DISCLOSURE_TRUNCATED records the
 * gap.
 */
export const MAX_LINE_LENGTH = 2000;

/** Upper bound on findings from one rule in one file. */
export const MAX_FINDINGS_PER_RULE = 25;

/** Upper bound on findings from the whole family in one file. */
export const MAX_FINDINGS_PER_FILE = 100;

/**
 * Upper bound on regex matches one rule inspects in one file. Guards the case
 * where nearly every match is rejected by a value guard, which produces no
 * findings at all and so is not bounded by the two limits above.
 */
export const MAX_MATCH_ATTEMPTS_PER_RULE = 20000;

/** Longest line the deny-list pass inspects. */
const MAX_DENYLIST_LINE = MAX_LINE_LENGTH;

/** Upper bound on tokens hashed per line. */
const MAX_TOKENS_PER_LINE = 400;

/** Severity ordering used when the per-file cap has to drop findings. */
const INTERNAL_SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/**
 * Byte offset of the first character of every line, so a match index found by
 * a single whole-file regex pass can be turned into a line number by binary
 * search instead of by rescanning the file. Built once per file.
 */
interface LineIndex {
  /** Line texts, index 0 = line 1. */
  lines: string[];
  /** Absolute offset of the first character of each line. */
  starts: number[];
}

/** Split a file into lines and record where each one begins. */
export function buildLineIndex(content: string): LineIndex {
  const lines = content.split("\n");
  const starts = new Array<number>(lines.length);
  let offset = 0;
  for (let i = 0; i < lines.length; i++) {
    starts[i] = offset;
    offset += lines[i].length + 1; // + the "\n" that split() removed
  }
  return { lines, starts };
}

/** Zero-based line number containing `offset`. Binary search, O(log n). */
export function lineAtOffset(index: LineIndex, offset: number): number {
  const { starts } = index;
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

/**
 * Everything about a line that a match on it needs to know, computed ONCE for
 * the line rather than once per match. Recomputing this per match is what made
 * an 810 KB single-line bundle take three quarters of a minute per rule: every
 * match rescanned the whole line for quotes and comment markers.
 */
interface LineContext {
  /** Column ranges of quoted string literals, ascending and non-overlapping. */
  quoted: Array<[number, number]>;
  /** Column where a line comment starts, or -1. */
  commentAt: number;
  /** True when the line is a block-comment continuation (" * text"). */
  blockComment: boolean;
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

/** True when `column` falls inside one of the (sorted) ranges. Binary search. */
export function rangesContain(ranges: Array<[number, number]>, column: number): boolean {
  let lo = 0;
  let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (column < ranges[mid][0]) hi = mid - 1;
    else if (column >= ranges[mid][1]) lo = mid + 1;
    else return true;
  }
  return false;
}

/**
 * Column where a line comment begins, or -1.
 *
 * `//` is only a comment when it is not the `//` of a URL scheme, which the
 * previous version missed: any line containing `https://` treated everything
 * after it as a comment, so every dotted property access to the right of a URL
 * on that line was accepted as a hostname.
 */
export function lineCommentStart(line: string, hashIsComment: boolean): number {
  let best = -1;
  const consider = (at: number): void => {
    if (at >= 0 && (best === -1 || at < best)) best = at;
  };

  for (let i = line.indexOf("//"); i >= 0; i = line.indexOf("//", i + 1)) {
    if (i > 0 && line[i - 1] === ":") continue; // "https://"
    consider(i);
    break;
  }
  consider(line.indexOf("/*"));
  if (hashIsComment) consider(line.indexOf("#"));
  return best;
}

/** Build the lexical context of one line. */
function buildLineContext(line: string, hashIsComment: boolean): LineContext {
  return {
    quoted: quotedRanges(line),
    commentAt: lineCommentStart(line, hashIsComment),
    blockComment: /^\s*\*/.test(line),
  };
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
  hashIsComment = true,
): boolean {
  if (!isCodeFile) return true;
  return isHostnameContextOkCached(line, index, buildLineContext(line, hashIsComment));
}

/** isHostnameContextOk against a context that was computed once for the line. */
function isHostnameContextOkCached(line: string, index: number, ctx: LineContext): boolean {
  if (rangesContain(ctx.quoted, index)) return true;

  const before = line.slice(Math.max(0, index - 3), index);
  if (before.endsWith("://") || before.endsWith("@")) return true;

  if (ctx.commentAt >= 0 && index > ctx.commentAt) return true;
  return ctx.blockComment;
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

/** Per-line markdown code state: illustrative fences and inline code spans. */
interface MarkdownCodeMap {
  /** True when the line is inside (or is) a fenced code block. */
  fenced: boolean[];
  /** True when that fence is tagged as placeholder text (```text, ```plaintext). */
  illustrative: boolean[];
  /** Column ranges of inline code spans, for lines outside a fence. */
  inline: Array<Array<[number, number]>>;
}

/** Build the fenced-block and inline-span map for a markdown document. */
export function buildMarkdownCodeMap(lines: string[]): MarkdownCodeMap {
  const fenced: boolean[] = [];
  const illustrative: boolean[] = [];
  const inline: Array<Array<[number, number]>> = [];
  let openFence: string | null = null;
  let openIllustrative = false;

  for (const line of lines) {
    const fenceMatch = /^\s{0,3}(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)/.exec(line);
    if (openFence === null && fenceMatch) {
      openFence = fenceMatch[1][0];
      openIllustrative = ILLUSTRATIVE_FENCE_LANGS.has((fenceMatch[2] ?? "").toLowerCase());
      fenced.push(true); // the fence line itself counts as code
      illustrative.push(openIllustrative);
      inline.push([]);
      continue;
    }
    if (openFence !== null) {
      fenced.push(true);
      illustrative.push(openIllustrative);
      inline.push([]);
      if (fenceMatch && fenceMatch[1][0] === openFence) {
        openFence = null;
        openIllustrative = false;
      }
      continue;
    }
    fenced.push(false);
    illustrative.push(false);
    inline.push(line.includes("`") ? inlineCodeRanges(line) : []);
  }

  return { fenced, illustrative, inline };
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

/** Environment variable holding an optional salt for the hashed deny-list. */
export const INTERNAL_HASH_SALT_ENV = "SCG_INTERNAL_HASH_SALT";

/**
 * sha256 of the normalised term, lowercase hex. The publishable form.
 *
 * With a salt the input is `<salt>\n<normalised term>`. The salt lives OUTSIDE
 * the repository (SCG_INTERNAL_HASH_SALT), which is the only thing that makes
 * a digest of a low-entropy value such as a hostname resistant to being
 * guessed: an unsalted digest can simply be recomputed for every candidate
 * name a reader can think of. A salt stored next to the digests would buy
 * nothing, so this deliberately has no config-file form.
 */
export function hashInternalTerm(term: string, salt?: string | null): string {
  const normalized = normalizeInternalTerm(term);
  const input = salt ? `${salt}\n${normalized}` : normalized;
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
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
  /** Salt applied to hashed terms, or null when the digests are unsalted. */
  salt: string | null;
}

/** Environment variable holding the path to the unpublished deny-list file. */
export const INTERNAL_DISCLOSURE_ENV = "SCG_INTERNAL_DISCLOSURE_FILE";

/** An empty runtime: the built-in shape rules still run against it. */
export function emptyInternalDisclosureRuntime(): InternalDisclosureRuntime {
  return { hashes: new Set(), matchers: [], loadFindings: [], enabled: false, salt: null };
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

  const salt = env[INTERNAL_HASH_SALT_ENV];
  runtime.salt = salt ? salt : null;

  for (const term of section?.hashedTerms ?? []) {
    const digest = term.trim().replace(/^sha256:/i, "").toLowerCase();
    if (/^[0-9a-f]{64}$/.test(digest)) runtime.hashes.add(digest);
    // Malformed digests are reported by the policy parser (POLICY_INVALID_INTERNAL_TERM).
  }

  // Fail visible, never silent: digests generated with a salt match nothing
  // without it, and "nothing matched" is exactly what a clean repository looks
  // like. `hashSalted: true` is the project stating that its digests are
  // salted, so the missing salt can be reported instead of assumed.
  if (section?.hashSalted && runtime.salt === null) {
    runtime.loadFindings.push(
      unavailableFinding(
        `$${INTERNAL_HASH_SALT_ENV}`,
        "hashSalted is set but the environment variable is not, so no hashed term can match",
      ),
    );
    runtime.hashes.clear();
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
export function candidateTokens(line: string, meta?: { truncated: boolean }): string[] {
  const tokens = new Set<string>();
  const found: Array<{ text: string; start: number; end: number }> = [];

  const re = /[A-Za-z0-9][A-Za-z0-9._-]*/g;
  let match: RegExpExecArray | null;
  // The cap is tested FIRST so that hitting it leaves `re.lastIndex` parked
  // after the last token read. A failed `exec` resets `lastIndex` to 0, so
  // probing after a null-terminated loop would rediscover the first token and
  // report a truncation that never happened.
  while (found.length < MAX_TOKENS_PER_LINE && (match = re.exec(line)) !== null) {
    found.push({ text: match[0], start: match.index, end: match.index + match[0].length });
  }
  // Signal a cut-off line so the caller can report it. Without this the
  // deny-list pass would go quiet past token 400 on a line short enough to
  // clear MAX_LINE_LENGTH, which is the one way this family can miss a
  // configured term without saying so.
  if (meta && found.length === MAX_TOKENS_PER_LINE && re.exec(line) !== null) {
    meta.truncated = true;
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
 * Findings are grouped by line first. The comparison is quadratic within a
 * group and the previous version ran it across the whole file, which on a
 * generated bundle - where every finding shares line 1 - is the difference
 * between a scan and a hang.
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
  const unique = findings.filter((f) => {
    const key = `${f.rule}|${f.line}|${f.match}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const byLine = new Map<number, Finding[]>();
  for (const f of unique) {
    const line = f.line ?? -1;
    const bucket = byLine.get(line);
    if (bucket) bucket.push(f);
    else byLine.set(line, [f]);
  }

  return unique.filter((f) => {
    const group = byLine.get(f.line ?? -1) ?? [];
    return !group.some((other) => {
      if (other === f) return false;
      const outer = other.match ?? "";
      const inner = f.match ?? " ";
      if (!outer.includes(inner)) return false;
      return outer.length > inner.length || specificity(other.rule) > specificity(f.rule);
    });
  });
}

/** Transparency finding: a limit stopped the scan of this file short. */
function truncatedFinding(relativePath: string, reasons: string[]): Finding {
  return {
    rule: "INTERNAL_DISCLOSURE_TRUNCATED",
    description: `Internal-disclosure scanning of this file was cut short (${reasons.join("; ")}). Some of the file was NOT examined by the INTERNAL_* rules.`,
    severity: "info",
    confidence: 1.0,
    category: "info",
    file: relativePath,
    recommendation:
      "Generated output (a bundle, a source map, an embedded data blob) is the usual cause and needs no action. If this is authored content, review it manually or split the over-long lines; the limits exist so one machine-generated file cannot dominate a scan.",
  };
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
  const surface = classifyFileSurface(normalizedPath);
  const isMarkdown = MARKDOWN_FILE.test(normalizedPath);
  const isCodeFile = CODE_FILE.test(normalizedPath);
  const hashIsComment = !C_FAMILY_FILE.test(normalizedPath);

  const index = buildLineIndex(content);
  const { lines, starts } = index;
  const codeMap = isMarkdown ? buildMarkdownCodeMap(lines) : null;

  // Computed on demand, once per line, and reused by every match on it.
  const contexts = new Array<LineContext | undefined>(lines.length);
  const contextFor = (lineNo: number): LineContext => {
    let ctx = contexts[lineNo];
    if (!ctx) {
      ctx = buildLineContext(lines[lineNo], hashIsComment);
      contexts[lineNo] = ctx;
    }
    return ctx;
  };

  const truncationReasons = new Set<string>();

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
    if (!isRuleArmedOnSurface(pattern.rule, surface)) continue;

    const regex = new RegExp(pattern.pattern, pattern.caseSensitive ? "g" : "gi");
    let attempts = 0;
    let kept = 0;
    let match: RegExpExecArray | null;

    // ONE pass over the whole file per rule. No built-in pattern can match
    // across a newline (none of the character classes admit one), so this is
    // equivalent to the per-line loop it replaces and avoids restarting the
    // regex engine once per line.
    while ((match = regex.exec(content)) !== null) {
      if (match[0] === "") {
        regex.lastIndex++;
        continue;
      }
      if (++attempts > MAX_MATCH_ATTEMPTS_PER_RULE) {
        truncationReasons.add(
          `${pattern.rule} stopped after ${MAX_MATCH_ATTEMPTS_PER_RULE} candidate matches`,
        );
        break;
      }

      // The VALUE guard runs first because it is O(1) and settles most
      // candidates: an SVG path coordinate (`1.16.68.344`) has the shape of an
      // address and is not one, and a file full of those should not be
      // reported as a coverage gap below.
      if (!isPatternMatchAccepted(pattern, match)) continue;

      const lineNo = lineAtOffset(index, match.index);
      const line = lines[lineNo];

      // Over-long line: generated content. Skip the REST OF THE LINE in one
      // step rather than walking every match on it, which is what makes an
      // 800 KB single-line bundle cost one regex probe instead of minutes.
      if (line.length > MAX_LINE_LENGTH) {
        truncationReasons.add(
          `line ${lineNo + 1} is longer than ${MAX_LINE_LENGTH} characters`,
        );
        regex.lastIndex = starts[lineNo] + line.length;
        continue;
      }

      if (pattern.contextFilter && !pattern.contextFilter(content, match)) continue;

      const column = match.index - starts[lineNo];
      if (
        pattern.rule === "INTERNAL_HOSTNAME" &&
        isCodeFile &&
        !isHostnameContextOkCached(line, column, contextFor(lineNo))
      ) {
        continue;
      }
      if (codeMap && MARKDOWN_LITERAL_SILENT_RULES.has(pattern.rule)) {
        if (codeMap.illustrative[lineNo]) continue;
        const end = column + match[0].length;
        if (codeMap.inline[lineNo].some(([a, b]) => column >= a && end <= b)) continue;
      }

      if (kept >= MAX_FINDINGS_PER_RULE) {
        truncationReasons.add(
          `${pattern.rule} reached the ${MAX_FINDINGS_PER_RULE}-finding limit for one file`,
        );
        break;
      }
      kept++;

      findings.push({
        rule: pattern.rule,
        description: pattern.description,
        severity: pattern.severityFor?.(match) ?? pattern.severity,
        file: relativePath,
        line: lineNo + 1,
        match: truncate(match[0]),
        confidence: 0.7,
        category: "disclosure",
        recommendation: getInternalDisclosureRecommendation(pattern.rule),
      });
    }
  }

  let result = dedupeOverlaps(findings);

  if (runtime.enabled) {
    result.push(...scanDenyList(lines, relativePath, runtime, truncationReasons));
  }

  if (result.length > MAX_FINDINGS_PER_FILE) {
    truncationReasons.add(
      `the file produced more than ${MAX_FINDINGS_PER_FILE} findings`,
    );
    // Keep the most severe findings rather than whichever rules happen to sit
    // early in INTERNAL_DISCLOSURE_PATTERNS, and reserve the last slot for the
    // notice below so a capped file reports exactly MAX_FINDINGS_PER_FILE.
    result = result
      .map((finding, index) => ({ finding, index }))
      .sort(
        (a, b) =>
          INTERNAL_SEVERITY_RANK[b.finding.severity] -
            INTERNAL_SEVERITY_RANK[a.finding.severity] || a.index - b.index,
      )
      .slice(0, MAX_FINDINGS_PER_FILE - 1)
      .sort((a, b) => a.index - b.index)
      .map((entry) => entry.finding);
  }

  if (truncationReasons.size > 0) {
    result.push(truncatedFinding(relativePath, [...truncationReasons].slice(0, 3)));
  }

  return result;
}

/** Deny-list pass: hashed tokens first, then literal and regex matchers. */
function scanDenyList(
  lines: string[],
  relativePath: string,
  runtime: InternalDisclosureRuntime,
  truncationReasons: Set<string>,
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
    if (findings.length >= MAX_FINDINGS_PER_RULE) {
      truncationReasons.add(
        `INTERNAL_DENYLIST_MATCH reached the ${MAX_FINDINGS_PER_RULE}-finding limit for one file`,
      );
      break;
    }
    const line = lines[i];
    if (line.length > MAX_DENYLIST_LINE) {
      truncationReasons.add(`line ${i + 1} is longer than ${MAX_DENYLIST_LINE} characters`);
      continue;
    }
    const lineNo = i + 1;

    if (runtime.hashes.size > 0) {
      const tokenMeta = { truncated: false };
      for (const token of candidateTokens(line, tokenMeta)) {
        const digest = hashInternalTerm(token, runtime.salt);
        if (runtime.hashes.has(digest)) {
          push(lineNo, `sha256:${digest.slice(0, 12)}`, "", true);
        }
      }
      if (tokenMeta.truncated) {
        truncationReasons.add(
          `line ${lineNo} holds more than ${MAX_TOKENS_PER_LINE} deny-list candidate tokens`,
        );
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
    INTERNAL_DISCLOSURE_TRUNCATED:
      "Generated output is the usual cause and needs no action. If this is authored content, review it manually: the INTERNAL_* rules did not examine all of it.",
  };
  return map[rule] ?? "Review whether this value describes internal infrastructure that should not be published.";
}
