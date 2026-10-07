/**
 * A path segment that looks like a credential rather than a repository name:
 * userinfo-shaped (`name:secret`, `name@host`), a well-known token prefix, or a
 * token-carrying pseudo user such as `x-access-token` / `oauth2`.
 */
const CREDENTIAL_SEGMENT =
  /[:@]|^(?:gh[pousr]_|github_pat_|glpat-|glptt-|gldt-|bbdc-|ATBB|npm_|xox[abprs]-|sk-)|^(?:x-access-token|x-token-auth|oauth2|private[-_]token)$/i;

/**
 * Hosts whose repository address is exactly owner/repo. Anything after those
 * two segments is a file or API path, never repository identity. Other forges
 * (GitLab subgroups, self-hosted servers) keep their full resolved path.
 */
const OWNER_REPO_HOSTS = new Set(["github.com", "bitbucket.org"]);

/**
 * Resolve `.` and `..` (including percent-encoded dots); on owner/repo hosts
 * keep only that prefix. Returns undefined when the path cannot be trusted.
 */
function publicRepositoryPath(rawPath: string, host: string): string | undefined {
  const resolved: string[] = [];
  for (const raw of rawPath.split("/")) {
    let segment = raw;
    try {
      segment = decodeURIComponent(raw);
    } catch {
      return undefined;
    }
    if (segment.includes("/") || segment.includes("\\")) return undefined;
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      resolved.pop();
      continue;
    }
    resolved.push(segment);
  }
  if (resolved.length === 0) return undefined;
  // Check every segment, not only the ones kept: a credential anywhere in the
  // path means the remote is not a plain owner/repo address.
  if (resolved.some((segment) => CREDENTIAL_SEGMENT.test(segment))) return undefined;
  const kept = OWNER_REPO_HOSTS.has(host.toLowerCase()) ? resolved.slice(0, 2) : resolved;
  return kept.map(encodeURIComponent).join("/");
}

/** Remove credentials and URL parameters before Git provenance enters a report. */
export function publicGitRemoteUrl(remote: string): string | undefined {
  const value = remote.trim();
  try {
    const url = new URL(value);
    if (!["https:", "http:", "ssh:", "git:"].includes(url.protocol)) return undefined;
    const repoPath = publicRepositoryPath(url.pathname, url.hostname);
    if (!repoPath) return undefined;
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    url.pathname = `/${repoPath}`;
    return url.toString();
  } catch {
    // Git also accepts the scp form. Its user component is authentication,
    // not repository identity, so omit it. Refuse all other unparsed forms.
    const match = /^(?:[^@\s/:]+@)?([A-Za-z0-9.-]+):([^?#\s]+)$/.exec(value);
    if (!match) return undefined;
    const repoPath = publicRepositoryPath(match[2], match[1]);
    return repoPath ? `ssh://${match[1]}/${repoPath}` : undefined;
  }
}
