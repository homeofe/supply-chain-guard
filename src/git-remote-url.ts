/** Remove credentials and URL parameters before Git provenance enters a report. */
export function publicGitRemoteUrl(remote: string): string | undefined {
  const value = remote.trim();
  try {
    const url = new URL(value);
    if (!["https:", "http:", "ssh:", "git:"].includes(url.protocol)) return undefined;
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    // Git also accepts the scp form. Its user component is authentication,
    // not repository identity, so omit it. Refuse all other unparsed forms.
    const match = /^(?:[^@\s/:]+@)?([A-Za-z0-9.-]+):([^?#\s]+)$/.exec(value);
    return match ? `ssh://${match[1]}/${match[2]}` : undefined;
  }
}
