import { describe, it, expect } from "vitest";
import { parseGitHubUrl, scanReadmeLures, analyzeGitHubTrust } from "../github-trust-scanner.js";
import { KNOWN_MALICIOUS_GITHUB_ACCOUNTS } from "../ioc-blocklist.js";

describe("GitHub Trust Scanner", () => {
  describe("parseGitHubUrl", () => {
    it("should parse standard GitHub URLs", () => {
      const result = parseGitHubUrl("https://github.com/owner/repo");
      expect(result).toEqual({ owner: "owner", repo: "repo" });
    });

    it("should parse GitHub URLs with .git suffix", () => {
      const result = parseGitHubUrl("https://github.com/owner/repo.git");
      expect(result).toEqual({ owner: "owner", repo: "repo" });
    });

    it("should parse GitHub URLs with subpaths", () => {
      const result = parseGitHubUrl("https://github.com/owner/repo/tree/main");
      expect(result).toEqual({ owner: "owner", repo: "repo" });
    });

    it("should return null for non-GitHub URLs", () => {
      expect(parseGitHubUrl("https://gitlab.com/owner/repo")).toBeNull();
      expect(parseGitHubUrl("not a url")).toBeNull();
    });
  });

  describe("scanReadmeLures", () => {
    it("should detect 'leaked source' language", () => {
      const readme = "# Project\nThis contains the leaked source code of an AI tool.";
      const findings = scanReadmeLures(readme, "README.md");
      expect(findings.some((f) => f.rule === "README_LURE_LEAKED")).toBe(true);
    });

    it("should detect crack/keygen language", () => {
      const readme = "# Free Tool\nAll enterprise features unlocked! No limits!";
      const findings = scanReadmeLures(readme, "README.md");
      expect(findings.some((f) => f.rule === "README_LURE_CRACK")).toBe(true);
    });

    it("should detect urgency language", () => {
      const readme = "# Important\nDownload before it gets removed from GitHub!";
      const findings = scanReadmeLures(readme, "README.md");
      expect(findings.some((f) => f.rule === "README_LURE_URGENCY")).toBe(true);
    });

    it("should detect Claude Code lure pattern", () => {
      const readme = "# Claude Code Leaked\nRebuilt from Anthropic's leaked Claude Code source.";
      const findings = scanReadmeLures(readme, "README.md");
      expect(findings.some((f) => f.rule === "CAMPAIGN_CLAUDE_LURE")).toBe(true);
    });

    it("should detect generic AI tool lure", () => {
      const readme = "# Copilot Free\nCopilot leaked source dump with all features.";
      const findings = scanReadmeLures(readme, "README.md");
      expect(findings.some((f) => f.rule === "CAMPAIGN_AI_TOOL_LURE")).toBe(true);
    });

    it("should not flag clean README", () => {
      const readme = [
        "# My Project",
        "",
        "A supply-chain security scanner for npm and PyPI.",
        "",
        "## Installation",
        "```bash",
        "npm install my-project",
        "```",
      ].join("\n");
      const findings = scanReadmeLures(readme, "README.md");
      expect(findings).toHaveLength(0);
    });

    it("should include line numbers", () => {
      const readme = "# Normal line\n\n# This has leaked source code\n";
      const findings = scanReadmeLures(readme, "README.md");
      const f = findings.find((f) => f.rule === "README_LURE_LEAKED");
      expect(f?.line).toBe(3);
    });
  });
});

describe("github-trust-scanner input validation (injection hardening)", () => {
  it("parseGitHubUrl rejects a leading-hyphen owner or a '..' repo", () => {
    expect(parseGitHubUrl("https://github.com/--evil/repo")).toBeNull();
    expect(parseGitHubUrl("https://github.com/owner/..")).toBeNull();
  });

  it("parseGitHubUrl still accepts a valid owner/repo with dots and hyphens", () => {
    expect(parseGitHubUrl("https://github.com/ok-org/ok.repo")).toEqual({ owner: "ok-org", repo: "ok.repo" });
  });

  it("analyzeGitHubTrust returns no findings for names with shell metacharacters (no gh call)", () => {
    // A crafted owner/repo must never reach gh; the guard returns [] first.
    expect(analyzeGitHubTrust("foo; rm -rf ~", "repo")).toEqual([]);
    expect(analyzeGitHubTrust("owner", "$(id)")).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // Known malicious account blocklist
  // -------------------------------------------------------------------------

  describe("known malicious account blocklist", () => {
    // GH_OWNER deliberately rejects underscores (GitHub logins cannot contain
    // them; the regex is injection hardening for values interpolated into a
    // `gh api` path). Threat-actor handles that are not legal logins are still
    // tracked in the array for the content matcher, but cannot be reached
    // through the repo-owner path. Asserted explicitly so a future addition is
    // a deliberate act rather than a silent hole.
    const notALogin = (a: string) => !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(a);
    const reachable = KNOWN_MALICIOUS_GITHUB_ACCOUNTS.filter((a) => !notALogin(a));
    const unreachable = KNOWN_MALICIOUS_GITHUB_ACCOUNTS.filter(notALogin);

    it("has a populated blocklist", () => {
      expect(KNOWN_MALICIOUS_GITHUB_ACCOUNTS.length).toBeGreaterThan(10);
      expect(reachable.length).toBeGreaterThan(10);
    });

    it("flags EVERY blocklisted account, whatever its casing", () => {
      // The regression: the check compared a lowercased owner against the raw
      // mixed-case array, so every mixed-case entry was silently unreachable.
      for (const account of reachable) {
        const findings = analyzeGitHubTrust(account, "some-repo");
        expect(
          findings.some((f) => f.rule === "REPO_KNOWN_MALICIOUS_ACCOUNT"),
          `${account} must be flagged`,
        ).toBe(true);
      }
    });

    it("flags a blocklisted account regardless of how the caller cases it", () => {
      const account = reachable[0]!;
      for (const variant of [account.toLowerCase(), account.toUpperCase()]) {
        const findings = analyzeGitHubTrust(variant, "some-repo");
        expect(
          findings.some((f) => f.rule === "REPO_KNOWN_MALICIOUS_ACCOUNT"),
          variant,
        ).toBe(true);
      }
    });

    it("covers the mixed-case entries specifically", () => {
      const mixed = reachable.filter((a) => a !== a.toLowerCase());
      expect(mixed.length, "expected mixed-case entries to exist").toBeGreaterThan(0);
      for (const account of mixed) {
        expect(
          analyzeGitHubTrust(account, "r").some(
            (f) => f.rule === "REPO_KNOWN_MALICIOUS_ACCOUNT",
          ),
          account,
        ).toBe(true);
      }
    });

    it("documents exactly which entries are not valid GitHub logins", () => {
      // If this count changes, someone added a handle that the repo-owner path
      // cannot see. That may be fine, but it must be noticed.
      expect(unreachable).toEqual(["Mr_Rot13"]);
    });

    it("does not flag an innocent account", () => {
      expect(
        analyzeGitHubTrust("some-unremarkable-org", "repo").some(
          (f) => f.rule === "REPO_KNOWN_MALICIOUS_ACCOUNT",
        ),
      ).toBe(false);
    });
  });
});
