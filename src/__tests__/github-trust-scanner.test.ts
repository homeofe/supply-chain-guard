import { describe, it, expect } from "vitest";
import { parseGitHubUrl, scanReadmeLures } from "../github-trust-scanner.js";

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
