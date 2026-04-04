import { describe, it, expect } from "vitest";
import { INFOSTEALER_PATTERNS, LURE_PATTERNS } from "../patterns.js";

function matchPattern(pattern: string, input: string): boolean {
  return new RegExp(pattern, "i").test(input);
}

describe("Infostealer Patterns", () => {
  describe("Dead-drop resolvers", () => {
    it("should detect Steam profile dead-drop", () => {
      const p = INFOSTEALER_PATTERNS.find((p) => p.rule === "DEAD_DROP_STEAM");
      expect(p).toBeDefined();
      expect(matchPattern(p!.pattern, 'url = "https://steamcommunity.com/profiles/76561198721263282"')).toBe(true);
    });

    it("should detect Telegram dead-drop", () => {
      const p = INFOSTEALER_PATTERNS.find((p) => p.rule === "DEAD_DROP_TELEGRAM");
      expect(p).toBeDefined();
      expect(matchPattern(p!.pattern, "https://telegram.me/g1n3sss")).toBe(true);
      expect(matchPattern(p!.pattern, "https://t.me/malware_channel")).toBe(true);
    });

    it("should detect Pastebin dead-drop", () => {
      const p = INFOSTEALER_PATTERNS.find((p) => p.rule === "DEAD_DROP_PASTEBIN");
      expect(p).toBeDefined();
      expect(matchPattern(p!.pattern, "https://pastebin.com/raw/abc123")).toBe(true);
      expect(matchPattern(p!.pattern, "https://rentry.co/abc123")).toBe(true);
    });

    it("should detect DNS TXT dead-drop", () => {
      const p = INFOSTEALER_PATTERNS.find((p) => p.rule === "DEAD_DROP_DNS_TXT");
      expect(p).toBeDefined();
      expect(matchPattern(p!.pattern, "nslookup -type=TXT config.evil.com")).toBe(true);
      expect(matchPattern(p!.pattern, "dns.resolveTxt('evil.com')")).toBe(true);
    });
  });

  describe("Browser/wallet theft", () => {
    it("should detect browser credential theft", () => {
      const p = INFOSTEALER_PATTERNS.find((p) => p.rule === "VIDAR_BROWSER_THEFT");
      expect(p).toBeDefined();
      expect(matchPattern(p!.pattern, 'copy("Login Data", sqlite_path)')).toBe(true);
      expect(matchPattern(p!.pattern, 'path.join(AppData, "Local", "Google", "Chrome")')).toBe(true);
    });

    it("should detect crypto wallet theft", () => {
      const p = INFOSTEALER_PATTERNS.find((p) => p.rule === "VIDAR_WALLET_THEFT");
      expect(p).toBeDefined();
      expect(matchPattern(p!.pattern, 'read_file(Exodus_wallet_path)')).toBe(true);
      expect(matchPattern(p!.pattern, 'find("MetaMask", "vault")')).toBe(true);
      expect(matchPattern(p!.pattern, "wallet.dat")).toBe(true);
    });
  });

  describe("Proxy/backconnect", () => {
    it("should detect SOCKS5 proxy patterns", () => {
      const p = INFOSTEALER_PATTERNS.find((p) => p.rule === "GHOSTSOCKS_SOCKS5");
      expect(p).toBeDefined();
      expect(matchPattern(p!.pattern, "socks5://proxy.evil.com:1080")).toBe(true);
      expect(matchPattern(p!.pattern, "SOCKS5 handshake")).toBe(true);
    });

    it("should detect backconnect patterns", () => {
      const p = INFOSTEALER_PATTERNS.find((p) => p.rule === "PROXY_BACKCONNECT");
      expect(p).toBeDefined();
      expect(matchPattern(p!.pattern, "register as residential proxy")).toBe(true);
      expect(matchPattern(p!.pattern, "backconnect_server")).toBe(true);
    });
  });

  describe("Dropper patterns", () => {
    it("should detect temp directory execution", () => {
      const p = INFOSTEALER_PATTERNS.find((p) => p.rule === "DROPPER_TEMP_EXEC");
      expect(p).toBeDefined();
      expect(matchPattern(p!.pattern, 'writeFile(TEMP + "/payload.exe")')).toBe(true);
    });

    it("should detect anti-VM evasion", () => {
      const p = INFOSTEALER_PATTERNS.find((p) => p.rule === "DROPPER_ANTIVM");
      expect(p).toBeDefined();
      expect(matchPattern(p!.pattern, 'if (detect VMware) exit')).toBe(true);
      expect(matchPattern(p!.pattern, "IsDebuggerPresent()")).toBe(true);
    });

    it("should detect sleep evasion", () => {
      const p = INFOSTEALER_PATTERNS.find((p) => p.rule === "DROPPER_SLEEP_EVASION");
      expect(p).toBeDefined();
      expect(matchPattern(p!.pattern, "time.sleep(300000)")).toBe(true);
      expect(matchPattern(p!.pattern, "Sleep(60 * 60000)")).toBe(true);
    });
  });
});

describe("Lure Patterns", () => {
  it("should detect leaked source language", () => {
    const p = LURE_PATTERNS.find((p) => p.rule === "README_LURE_LEAKED");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "leaked source code")).toBe(true);
    expect(matchPattern(p!.pattern, "exposed source")).toBe(true);
  });

  it("should detect crack/keygen language", () => {
    const p = LURE_PATTERNS.find((p) => p.rule === "README_LURE_CRACK");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "cracked version")).toBe(true);
    expect(matchPattern(p!.pattern, "unlocked enterprise features")).toBe(true);
    expect(matchPattern(p!.pattern, "no message limits")).toBe(true);
  });

  it("should detect Claude Code specific lure", () => {
    const p = LURE_PATTERNS.find((p) => p.rule === "CAMPAIGN_CLAUDE_LURE");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "claude code leaked source")).toBe(true);
    expect(matchPattern(p!.pattern, "Anthropic Claude Code rebuilt from leaked")).toBe(true);
  });

  it("should detect generic AI tool lure", () => {
    const p = LURE_PATTERNS.find((p) => p.rule === "CAMPAIGN_AI_TOOL_LURE");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "Cursor leaked source dump")).toBe(true);
    expect(matchPattern(p!.pattern, "ChatGPT cracked")).toBe(true);
    expect(matchPattern(p!.pattern, "OpenClaw leaked")).toBe(true);
  });

  it("should detect suspicious exe naming", () => {
    const p = LURE_PATTERNS.find((p) => p.rule === "FAKE_AI_TOOL_LURE");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "ClaudeCode_x64.exe")).toBe(true);
    expect(matchPattern(p!.pattern, "Setup_amd64.msi")).toBe(true);
  });

  it("should not match normal text", () => {
    const p = LURE_PATTERNS.find((p) => p.rule === "README_LURE_LEAKED");
    expect(matchPattern(p!.pattern, "This is a normal README about a project")).toBe(false);
  });
});
