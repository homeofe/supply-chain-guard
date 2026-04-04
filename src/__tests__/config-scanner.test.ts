import { describe, it, expect } from "vitest";
import { scanConfigFile, isConfigFile, CONFIG_PATTERNS } from "../config-scanner.js";

describe("Config Scanner", () => {
  it("should identify config file names", () => {
    expect(isConfigFile(".npmrc")).toBe(true);
    expect(isConfigFile(".yarnrc")).toBe(true);
    expect(isConfigFile(".yarnrc.yml")).toBe(true);
    expect(isConfigFile(".pnpmrc")).toBe(true);
    expect(isConfigFile("pip.conf")).toBe(true);
    expect(isConfigFile(".pypirc")).toBe(true);
    expect(isConfigFile("package.json")).toBe(false);
    expect(isConfigFile("tsconfig.json")).toBe(false);
  });

  it("should detect HTTP registry in .npmrc", () => {
    const content = "registry=http://evil-registry.com";
    const findings = scanConfigFile(content, ".npmrc");
    expect(findings.some((f) => f.rule === "CONFIG_HTTP_REGISTRY")).toBe(true);
    expect(findings.find((f) => f.rule === "CONFIG_HTTP_REGISTRY")?.severity).toBe("critical");
  });

  it("should detect custom (non-default) registry", () => {
    const content = "registry=https://custom-registry.company.com";
    const findings = scanConfigFile(content, ".npmrc");
    expect(findings.some((f) => f.rule === "CONFIG_CUSTOM_REGISTRY")).toBe(true);
  });

  it("should not flag default npm registry", () => {
    const content = "registry=https://registry.npmjs.org/";
    const findings = scanConfigFile(content, ".npmrc");
    expect(findings.some((f) => f.rule === "CONFIG_CUSTOM_REGISTRY")).toBe(false);
  });

  it("should detect exposed auth tokens", () => {
    const content = "//registry.npmjs.org/:_authToken=npm_ABCDEF1234567890";
    const findings = scanConfigFile(content, ".npmrc");
    expect(findings.some((f) => f.rule === "CONFIG_AUTH_TOKEN_EXPOSED")).toBe(true);
  });

  it("should detect unsafe-perm=true", () => {
    const content = "unsafe-perm=true";
    const findings = scanConfigFile(content, ".npmrc");
    expect(findings.some((f) => f.rule === "CONFIG_UNSAFE_PERM")).toBe(true);
  });

  it("should detect pip extra-index-url", () => {
    const content = "extra-index-url = https://evil-pypi.example.com/simple/";
    const findings = scanConfigFile(content, "pip.conf");
    expect(findings.some((f) => f.rule === "CONFIG_EXTRA_INDEX")).toBe(true);
  });

  it("should detect pip trusted-host", () => {
    const content = "trusted-host = evil-pypi.example.com";
    const findings = scanConfigFile(content, "pip.conf");
    expect(findings.some((f) => f.rule === "CONFIG_TRUSTED_HOST")).toBe(true);
  });

  it("should skip comment lines", () => {
    const content = "# registry=http://evil-registry.com\n; also a comment";
    const findings = scanConfigFile(content, ".npmrc");
    expect(findings).toHaveLength(0);
  });

  it("should return empty for clean config", () => {
    const content = "registry=https://registry.npmjs.org/\nsave-exact=true";
    const findings = scanConfigFile(content, ".npmrc");
    // custom registry match won't fire for npmjs.org
    const nonInfo = findings.filter((f) => f.severity !== "info");
    expect(nonInfo).toHaveLength(0);
  });

  it("should include line numbers", () => {
    const content = "save=true\nunsafe-perm=true";
    const findings = scanConfigFile(content, ".npmrc");
    expect(findings.find((f) => f.rule === "CONFIG_UNSAFE_PERM")?.line).toBe(2);
  });

  it("should have patterns array", () => {
    expect(CONFIG_PATTERNS.length).toBeGreaterThan(3);
  });
});
