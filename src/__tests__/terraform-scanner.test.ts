import { describe, it, expect } from "vitest";
import {
  extractTerraformProviders,
  isTerraformProviderFile,
  scanTerraformContent,
} from "../terraform-scanner.js";
import type { FeedIOC } from "../threat-intel.js";

// A synthetic feed, so these tests pin the matcher's semantics independently of
// what the bundled feed happens to hold. The bundled Graphalgo entries are
// asserted through the real scan path in campaigns.test.ts.
const FEED: FeedIOC[] = [
  { type: "package", value: "terraform:evil-ns/docker", severity: "critical", confidence: 0.9, family: "TestFamily", campaign: "Test campaign" },
  { type: "package", value: "terraform:pinned-ns/aws@5.1.0", severity: "high", confidence: 1.0 },
  { type: "package", value: "go:evil-ns/docker", severity: "critical", confidence: 1.0 },
];

const rules = (content: string, file: string) =>
  scanTerraformContent(content, file, FEED).filter((f) => f.rule === "TERRAFORM_MALICIOUS_PROVIDER");

describe("isTerraformProviderFile", () => {
  it("accepts .tf, .tf.json and the dependency lock file", () => {
    expect(isTerraformProviderFile("main.tf")).toBe(true);
    expect(isTerraformProviderFile("versions.tf.json")).toBe(true);
    expect(isTerraformProviderFile(".terraform.lock.hcl")).toBe(true);
  });

  it("rejects other HCL and JSON files", () => {
    expect(isTerraformProviderFile("terragrunt.hcl")).toBe(false);
    expect(isTerraformProviderFile("package.json")).toBe(false);
    expect(isTerraformProviderFile("main.tfvars")).toBe(false);
  });
});

describe("extractTerraformProviders", () => {
  it("reads an inline required_providers source", () => {
    const content = [
      "terraform {",
      "  required_providers {",
      '    docker = { source = "evil-ns/docker", version = "~> 3.0" }',
      "  }",
      "}",
    ].join("\n");
    expect(extractTerraformProviders(content, "main.tf")).toEqual([
      { address: "evil-ns/docker", version: undefined, line: 3 },
    ]);
  });

  it("reads a multi-line required_providers source", () => {
    const content = [
      "terraform {",
      "  required_providers {",
      "    docker = {",
      '      source  = "registry.terraform.io/Evil-NS/Docker"',
      '      version = "3.0.2"',
      "    }",
      "  }",
      "}",
    ].join("\n");
    expect(extractTerraformProviders(content, "main.tf")).toEqual([
      { address: "evil-ns/docker", version: undefined, line: 4 },
    ]);
  });

  it("reads provider blocks and exact versions from the lock file", () => {
    const content = [
      "# This file is maintained automatically by \"terraform init\".",
      'provider "registry.terraform.io/evil-ns/docker" {',
      '  version     = "3.0.2"',
      '  constraints = "~> 3.0"',
      "  hashes = [",
      '    "h1:AAAA=",',
      "  ]",
      "}",
      "",
      'provider "registry.opentofu.org/hashicorp/aws" {',
      '  version = "5.1.0"',
      "}",
    ].join("\n");
    expect(extractTerraformProviders(content, ".terraform.lock.hcl")).toEqual([
      { address: "evil-ns/docker", version: "3.0.2", line: 2 },
      { address: "hashicorp/aws", version: "5.1.0", line: 10 },
    ]);
  });

  it("reads a .tf.json source attribute", () => {
    const content = JSON.stringify(
      { terraform: { required_providers: { docker: { source: "evil-ns/docker" } } } },
      null,
      2,
    );
    expect(extractTerraformProviders(content, "main.tf.json").map((p) => p.address)).toEqual([
      "evil-ns/docker",
    ]);
  });

  // Module sources share the attribute name. A registry module address has
  // three parts without a host (ns/name/system), and every other module form
  // is a path or a URL; none of them may be read as a provider.
  it("never reads a module source as a provider", () => {
    const content = [
      'module "vpc" { source = "evil-ns/docker/aws" }',
      'module "local" { source = "./evil-ns/docker" }',
      // Two segments, the same shape as a provider address: only the label
      // rule stands between these and a lookup.
      'module "near" { source = "./docker" }',
      'module "parent" { source = "../docker" }',
      'module "tilde" { source = "~/docker" }',
      'module "up" { source = "../evil-ns/docker" }',
      'module "git" { source = "git::https://example.com/evil-ns/docker.git" }',
      'module "gh" { source = "github.com/evil-ns/docker" }',
      'module "reg" { source = "registry.terraform.io/evil-ns/docker/aws" }',
      'module "http" { source = "https://example.com/evil-ns/docker.zip" }',
    ].join("\n");
    expect(extractTerraformProviders(content, "main.tf")).toEqual([]);
  });

  // A private registry host names a different provider that merely shares the
  // namespace/type, so only the public registries resolve to feed identities.
  it("ignores providers served from a private registry host", () => {
    const content = '    docker = { source = "tf.internal.example/evil-ns/docker" }';
    expect(extractTerraformProviders(content, "main.tf")).toEqual([]);
  });
});

describe("scanTerraformContent", () => {
  it("flags a bare-name provider IOC from a .tf source", () => {
    const hits = rules('    docker = { source = "evil-ns/docker" }', "infra/main.tf");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.severity).toBe("critical");
    expect(hits[0]?.category).toBe("malware");
    expect(hits[0]?.confidence).toBe(0.9);
    expect(hits[0]?.file).toBe("infra/main.tf");
    expect(hits[0]?.line).toBe(1);
    expect(hits[0]?.description).toContain("evil-ns/docker");
    expect(hits[0]?.description).toContain("TestFamily");
  });

  it("matches case-insensitively, as the registry does", () => {
    expect(rules('source = "EVIL-NS/Docker"', "main.tf")).toHaveLength(1);
  });

  // The feed side too: a hand-curated entry is not guaranteed to be lowercase.
  it("matches a feed entry written in mixed case", () => {
    const feed: FeedIOC[] = [{ type: "package", value: "terraform:Mixed-NS/Provider", severity: "critical", confidence: 1.0 }];
    expect(scanTerraformContent('source = "mixed-ns/provider"', "main.tf", feed)).toHaveLength(1);
  });

  it("flags a lock-file provider and reports each provider once", () => {
    const content = [
      'provider "registry.terraform.io/evil-ns/docker" {',
      '  version = "3.0.2"',
      "}",
      'provider "registry.terraform.io/evil-ns/docker" {',
      '  version = "3.0.2"',
      "}",
    ].join("\n");
    const hits = rules(content, ".terraform.lock.hcl");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.match).toBe("evil-ns/docker@3.0.2");
  });

  it("matches a version-pinned IOC only on the locked version", () => {
    const at = (v: string) =>
      rules(`provider "registry.terraform.io/pinned-ns/aws" {\n  version = "${v}"\n}`, ".terraform.lock.hcl");
    expect(at("5.1.0")).toHaveLength(1);
    expect(at("5.0.9")).toHaveLength(0);
    // A .tf constraint is not a resolved version, so a pin cannot fire there.
    expect(rules('source = "pinned-ns/aws"', "main.tf")).toHaveLength(0);
  });

  it("does not cross ecosystems: a go: entry with the same name stays silent", () => {
    const feed: FeedIOC[] = [{ type: "package", value: "go:evil-ns/docker", severity: "critical", confidence: 1.0 }];
    expect(scanTerraformContent('source = "evil-ns/docker"', "main.tf", feed)).toEqual([]);
  });

  it("leaves a clean configuration alone", () => {
    const content = [
      "terraform {",
      "  required_providers {",
      '    aws    = { source = "hashicorp/aws", version = "~> 5.0" }',
      '    docker = { source = "kreuzwerker/docker", version = "~> 3.0" }',
      "  }",
      "}",
    ].join("\n");
    expect(scanTerraformContent(content, "main.tf", FEED)).toEqual([]);
  });
});
