/**
 * Extractors of the registry ecosystems (ecosystem-registry.ts): what each
 * reads, and the false-positive boundaries it must hold. End-to-end detection
 * through a real scan is proven in coverage-matrix.test.ts.
 */
import { describe, it, expect } from "vitest";
import { ECOSYSTEM_MATCHERS, isRegistryFile, normalizeRepositoryUrl, scanRegistryFile } from "../ecosystem-registry.js";
import type { FeedIOC } from "../threat-intel.js";

const m = (id: string) => ECOSYSTEM_MATCHERS.find((x) => x.id === id)!;
const refs = (id: string, content: string, file: string) =>
  m(id).extract(content, file).map((r) => `${r.name}@${r.version ?? "-"}`);

describe("normalizeRepositoryUrl (OSV SwiftURL spelling)", () => {
  it("normalises scheme, .git, case and scp-style URLs", () => {
    expect(normalizeRepositoryUrl("https://github.com/Vapor/Vapor.git")).toBe("github.com/vapor/vapor");
    expect(normalizeRepositoryUrl("git@github.com:apple/swift-nio.git")).toBe("github.com/apple/swift-nio");
    expect(normalizeRepositoryUrl("ssh://git@gitlab.com/group/sub/repo")).toBe("gitlab.com/group/sub/repo");
  });
  it("rejects local paths and hostless values", () => {
    for (const v of ["../local/pkg", "/abs/path", "file:///x/y/z", "github.com/only-owner", "not a url"]) {
      expect(normalizeRepositoryUrl(v), v).toBeNull();
    }
  });
});

describe("swift", () => {
  it("reads Package.resolved v1 and v2/v3, remote pins only", () => {
    const v1 = JSON.stringify({ object: { pins: [{ package: "Vapor", repositoryURL: "https://github.com/vapor/vapor.git", state: { version: "4.99.0" } }] }, version: 1 });
    const v2 = JSON.stringify({ pins: [
      { identity: "evil", kind: "remoteSourceControl", location: "https://github.com/evil/pkg.git", state: { version: "1.0.0" } },
      { identity: "local", kind: "localSourceControl", location: "/src/local", state: { version: "1.0.0" } },
      { identity: "branch", kind: "remoteSourceControl", location: "https://github.com/x/branch", state: { branch: "main", revision: "abc" } },
    ], version: 2 });
    expect(refs("swift", v1, "Package.resolved")).toEqual(["github.com/vapor/vapor@4.99.0"]);
    expect(refs("swift", v2, "Package.resolved")).toEqual(["github.com/evil/pkg@1.0.0", "github.com/x/branch@-"]);
  });
  it("reads Package.swift, keeping only exact versions", () => {
    const pkg = [
      '.package(url: "https://github.com/evil/pkg.git", from: "1.0.0"),',
      '.package(url: "https://github.com/evil/pinned", exact: "2.0.0"),',
      '// .package(url: "https://github.com/evil/commented", from: "1.0.0"),',
    ].join("\n");
    expect(refs("swift", pkg, "Package.swift")).toEqual(["github.com/evil/pkg@-", "github.com/evil/pinned@2.0.0"]);
  });
});

describe("cocoapods", () => {
  it("reads top-level Podfile.lock pods with exact versions, not their dependency lines", () => {
    const lock = ["PODS:", "  - EvilPod (1.2.3):", "    - AFNetworking (~> 4.0)", "  - AFNetworking (4.0.1)", "  - Firebase/Core (10.0.0)", "", "DEPENDENCIES:", "  - EvilPod"].join("\n");
    expect(refs("cocoapods", lock, "Podfile.lock")).toEqual(["evilpod@1.2.3", "afnetworking@4.0.1", "firebase@10.0.0"]);
  });
  it("reads Podfile pods and skips git/path sources", () => {
    const podfile = ["pod 'EvilPod', '1.2.3'", "pod 'Other', '~> 2.0'", "pod 'Local', :path => '../Local'", "pod 'Git', :git => 'https://x/y.git'"].join("\n");
    expect(refs("cocoapods", podfile, "Podfile")).toEqual(["evilpod@1.2.3", "other@-"]);
  });
});

describe("hex", () => {
  it("reads mix.lock by the Hex package name, not the key", () => {
    const lock = '%{\n  "alias": {:hex, :evil_pkg, "1.2.3", "abc", [:mix], [], "hexpm", "def"},\n  "git_dep": {:git, "https://x", "abc", []},\n}';
    expect(refs("hex", lock, "mix.lock")).toEqual(["evil_pkg@1.2.3"]);
  });
  it("reads mix.exs deps, follows hex: renames, skips git/path", () => {
    const exs = [
      'defp deps do',
      '  [{:evil_pkg, "~> 1.0"}, {:pinned, "== 2.0.0"},',
      '   {:alias, "~> 1.0", hex: :real_pkg},',
      '   {:local, path: "../local"}, {:gitdep, "~> 1.0", git: "https://x"}]',
      'end',
    ].join("\n");
    expect(refs("hex", exs, "mix.exs")).toEqual(["evil_pkg@-", "pinned@2.0.0", "real_pkg@-"]);
  });
});

describe("cran", () => {
  it("reads repository-sourced renv.lock packages only", () => {
    const lock = JSON.stringify({ Packages: {
      evilpkg: { Package: "evilpkg", Version: "1.0.0", Source: "Repository", Repository: "CRAN" },
      gh: { Package: "gh", Version: "0.1", Source: "GitHub" },
      bioc: { Package: "bioc", Version: "1.0", Source: "Bioconductor" },
    } });
    expect(refs("cran", lock, "renv.lock")).toEqual(["evilpkg@1.0.0"]);
  });
  it("reads DESCRIPTION dependency fields with continuation lines", () => {
    const desc = ["Package: mypkg", "Imports: evilpkg (>= 1.0),", "    other,", "    exact (== 2.0.0)", "Depends: R (>= 4.0)", "Title: x, y"].join("\n");
    expect(refs("cran", desc, "DESCRIPTION")).toEqual(["evilpkg@-", "other@-", "exact@2.0.0"]);
  });
});

describe("conan", () => {
  it("reads conan.lock v2 and v1", () => {
    const v2 = JSON.stringify({ version: "0.5", requires: ["evil/1.2.3#abc%123", "zlib/[>1 <2]"], build_requires: ["cmake/3.27.0"] });
    const v1 = JSON.stringify({ graph_lock: { nodes: { "1": { ref: "evil/1.2.3@user/stable#rev" } } } });
    expect(refs("conan", v2, "conan.lock")).toEqual(["evil@1.2.3", "zlib@-", "cmake@3.27.0"]);
    expect(refs("conan", v1, "conan.lock")).toEqual(["evil@1.2.3"]);
  });
  it("reads conanfile.txt requirement sections and conanfile.py requires", () => {
    const txt = "[requires]\nevil/1.2.3\n\n[generators]\nCMakeDeps\n";
    const py = 'class X(ConanFile):\n    requires = "evil/1.2.3", "fmt/10.1.1"\n    def requirements(self):\n        self.requires("boost/1.83.0")\n    name = "not/a-requirement"';
    expect(refs("conan", txt, "conanfile.txt")).toEqual(["evil@1.2.3"]);
    expect(refs("conan", py, "conanfile.py")).toEqual(["evil@1.2.3", "fmt@10.1.1", "boost@1.83.0"]);
  });
});

describe("helm", () => {
  it("reads dependencies with repository-qualified identities", () => {
    const chart = [
      "apiVersion: v2", "name: app", "dependencies:",
      "  - name: evil-chart", "    version: 1.2.3", "    repository: https://charts.example.com/stable",
      "  - name: oci-chart", '    version: "~1.0"', "    repository: oci://registry-1.docker.io/evilcharts",
      "  - name: aliased", "    version: 1.0.0", '    repository: "@stable"',
      "  - name: local", "    repository: file://../local",
      "maintainers:", "  - name: someone",
    ].join("\n");
    expect(refs("helm", chart, "Chart.yaml")).toEqual([
      "charts.example.com/stable/evil-chart@1.2.3",
      "registry-1.docker.io/evilcharts/oci-chart@-",
    ]);
  });
});

describe("helm Chart.lock (list items at column 0)", () => {
  it("reads the shape helm dependency update actually writes", () => {
    const lock = [
      "dependencies:",
      "- name: postgresql",
      "  repository: https://charts.bitnami.com/bitnami",
      "  version: 12.1.0",
      "- name: redis",
      "  repository: oci://registry-1.docker.io/bitnamicharts",
      "  version: 18.0.0",
      "digest: sha256:abc",
      'generated: "2026-01-01T00:00:00Z"',
    ].join("\n");
    expect(refs("helm", lock, "Chart.lock")).toEqual([
      "charts.bitnami.com/bitnami/postgresql@12.1.0",
      "registry-1.docker.io/bitnamicharts/redis@18.0.0",
    ]);
  });
});

describe("ansible", () => {
  it("reads collections and roles, skipping git and URL sources", () => {
    const req = [
      "collections:", "  - name: evil.coll", "    version: 1.2.3", "  - community.general",
      "  - name: https://example.com/x.tar.gz", "    type: url",
      "roles:", "  - src: evil.role", "    version: 2.0.0", "  - src: https://github.com/x/role.git", "    name: renamed",
    ].join("\n");
    expect(refs("ansible", req, "requirements.yml")).toEqual(["evil.coll@1.2.3", "community.general@-", "evil.role@2.0.0"]);
  });
  // A Galaxy-shaped NAME with a non-Galaxy SOURCE is someone else's content
  // that merely shares the name, so it is not looked up.
  it("skips a Galaxy-shaped name fetched from git or a private Galaxy", () => {
    const req = [
      "roles:", "  - name: evil.role", "    src: git+https://github.com/x/role.git",
      "collections:", "  - name: evil.coll", "    source: https://galaxy.internal.example/",
      "  - name: pub.coll", "    source: https://galaxy.ansible.com",
    ].join("\n");
    expect(refs("ansible", req, "requirements.yml")).toEqual(["pub.coll@-"]);
  });

  it("reads a bare role list and galaxy.yml dependencies", () => {
    expect(refs("ansible", "- evil.role\n- name: other.role\n", "requirements.yml")).toEqual(["evil.role@-", "other.role@-"]);
    expect(refs("ansible", "namespace: me\ndependencies:\n  evil.coll: '1.0.0'\n  other.coll: '>=2.0'\n", "galaxy.yml")).toEqual(["evil.coll@1.0.0", "other.coll@-"]);
  });
});

describe("homebrew", () => {
  it("reads Brewfile formulae, casks and taps", () => {
    const brewfile = ['tap "evil/tools"', 'brew "evil/tools/stealer"', 'brew "wget"', 'cask "evil-app"', '# brew "commented"'].join("\n");
    expect(refs("homebrew", brewfile, "Brewfile")).toEqual(["tap:evil/tools@-", "evil/tools/stealer@-", "wget@-", "cask:evil-app@-"]);
  });
  it("reads Brewfile.lock.json with versions", () => {
    const lock = JSON.stringify({ entries: { brew: { "aquasecurity/trivy/trivy": { version: "0.69.4" } }, cask: { "evil-app": { version: "1.0.0" } } } });
    expect(refs("homebrew", lock, "Brewfile.lock.json")).toEqual(["aquasecurity/trivy/trivy@0.69.4", "cask:evil-app@1.0.0"]);
  });
});

describe("browser extensions", () => {
  const CHROME_ID = "abcdefghijklmnopabcdefghijklmnop";
  it("reads Chromium policies (forcelist and ExtensionSettings) as Chrome and Edge candidates", () => {
    const policy = JSON.stringify({ ExtensionInstallForcelist: [`${CHROME_ID};https://clients2.google.com/service/update2/crx`], ExtensionSettings: { "*": {}, "ppppppppppppppppppppppppppppppppp": {} } });
    const found = m("chrome").extract(policy, "etc/opt/chrome/policies/managed/extensions.json");
    expect(found.map((r) => `${r.name}:${r.ecosystems?.join("+")}`)).toEqual([`${CHROME_ID}:chrome+edge`]);
  });
  it("reads Firefox policies.json ExtensionSettings ids", () => {
    const policy = JSON.stringify({ policies: { ExtensionSettings: { "*": { installation_mode: "blocked" }, "evil@addon.example": { installation_mode: "force_installed" } } } });
    expect(m("chrome").extract(policy, "distribution/policies.json").map((r) => `${r.name}:${r.ecosystems}`)).toEqual(["evil@addon.example:firefox"]);
  });
  it("reads installed Chromium extensions from their profile path, with the manifest version", () => {
    const manifest = JSON.stringify({ manifest_version: 3, name: "x", version: "24.10.4" });
    const file = `Default/Extensions/${CHROME_ID}/24.10.4_0/manifest.json`;
    expect(refs("chrome", manifest, file)).toEqual([`${CHROME_ID}@24.10.4`]);
  });
  // An extension's SOURCE tree may sit in a folder named after its id; only a
  // version directory marks an installed copy whose version the manifest states.
  it("does not read an extension source tree as an installed copy", () => {
    const manifest = JSON.stringify({ manifest_version: 3, name: "x", version: "1.0.0" });
    expect(refs("chrome", manifest, `${CHROME_ID}/src/manifest.json`)).toEqual([]);
  });

  it("reads a Firefox manifest's gecko id; a web-app manifest yields nothing", () => {
    const ff = JSON.stringify({ manifest_version: 2, version: "8.12.13", browser_specific_settings: { gecko: { id: "evil@addon.example" } } });
    expect(refs("chrome", ff, "addon/manifest.json")).toEqual(["evil@addon.example@8.12.13"]);
    expect(refs("chrome", JSON.stringify({ name: "PWA", short_name: "p", start_url: "/" }), "public/manifest.json")).toEqual([]);
  });
  it("only reads JSON under policies/managed or recommended, besides the named files", () => {
    expect(isRegistryFile("config/settings.json")).toBe(false);
    expect(isRegistryFile("etc/opt/edge/policies/managed/x.json")).toBe(true);
  });
});

describe("jetbrains", () => {
  it("reads required plugins and a plugin descriptor", () => {
    const deps = '<project version="4">\n  <component name="ExternalDependencies">\n    <plugin id="org.sm.yms.toolkit" />\n  </component>\n</project>';
    const desc = "<idea-plugin>\n  <id>com.evil.plugin</id>\n  <version>1.2.3</version>\n</idea-plugin>";
    expect(refs("jetbrains", deps, ".idea/externalDependencies.xml")).toEqual(["org.sm.yms.toolkit@-"]);
    expect(refs("jetbrains", desc, "src/main/resources/META-INF/plugin.xml")).toEqual(["com.evil.plugin@1.2.3"]);
  });
  it("reads nothing from other XML", () => {
    expect(isRegistryFile(".idea/workspace.xml")).toBe(false);
    expect(isRegistryFile("plugin.xml")).toBe(false);
  });
});

describe("scanRegistryFile", () => {
  const FEED: FeedIOC[] = [
    { type: "package", value: "edge:abcdefghijklmnopabcdefghijklmnop", severity: "critical", confidence: 1.0 },
    { type: "package", value: "homebrew:aquasecurity/trivy/trivy@0.69.4", severity: "critical", confidence: 1.0 },
  ];
  it("tries every candidate registry of a multi-registry identity", () => {
    const policy = JSON.stringify({ ExtensionInstallForcelist: ["abcdefghijklmnopabcdefghijklmnop"] });
    const found = scanRegistryFile(policy, "policies/managed/x.json", FEED);
    expect(found.map((f) => f.rule)).toEqual(["BROWSER_MALICIOUS_EXTENSION"]);
    expect(found[0]?.description).toContain("(edge)");
  });
  it("honours version pins", () => {
    const lock = (v: string) => JSON.stringify({ entries: { brew: { "aquasecurity/trivy/trivy": { version: v } } } });
    expect(scanRegistryFile(lock("0.69.4"), "Brewfile.lock.json", FEED)).toHaveLength(1);
    expect(scanRegistryFile(lock("0.69.3"), "Brewfile.lock.json", FEED)).toEqual([]);
  });
});
