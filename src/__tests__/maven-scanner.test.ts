import { describe, it, expect } from "vitest";
import { extractMavenCoordinates, isMavenFile, scanMavenContent } from "../maven-scanner.js";
import type { FeedIOC } from "../threat-intel.js";

// Synthetic feed, so the matcher's semantics are pinned independently of the bundle.
const FEED: FeedIOC[] = [
  { type: "package", value: "maven:com.evil:stealer", severity: "critical", confidence: 0.9, family: "TestFamily" },
  { type: "package", value: "maven:org.hijacked:lib@2.0.1", severity: "critical", confidence: 1.0 },
  { type: "package", value: "maven:com.evil:build-plugin", severity: "critical", confidence: 1.0 },
];

const hits = (content: string, file: string, feed: FeedIOC[] = FEED) =>
  scanMavenContent(content, file, feed).filter((f) => f.rule === "MAVEN_MALICIOUS_PACKAGE");

const coords = (content: string, file: string) =>
  extractMavenCoordinates(content, file).map((c) => `${c.group}:${c.artifact}@${c.version ?? "-"}`);

describe("isMavenFile", () => {
  it("accepts pom.xml, Gradle build scripts, lockfiles and version catalogs", () => {
    for (const f of ["pom.xml", "app/pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
      "app/gradle.lockfile", "gradle/libs.versions.toml", "settings.gradle.kts"]) {
      expect(isMavenFile(f), f).toBe(true);
    }
  });

  it("rejects unrelated XML and TOML", () => {
    for (const f of ["web.xml", "Cargo.toml", "pyproject.toml", "libs.toml"]) {
      expect(isMavenFile(f), f).toBe(false);
    }
  });
});

describe("extractMavenCoordinates", () => {
  it("reads pom.xml dependencies, plugins and the parent, resolving properties", () => {
    const pom = `<?xml version="1.0"?>
<project>
  <parent><groupId>org.parent</groupId><artifactId>parent-pom</artifactId><version>1.0</version></parent>
  <properties><lib.version>2.0.1</lib.version></properties>
  <dependencies>
    <dependency>
      <groupId>org.hijacked</groupId>
      <artifactId>lib</artifactId>
      <version>\${lib.version}</version>
    </dependency>
    <!-- <dependency><groupId>com.evil</groupId><artifactId>stealer</artifactId></dependency> -->
    <dependency><groupId>org.managed</groupId><artifactId>no-version</artifactId></dependency>
  </dependencies>
  <build><plugins><plugin>
    <groupId>com.evil</groupId><artifactId>build-plugin</artifactId><version>\${undefined.prop}</version>
  </plugin></plugins></build>
</project>`;
    expect(coords(pom, "pom.xml")).toEqual([
      "org.parent:parent-pom@1.0",
      "org.hijacked:lib@2.0.1",
      "org.managed:no-version@-",
      "com.evil:build-plugin@-",
    ]);
  });

  // A plugin may omit its groupId (Maven defaults it) and may nest its own
  // dependencies; an exclusion names an artifact the project is REMOVING, so
  // it must never be reported as a dependency.
  it("attributes nested plugin dependencies correctly and ignores exclusions", () => {
    const pom = `<project><build><plugins>
  <plugin>
    <artifactId>maven-compiler-plugin</artifactId>
    <dependencies>
      <dependency><groupId>org.inner</groupId><artifactId>helper</artifactId><version>1.1</version></dependency>
    </dependencies>
  </plugin>
</plugins></build>
<dependencies>
  <dependency>
    <groupId>org.app</groupId><artifactId>core</artifactId><version>2.0</version>
    <exclusions><exclusion><groupId>com.evil</groupId><artifactId>stealer</artifactId></exclusion></exclusions>
  </dependency>
</dependencies></project>`;
    expect(coords(pom, "pom.xml")).toEqual([
      "org.inner:helper@1.1",
      "org.apache.maven.plugins:maven-compiler-plugin@-",
      "org.app:core@2.0",
    ]);
    expect(hits(pom, "pom.xml")).toEqual([]);
  });

  it("reads gradle.lockfile entries with their exact versions", () => {
    const lock = [
      "# This is a Gradle generated file for dependency locking.",
      "org.hijacked:lib:2.0.1=compileClasspath,runtimeClasspath",
      "com.google.guava:guava:33.0.0-jre=runtimeClasspath",
      "empty=annotationProcessor",
    ].join("\n");
    expect(coords(lock, "gradle.lockfile")).toEqual([
      "org.hijacked:lib@2.0.1",
      "com.google.guava:guava@33.0.0-jre",
    ]);
  });

  it("reads Groovy and Kotlin DSL coordinate strings", () => {
    const groovy = [
      "dependencies {",
      "  implementation 'org.hijacked:lib:2.0.1'",
      '  testImplementation "com.evil:stealer:1.0.0:sources"',
      "  // implementation 'com.evil:commented:1.0'",
      "}",
    ].join("\n");
    expect(coords(groovy, "build.gradle")).toEqual(["org.hijacked:lib@2.0.1", "com.evil:stealer@1.0.0"]);
    expect(coords('dependencies { implementation("com.evil:stealer:1.2") }', "build.gradle.kts")).toEqual([
      "com.evil:stealer@1.2",
    ]);
  });

  it("reads a version catalog in both module and string form", () => {
    const toml = [
      "[versions]",
      'lib = "2.0.1"',
      "[libraries]",
      'hijacked = { module = "org.hijacked:lib", version.ref = "lib" }',
      'stealer = "com.evil:stealer:1.0.0"',
      'plain = { group = "com.evil", name = "build-plugin", version = "3.0" }',
    ].join("\n");
    expect(coords(toml, "gradle/libs.versions.toml")).toEqual([
      "org.hijacked:lib@2.0.1",
      "com.evil:stealer@1.0.0",
      "com.evil:build-plugin@3.0",
    ]);
  });

  // The plugin id resolves through its marker artifact (asserted as such); what
  // must never happen is the bare version string, a URL or a numeric triple
  // being read as a coordinate of its own.
  it("does not read a Gradle version string or a URL as a coordinate", () => {
    const groovy = [
      "plugins { id 'org.springframework.boot' version '3.2.0' }",
      "repositories { maven { url 'https://repo.example.com:8443/releases' } }",
      "def v = '1:2:3'",
    ].join("\n");
    expect(coords(groovy, "build.gradle")).toEqual([
      "org.springframework.boot:org.springframework.boot.gradle.plugin@3.2.0",
    ]);
  });
});

describe("extractMavenCoordinates: remaining build formats", () => {
  it("accepts SBT and Bazel lockfiles", () => {
    expect(isMavenFile("build.sbt")).toBe(true);
    expect(isMavenFile("project/plugins.sbt")).toBe(true);
    expect(isMavenFile("maven_install.json")).toBe(true);
    expect(isMavenFile("third_party/maven_install.json")).toBe(true);
  });

  it("reads Groovy map and Kotlin named-argument declarations", () => {
    const groovy = "dependencies {\n  implementation group: 'com.evil', name: 'stealer', version: '1.0.0'\n}";
    const kts = 'dependencies {\n  implementation(group = "com.evil", name = "stealer", version = "1.0.0")\n}';
    expect(coords(groovy, "build.gradle")).toEqual(["com.evil:stealer@1.0.0"]);
    expect(coords(kts, "build.gradle.kts")).toEqual(["com.evil:stealer@1.0.0"]);
  });

  // A plugins {} id resolves through its marker artifact, id:id.gradle.plugin.
  it("reads plugins {} ids as their marker artifacts", () => {
    const kts = 'plugins {\n  id("com.evil.plugin") version "2.0"\n  kotlin("jvm") version "2.0.0"\n}';
    const groovy = "plugins {\n  id 'com.evil.plugin' version '2.0'\n  id 'java'\n}";
    expect(coords(kts, "build.gradle.kts")).toEqual(["com.evil.plugin:com.evil.plugin.gradle.plugin@2.0"]);
    expect(coords(groovy, "settings.gradle")).toEqual(["com.evil.plugin:com.evil.plugin.gradle.plugin@2.0"]);
  });

  // %% appends the Scala binary version, which the build file does not state,
  // so each binary version in use is a candidate.
  it("reads SBT % and %% dependencies", () => {
    const sbt = [
      'libraryDependencies += "com.evil" % "stealer" % "1.0.0"',
      'libraryDependencies ++= Seq(',
      '  "com.evil" %% "scala-lib" % "2.0.0" % Test,',
      ')',
      '// libraryDependencies += "com.evil" % "commented" % "1.0"',
    ].join("\n");
    expect(coords(sbt, "build.sbt")).toEqual([
      "com.evil:stealer@1.0.0",
      "com.evil:scala-lib@2.0.0",
      "com.evil:scala-lib_2.12@2.0.0",
      "com.evil:scala-lib_2.13@2.0.0",
      "com.evil:scala-lib_3@2.0.0",
    ]);
  });

  it("reads both maven_install.json formats", () => {
    const v2 = JSON.stringify({ version: "2", artifacts: { "com.evil:stealer": { shasums: {}, version: "1.0.0" }, "org.slf4j:slf4j-api": { version: "2.0.9" } } });
    const v1 = JSON.stringify({ dependency_tree: { dependencies: [{ coord: "com.evil:stealer:1.0.0" }, { coord: "com.evil:stealer:jar:sources:1.0.0" }] } });
    expect(coords(v2, "maven_install.json")).toEqual(["com.evil:stealer@1.0.0", "org.slf4j:slf4j-api@2.0.9"]);
    expect(coords(v1, "maven_install.json")).toEqual(["com.evil:stealer@1.0.0"]);
  });
});

describe("scanMavenContent", () => {
  it("flags a bare-name IOC from a pom.xml dependency", () => {
    const pom = "<project><dependencies><dependency><groupId>com.evil</groupId><artifactId>stealer</artifactId><version>9.9</version></dependency></dependencies></project>";
    const found = hits(pom, "pom.xml");
    expect(found).toHaveLength(1);
    expect(found[0]?.severity).toBe("critical");
    expect(found[0]?.category).toBe("malware");
    expect(found[0]?.match).toBe("com.evil:stealer@9.9");
    expect(found[0]?.description).toContain("TestFamily");
  });

  it("flags a build plugin, not only a dependency", () => {
    const pom = "<project><build><plugins><plugin><groupId>com.evil</groupId><artifactId>build-plugin</artifactId></plugin></plugins></build></project>";
    expect(hits(pom, "pom.xml")).toHaveLength(1);
  });

  it("matches a version pin only on that version", () => {
    expect(hits("org.hijacked:lib:2.0.1=runtimeClasspath", "gradle.lockfile")).toHaveLength(1);
    expect(hits("org.hijacked:lib:2.0.2=runtimeClasspath", "gradle.lockfile")).toHaveLength(0);
  });

  // Maven coordinates are case-sensitive, so a case variant is a different artifact.
  it("does not fold case", () => {
    expect(hits("com.Evil:Stealer:1.0=runtimeClasspath", "gradle.lockfile")).toHaveLength(0);
  });

  it("reports each coordinate once per file", () => {
    const lock = ["com.evil:stealer:1.0=compileClasspath", "com.evil:stealer:1.0=runtimeClasspath"].join("\n");
    expect(hits(lock, "gradle.lockfile")).toHaveLength(1);
  });

  it("leaves a clean build alone", () => {
    const lock = ["com.google.guava:guava:33.0.0-jre=runtimeClasspath", "org.slf4j:slf4j-api:2.0.9=runtimeClasspath"].join("\n");
    expect(scanMavenContent(lock, "gradle.lockfile", FEED)).toEqual([]);
  });
});
