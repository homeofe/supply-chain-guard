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
  // kotlin("x") is shorthand for the id org.jetbrains.kotlin.x. (This test used
  // to assert that kotlin("jvm") yields nothing, which encoded the gap.)
  it("reads plugins {} ids as their marker artifacts", () => {
    const kts = 'plugins {\n  id("com.evil.plugin") version "2.0"\n  kotlin("jvm") version "2.0.0"\n  kotlin("plugin.spring") version "2.0.0" apply false\n}';
    const groovy = "plugins {\n  id 'com.evil.plugin' version '2.0'\n  id 'java'\n}";
    expect(coords(kts, "build.gradle.kts")).toEqual([
      "com.evil.plugin:com.evil.plugin.gradle.plugin@2.0",
      "org.jetbrains.kotlin.jvm:org.jetbrains.kotlin.jvm.gradle.plugin@2.0.0",
      "org.jetbrains.kotlin.plugin.spring:org.jetbrains.kotlin.plugin.spring.gradle.plugin@2.0.0",
    ]);
    expect(coords(groovy, "settings.gradle")).toEqual(["com.evil.plugin:com.evil.plugin.gradle.plugin@2.0"]);
    // kotlin("stdlib") without a version is the dependency shorthand, not a plugin.
    expect(coords('dependencies {\n  implementation(kotlin("stdlib"))\n}', "build.gradle.kts")).toEqual([]);
  });

  // %% appends the Scala binary version, which the build file does not state,
  // so each binary version in use is a candidate. The plain artifact name is
  // never resolved by %%, so it is not a candidate (this test used to expect
  // it, which was a false positive against a different artifact).
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
      "com.evil:scala-lib_2.11@2.0.0",
      "com.evil:scala-lib_2.12@2.0.0",
      "com.evil:scala-lib_2.13@2.0.0",
      "com.evil:scala-lib_3@2.0.0",
    ]);
  });

  it("does not report the plain artifact for %%, and expands %%% to Scala.js artifacts", () => {
    expect(hits('libraryDependencies += "com.evil" %% "stealer" % "1.0.0"', "build.sbt")).toEqual([]);
    expect(coords('libraryDependencies += "com.evil" %%% "scala-lib" % "2.0.0"', "build.sbt")).toEqual([
      "com.evil:scala-lib_sjs1_2.11@2.0.0",
      "com.evil:scala-lib_sjs1_2.12@2.0.0",
      "com.evil:scala-lib_sjs1_2.13@2.0.0",
      "com.evil:scala-lib_sjs1_3@2.0.0",
    ]);
  });

  // `cross CrossVersion.full` appends the full Scala version the build states;
  // `CrossVersion.binary` behaves like %%.
  it("expands cross CrossVersion.full from the build's Scala versions, and binary like %%", () => {
    const sbt = [
      'ThisBuild / scalaVersion := "2.13.12"',
      'crossScalaVersions := Seq("2.12.18", "2.13.12")',
      'addCompilerPlugin("org.evil" % "plugin" % "1.0.0" cross CrossVersion.full)',
      'libraryDependencies += ("org.evil" % "macro" % "2.0.0").cross(CrossVersion.binary)',
    ].join("\n");
    expect(coords(sbt, "build.sbt")).toEqual([
      "org.evil:plugin_2.13.12@1.0.0",
      "org.evil:plugin_2.12.18@1.0.0",
      "org.evil:macro_2.11@2.0.0",
      "org.evil:macro_2.12@2.0.0",
      "org.evil:macro_2.13@2.0.0",
      "org.evil:macro_3@2.0.0",
    ]);
  });

  it("reports nothing for CrossVersion.full when the build states no Scala version", () => {
    expect(coords('addCompilerPlugin("org.evil" % "plugin" % "1.0.0" cross CrossVersion.full)', "build.sbt")).toEqual([]);
  });

  // A non-literal version is unknown: a whole-name entry fires, a pin cannot.
  it("reads SBT dependencies whose version is a val", () => {
    const sbt = [
      'val libVersion = "2.0.1"',
      'libraryDependencies += "com.evil" % "stealer" % libVersion',
      'libraryDependencies += "org.hijacked" % "lib" % Versions.lib',
      'libraryDependencies += "com.evil" %% "scala-lib" % scalaLibV',
    ].join("\n");
    expect(coords(sbt, "build.sbt")).toEqual([
      "com.evil:stealer@-",
      "org.hijacked:lib@-",
      "com.evil:scala-lib_2.11@-",
      "com.evil:scala-lib_2.12@-",
      "com.evil:scala-lib_2.13@-",
      "com.evil:scala-lib_3@-",
    ]);
    expect(hits(sbt, "build.sbt").map((f) => f.match)).toEqual(["com.evil:stealer"]);
  });

  // Gradle coordinates whose version is a variable, a catalog accessor or
  // absent (platform/BOM-managed): the artifact is still resolved.
  // A configuration the script declares itself counts like a built-in one; an
  // undeclared call such as println(...) still never does.
  it("reads non-literal versions on configurations the script declares", () => {
    const kts = [
      'val shadowed by configurations.creating',
      'configurations.register("agent")',
      'shadowed("com.evil:stealer:$ver")',
      'agent("org.evil:javaagent")',
      'println("com.evil:not-a-dep:$ver")',
    ].join("\n");
    expect(coords(kts, "build.gradle.kts")).toEqual(["com.evil:stealer@-", "org.evil:javaagent@-"]);
    const groovy = [
      "configurations {",
      "    bundled",
      "    tooling {",
      "        canBeResolved = true",
      "    }",
      "}",
      'bundled "com.evil:stealer:${libVersion}"',
      'tooling "org.evil:tool"',
    ].join("\n");
    expect(coords(groovy, "build.gradle")).toEqual(["com.evil:stealer@-", "org.evil:tool@-"]);
  });

  it("reads Gradle declarations with a non-literal or managed version", () => {
    const groovy = [
      "dependencies {",
      '  implementation "com.evil:stealer:$stealerVersion"',
      "  implementation 'org.hijacked:lib:${libs.versions.lib.get()}'",
      '  api platform("org.bom:bom:$bomVersion")',
      "  // implementation 'com.evil:commented'",
      "}",
    ].join("\n");
    expect(coords(groovy, "build.gradle")).toEqual([
      "com.evil:stealer@-",
      "org.hijacked:lib@-",
      "org.bom:bom@-",
    ]);
    const kts = [
      "dependencies {",
      '  implementation("com.evil:stealer:${libs.versions.x.get()}")',
      '  testImplementation("com.evil:build-plugin")',
      '  implementation("org.hijacked:lib:2.0.1")',
      "}",
    ].join("\n");
    expect(coords(kts, "build.gradle.kts")).toEqual([
      "com.evil:stealer@-",
      "com.evil:build-plugin@-",
      "org.hijacked:lib@2.0.1",
    ]);
    // The pin needs the exact version; an unknown one fires only whole-name entries.
    expect(hits('dependencies { implementation("org.hijacked:lib:$v") }', "build.gradle.kts")).toEqual([]);
    expect(hits('dependencies { implementation("com.evil:stealer") }', "build.gradle.kts")).toHaveLength(1);
  });

  // A quoted g:a outside a dependency declaration is not a dependency: a
  // substitution target, an exclude, a log line.
  it("does not read a version-less g:a string outside a dependency configuration", () => {
    const kts = [
      "configurations.all {",
      '  resolutionStrategy.dependencySubstitution { substitute(module("com.evil:stealer")).using(module("org.safe:lib:1.0")) }',
      '  exclude("com.evil:stealer")',
      "}",
      'println("com.evil:stealer")',
      'val coordinate = "com.evil:stealer"',
    ].join("\n");
    expect(coords(kts, "build.gradle.kts")).toEqual(["org.safe:lib@1.0"]);
  });

  it("reads rich versions and the [plugins] table of a version catalog", () => {
    const toml = [
      "[versions]",
      'lib = { strictly = "2.0.1" }',
      "[libraries]",
      'hijacked = { module = "org.hijacked:lib", version.ref = "lib" }',
      'strict = { module = "com.evil:stealer", version = { strictly = "4.18.1" } }',
      'required = { group = "com.evil", name = "build-plugin", version = { require = "3.0" } }',
      'preferred = { module = "org.x:y", version = { prefer = "1.5" } }',
      "[plugins]",
      'boot = { id = "org.springframework.boot", version = "3.2.0" }',
      'evil = { id = "com.evil.plugin", version.ref = "lib" }',
      'short = "com.evil.short:1.0"',
      "[bundles]",
      'all = ["hijacked", "strict"]',
    ].join("\n");
    expect(coords(toml, "gradle/libs.versions.toml")).toEqual([
      "org.hijacked:lib@2.0.1",
      "com.evil:stealer@4.18.1",
      "com.evil:build-plugin@3.0",
      "org.x:y@1.5",
      "org.springframework.boot:org.springframework.boot.gradle.plugin@3.2.0",
      "com.evil.plugin:com.evil.plugin.gradle.plugin@2.0.1",
      "com.evil.short:com.evil.short.gradle.plugin@1.0",
    ]);
    expect(hits(toml, "gradle/libs.versions.toml").map((f) => f.match)).toEqual([
      "org.hijacked:lib@2.0.1",
      "com.evil:stealer@4.18.1",
      "com.evil:build-plugin@3.0",
    ]);
  });

  // Properties can sit in several blocks; the top level wins over a profile.
  it("merges pom properties from every block, the top level winning", () => {
    const pom = `<project>
  <profiles><profile><id>p</id><properties><lib.version>9.9</lib.version><evil.version>1.0</evil.version></properties></profile></profiles>
  <dependencies>
    <dependency><groupId>org.hijacked</groupId><artifactId>lib</artifactId><version>\${lib.version}</version></dependency>
    <dependency><groupId>com.evil</groupId><artifactId>stealer</artifactId><version>\${evil.version}</version></dependency>
  </dependencies>
  <build><plugins><plugin><artifactId>x</artifactId><configuration><properties><other>7.7</other></properties></configuration></plugin></plugins></build>
  <properties><lib.version>2.0.1</lib.version></properties>
  <dependencies><dependency><groupId>org.a</groupId><artifactId>b</artifactId><version>\${other}</version></dependency></dependencies>
</project>`;
    expect(coords(pom, "pom.xml")).toEqual([
      "org.hijacked:lib@2.0.1",
      "com.evil:stealer@1.0",
      "org.apache.maven.plugins:x@-",
      "org.a:b@-",
    ]);
  });

  it("stays linear on hostile build files", () => {
    // Long whitespace runs after each keyword: the shape that makes
    // `\s*\(?\s*` split one run every way before failing.
    const ws = " ".repeat(100_000);
    const gradle = ("implementation " + "a".repeat(100_000) + " '" + "b.".repeat(100_000) + "\n").repeat(3)
      + "x".repeat(300_000) + "(\n" + " ".repeat(300_000) + "kotlin(\"a\")\n"
      + `implementation${ws}x\n` + `id${ws}x\n` + `id 'a'${ws}version${ws}x\n` + `kotlin(${ws}"a")${ws}version${ws}x\n`;
    const sbt = ('"a" % "b" % ' + "c".repeat(200_000) + "\n") + '"a" '.repeat(100_000) + "\n"
      + `"a"${ws}%%${ws}"b"${ws}%${ws}!\n`;
    const toml = "[libraries]\n" + ('x = { version = { strictly = "' + "1".repeat(100_000) + "\n").repeat(3);
    const t0 = Date.now();
    extractMavenCoordinates(gradle, "build.gradle.kts");
    extractMavenCoordinates(sbt, "build.sbt");
    extractMavenCoordinates(toml, "gradle/libs.versions.toml");
    expect(Date.now() - t0).toBeLessThan(3000);
  });

  // pom.xml: a comment regex and a tag regex that rescanned to the end of the
  // file from every unclosed "<!--" / "<a" (30 s and 4.6 s at a few hundred KB).
  it("stays linear on a hostile pom.xml", () => {
    const comments = "<project>" + "<!--".repeat(100_000) + "</project>";
    // No ">" anywhere: a closing tag at the end lets the regex match once and skip ahead.
    const tags = "<a ".repeat(100_000);
    const t0 = Date.now();
    extractMavenCoordinates(comments, "pom.xml");
    extractMavenCoordinates(tags, "pom.xml");
    expect(Date.now() - t0).toBeLessThan(1500);
  });

  it("still reads a pom whose comments and attributes are ordinary", () => {
    const pom = [
      "<project>",
      "  <!-- a comment with <dependency> inside -->",
      '  <dependencies><dependency scope="x">',
      "    <groupId>com.evil</groupId><artifactId>stealer</artifactId><version>1.0.0</version>",
      "  </dependency></dependencies>",
      "</project>",
    ].join("\n");
    expect(extractMavenCoordinates(pom, "pom.xml").map((c) => `${c.group}:${c.artifact}@${c.version}:${c.line}`))
      .toEqual(["com.evil:stealer@1.0.0:3"]);
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
