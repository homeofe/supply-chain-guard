/**
 * Regression test for Issue #201:
 * Assert that scanning a local directory performs zero outbound network calls.
 * https://github.com/homeofe/supply-chain-guard/issues/201
 */

import { describe, it, expect, vi } from "vitest";
import * as net from "node:net";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import * as fs from "node:fs";
import { scan } from "../scanner.js";

describe("Issue 201: Local scan offline contract", () => {
  it("performs zero network calls when scanning a local directory", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "scg-offline-test-"));

    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify(
        {
          name: "test-pkg",
          version: "1.0.0",
          dependencies: {
            lodash: "^4.17.21",
            express: "^4.18.2",
          },
          devDependencies: {
            vitest: "^1.0.0",
          },
        },
        null,
        2,
      ),
    );
    fs.writeFileSync(
      path.join(tempDir, "index.js"),
      'const _ = require("lodash");\nmodule.exports = { value: 42 };\n',
    );

    const networkCalls: string[] = [];

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      networkCalls.push(`FETCH: ${url}`);
      throw new Error(`Unexpected network fetch to ${url}`);
    });

    const socketSpy = vi.spyOn(net.Socket.prototype, "connect").mockImplementation((...args: any[]) => {
      networkCalls.push(`SOCKET_CONNECT: ${JSON.stringify(args[0])}`);
      throw new Error("Unexpected net.Socket.connect");
    });

    const agentSpy = vi.spyOn(http.Agent.prototype, "createConnection").mockImplementation((...args: any[]) => {
      networkCalls.push(`AGENT_CREATE_CONNECTION: ${JSON.stringify(args[0])}`);
      throw new Error("Unexpected Agent.createConnection");
    });

    try {
      const report = await scan({
        target: tempDir,
        noHistory: true,
      });

      expect(report).toBeDefined();
      expect(networkCalls).toEqual([]);
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(socketSpy).not.toHaveBeenCalled();
      expect(agentSpy).not.toHaveBeenCalled();
    } finally {
      vi.restoreAllMocks();
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
