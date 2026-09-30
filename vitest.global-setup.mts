// Removes the per-run test cache directory when the run ends. Without this,
// every test run left one scg-vitest-cache-<pid> directory in the system temp
// directory behind (measured on a Linux runner and on a Windows workstation).
import * as fs from "node:fs";
import { testCacheRoot } from "./vitest.test-cache.mts";

export default function setup(): () => void {
  return () => {
    fs.rmSync(testCacheRoot, { recursive: true, force: true });
  };
}
