/**
 * Archive extraction helpers.
 *
 * Archive paths can originate from user input. Resolve them to absolute paths
 * and invoke extraction tools directly with an argv array so option-like
 * prefixes and shell metacharacters remain literal path characters.
 */

import { execFileSync } from "node:child_process";
import * as path from "node:path";

export function extractZip(
  archivePath: string,
  extractDir: string,
  overwrite = false,
): void {
  const resolvedArchivePath = path.resolve(archivePath);
  const resolvedExtractDir = path.resolve(extractDir);
  const args = ["-q"];
  if (overwrite) args.push("-o");
  args.push(resolvedArchivePath, "-d", resolvedExtractDir);
  execFileSync("unzip", args, { stdio: "pipe" });
}

export function extractTarGz(archivePath: string, extractDir: string): void {
  const resolvedArchivePath = path.resolve(archivePath);
  const resolvedExtractDir = path.resolve(extractDir);
  execFileSync("tar", ["xzf", resolvedArchivePath, "-C", resolvedExtractDir], {
    stdio: "pipe",
  });
}
