import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock node:https before importing the module (see solana-monitor.test.ts)
vi.mock("node:https", () => {
  const mockGet = vi.fn();
  return {
    default: { get: mockGet },
    get: mockGet,
  };
});

import * as https from "node:https";
import { resolveVsixDownloadUrl, scanVscodeExtension } from "../vscode-scanner.js";

interface MockResponseSpec {
  status: number;
  body?: string;
  headers?: Record<string, string>;
}

interface CapturedRequestOptions {
  hostname: string;
  path: string;
  headers?: Record<string, string>;
}

/**
 * Helper: configure the mocked https.get to answer sequential requests.
 * Purely metadata/HTTP-level - no zip binary and no real network involved.
 */
function mockHttpResponses(responses: MockResponseSpec[]): void {
  let callIndex = 0;
  const mockedGet = https.get as unknown as ReturnType<typeof vi.fn>;
  mockedGet.mockImplementation(
    (
      _opts: unknown,
      cb: (res: {
        statusCode: number;
        headers: Record<string, string>;
        on: (event: string, handler: (chunk?: Buffer) => void) => void;
        pipe: (dest: unknown) => void;
      }) => void,
    ) => {
      const resp = responses[Math.min(callIndex, responses.length - 1)] ?? {
        status: 500,
      };
      callIndex++;

      cb({
        statusCode: resp.status,
        headers: resp.headers ?? {},
        on(event: string, handler: (chunk?: Buffer) => void) {
          if (event === "data" && resp.body !== undefined) {
            handler(Buffer.from(resp.body));
          }
          if (event === "end") handler();
        },
        pipe: vi.fn(),
      });

      return { on: vi.fn() };
    },
  );
}

/** Helper: options object of the n-th https.get call. */
function requestOptions(callIndex: number): CapturedRequestOptions {
  const mockedGet = https.get as unknown as ReturnType<typeof vi.fn>;
  return mockedGet.mock.calls[callIndex]?.[0] as CapturedRequestOptions;
}

describe("VS Code Extension Scanner - registry support", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("resolveVsixDownloadUrl", () => {
    it("builds the marketplace URL without any metadata request", async () => {
      const url = await resolveVsixDownloadUrl("ms-python.python", "marketplace");

      expect(url).toBe(
        "https://ms-python.gallery.vsassets.io/_apis/public/gallery/publisher/ms-python/extension/python/latest/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage",
      );
      expect(https.get).not.toHaveBeenCalled();
    });

    it("defaults to the marketplace when no registry is given", async () => {
      const url = await resolveVsixDownloadUrl("testpub.testext");

      expect(url).toContain("testpub.gallery.vsassets.io");
      expect(https.get).not.toHaveBeenCalled();
    });

    it("resolves the download URL from Open VSX metadata", async () => {
      const downloadUrl =
        "https://open-vsx.org/api/testpub/testext/1.2.3/file/testpub.testext-1.2.3.vsix";
      mockHttpResponses([
        {
          status: 200,
          body: JSON.stringify({
            namespace: "testpub",
            name: "testext",
            version: "1.2.3",
            files: { download: downloadUrl },
          }),
        },
      ]);

      const url = await resolveVsixDownloadUrl("testpub.testext", "openvsx");

      expect(url).toBe(downloadUrl);
      expect(https.get).toHaveBeenCalledTimes(1);
      expect(requestOptions(0).hostname).toBe("open-vsx.org");
      expect(requestOptions(0).path).toBe("/api/testpub/testext");
    });

    it("follows redirects when fetching Open VSX metadata", async () => {
      const downloadUrl =
        "https://open-vsx.org/api/testpub/testext/2.0.0/file/testpub.testext-2.0.0.vsix";
      mockHttpResponses([
        {
          status: 302,
          headers: { location: "https://open-vsx.org/api/moved/testext" },
        },
        {
          status: 200,
          body: JSON.stringify({ files: { download: downloadUrl } }),
        },
      ]);

      const url = await resolveVsixDownloadUrl("testpub.testext", "openvsx");

      expect(url).toBe(downloadUrl);
      expect(https.get).toHaveBeenCalledTimes(2);
      expect(requestOptions(1).path).toBe("/api/moved/testext");
    });

    it("rejects an unknown Open VSX extension with a 404 error", async () => {
      mockHttpResponses([{ status: 404, body: JSON.stringify({ error: "not found" }) }]);

      await expect(
        resolveVsixDownloadUrl("nosuchpub.nosuchext", "openvsx"),
      ).rejects.toThrow('Extension "nosuchpub.nosuchext" not found on Open VSX (HTTP 404)');
    });

    it("rejects when Open VSX metadata has no files.download URL", async () => {
      mockHttpResponses([
        {
          status: 200,
          body: JSON.stringify({ namespace: "testpub", name: "testext", files: {} }),
        },
      ]);

      await expect(
        resolveVsixDownloadUrl("testpub.testext", "openvsx"),
      ).rejects.toThrow("does not contain a download URL");
    });

    it("rejects when Open VSX returns invalid JSON", async () => {
      mockHttpResponses([{ status: 200, body: "<html>not json</html>" }]);

      await expect(
        resolveVsixDownloadUrl("testpub.testext", "openvsx"),
      ).rejects.toThrow("invalid JSON");
    });

    it("rejects an invalid extension ID on both registries", async () => {
      await expect(resolveVsixDownloadUrl("justaname", "marketplace")).rejects.toThrow(
        "Invalid extension ID format",
      );
      await expect(resolveVsixDownloadUrl("trailingdot.", "openvsx")).rejects.toThrow(
        "Invalid extension ID format",
      );
      expect(https.get).not.toHaveBeenCalled();
    });
  });

  describe("scanVscodeExtension registry threading", () => {
    it("uses the marketplace by default when no registry option is set", async () => {
      mockHttpResponses([{ status: 404 }]);

      await expect(
        scanVscodeExtension({ target: "testpub.testext", format: "text" }),
      ).rejects.toThrow("Download failed with status 404");

      expect(https.get).toHaveBeenCalledTimes(1);
      expect(requestOptions(0).hostname).toBe("testpub.gallery.vsassets.io");
    });

    it("queries Open VSX when registry is openvsx", async () => {
      mockHttpResponses([{ status: 404 }]);

      await expect(
        scanVscodeExtension({
          target: "testpub.testext",
          format: "text",
          registry: "openvsx",
        }),
      ).rejects.toThrow("not found on Open VSX");

      expect(https.get).toHaveBeenCalledTimes(1);
      expect(requestOptions(0).hostname).toBe("open-vsx.org");
      expect(requestOptions(0).path).toBe("/api/testpub/testext");
    });

    it("downloads the .vsix from the URL in the Open VSX metadata", async () => {
      const downloadPath = "/api/testpub/testext/1.2.3/file/testpub.testext-1.2.3.vsix";
      mockHttpResponses([
        {
          status: 200,
          body: JSON.stringify({
            files: { download: `https://open-vsx.org${downloadPath}` },
          }),
        },
        // The download itself fails: proves the metadata URL was used,
        // without needing a zip binary for .vsix extraction.
        { status: 404 },
      ]);

      await expect(
        scanVscodeExtension({
          target: "testpub.testext",
          format: "text",
          registry: "openvsx",
        }),
      ).rejects.toThrow("Download failed with status 404");

      expect(https.get).toHaveBeenCalledTimes(2);
      expect(requestOptions(1).hostname).toBe("open-vsx.org");
      expect(requestOptions(1).path).toBe(downloadPath);
    });
  });

  describe("Open VSX host allowlist", () => {
    it("accepts a files.download URL on the Open VSX blob storage host", async () => {
      const downloadUrl =
        "https://openvsxorg.blob.core.windows.net/resources/testpub/testext/1.0.0/testpub.testext-1.0.0.vsix";
      mockHttpResponses([
        { status: 200, body: JSON.stringify({ files: { download: downloadUrl } }) },
      ]);

      const url = await resolveVsixDownloadUrl("testpub.testext", "openvsx");

      expect(url).toBe(downloadUrl);
    });

    it("accepts a files.download URL on a subdomain of open-vsx.org", async () => {
      const downloadUrl =
        "https://files.open-vsx.org/testpub/testext/1.0.0/testpub.testext-1.0.0.vsix";
      mockHttpResponses([
        { status: 200, body: JSON.stringify({ files: { download: downloadUrl } }) },
      ]);

      const url = await resolveVsixDownloadUrl("testpub.testext", "openvsx");

      expect(url).toBe(downloadUrl);
    });

    it("rejects a files.download URL using http:", async () => {
      mockHttpResponses([
        {
          status: 200,
          body: JSON.stringify({
            files: { download: "http://open-vsx.org/api/testpub/testext/file/x.vsix" },
          }),
        },
      ]);

      await expect(
        resolveVsixDownloadUrl("testpub.testext", "openvsx"),
      ).rejects.toThrow("must use https:");
    });

    it("rejects a files.download URL on a foreign host", async () => {
      mockHttpResponses([
        {
          status: 200,
          body: JSON.stringify({
            files: { download: "https://evil.example.com/testpub.testext.vsix" },
          }),
        },
      ]);

      await expect(
        resolveVsixDownloadUrl("testpub.testext", "openvsx"),
      ).rejects.toThrow('non-allowlisted host "evil.example.com"');
    });

    it("rejects lookalike hosts that only embed the allowlisted name", async () => {
      mockHttpResponses([
        {
          status: 200,
          body: JSON.stringify({
            files: { download: "https://evilopen-vsx.org/x.vsix" },
          }),
        },
      ]);
      await expect(
        resolveVsixDownloadUrl("testpub.testext", "openvsx"),
      ).rejects.toThrow("non-allowlisted host");

      mockHttpResponses([
        {
          status: 200,
          body: JSON.stringify({
            files: { download: "https://open-vsx.org.evil.example.com/x.vsix" },
          }),
        },
      ]);
      await expect(
        resolveVsixDownloadUrl("testpub.testext", "openvsx"),
      ).rejects.toThrow("non-allowlisted host");
    });

    it("rejects a download redirect hop to a foreign host", async () => {
      mockHttpResponses([
        {
          status: 200,
          body: JSON.stringify({
            files: { download: "https://open-vsx.org/api/testpub/testext/file/x.vsix" },
          }),
        },
        {
          status: 302,
          headers: { location: "https://evil.example.com/payload.vsix" },
        },
      ]);

      await expect(
        scanVscodeExtension({
          target: "testpub.testext",
          format: "text",
          registry: "openvsx",
        }),
      ).rejects.toThrow('non-allowlisted host "evil.example.com"');

      // Metadata request + first download hop only; the foreign hop is never fetched.
      expect(https.get).toHaveBeenCalledTimes(2);
    });

    it("follows a download redirect hop that stays on allowlisted hosts", async () => {
      mockHttpResponses([
        {
          status: 200,
          body: JSON.stringify({
            files: { download: "https://open-vsx.org/api/testpub/testext/file/x.vsix" },
          }),
        },
        {
          status: 302,
          headers: {
            location:
              "https://openvsxorg.blob.core.windows.net/resources/testpub/testext/x.vsix",
          },
        },
        // The download itself fails: proves the redirect was followed,
        // without needing a zip binary for .vsix extraction.
        { status: 404 },
      ]);

      await expect(
        scanVscodeExtension({
          target: "testpub.testext",
          format: "text",
          registry: "openvsx",
        }),
      ).rejects.toThrow("Download failed with status 404");

      expect(https.get).toHaveBeenCalledTimes(3);
      expect(requestOptions(2).hostname).toBe("openvsxorg.blob.core.windows.net");
    });

    it("rejects a metadata redirect to a foreign host", async () => {
      mockHttpResponses([
        {
          status: 302,
          headers: { location: "https://evil.example.com/api/testpub/testext" },
        },
      ]);

      await expect(
        resolveVsixDownloadUrl("testpub.testext", "openvsx"),
      ).rejects.toThrow('non-allowlisted host "evil.example.com"');
      expect(https.get).toHaveBeenCalledTimes(1);
    });

    it("leaves the marketplace download path unconstrained", async () => {
      mockHttpResponses([
        {
          status: 302,
          headers: { location: "https://cdn.example.net/some/marketplace/mirror.vsix" },
        },
        { status: 404 },
      ]);

      await expect(
        scanVscodeExtension({ target: "testpub.testext", format: "text" }),
      ).rejects.toThrow("Download failed with status 404");

      // The redirect to the non-Open-VSX CDN host was followed, not rejected.
      expect(https.get).toHaveBeenCalledTimes(2);
      expect(requestOptions(1).hostname).toBe("cdn.example.net");
    });
  });
});
