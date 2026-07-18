# MCP Server

supply-chain-guard ships a zero-dependency [Model Context Protocol](https://modelcontextprotocol.io) server so AI coding agents can vet packages and code BEFORE touching them. It speaks JSON-RPC 2.0 over stdio (newline-delimited JSON, UTF-8); all logging goes to stderr, stdout carries only protocol messages.

Start it with:

```bash
supply-chain-guard mcp
```

## Tools

| Tool | Network | Purpose |
| --- | --- | --- |
| `ioc_lookup` | none (offline) | Check a package name (+ optional exact version) against the bundled threat-intel feed and known-bad version blocklist. Ecosystems: npm, pypi, ruby, composer, nuget. Returns verdict + matched campaign/family. |
| `scan_directory` | none (local FS) | Full static scan (350+ rules) of a local directory. Returns risk score, findings by severity, top 20 findings. |
| `scan_npm_package` | downloads from the npm registry | Scans the latest published version of an npm package without installing it, plus the offline IOC lookup for the requested name/version. |

Recommended agent workflow: call `ioc_lookup` before every `npm install` / `pip install` suggestion (it is instant and offline), `scan_npm_package` before adding a new npm dependency, and `scan_directory` after cloning or downloading third-party code.

## Version pinning guidance

The snippets below use `supply-chain-guard@latest` so the bundled threat-intel feed stays current - for a threat scanner, freshness IS the feature. If your environment requires reproducible toolchains, pin an exact version (e.g. `supply-chain-guard@5.3.0`) and bump it on a schedule; a pinned scanner slowly goes blind to new campaigns.

## Claude Code

Recommended (works in every shell, including PowerShell, and avoids npx
cold-start timeouts on the first MCP connect):

```bash
npm install -g supply-chain-guard
claude mcp add supply-chain-guard supply-chain-guard mcp
```

On bash/zsh you can use the npx one-liner instead:

```bash
claude mcp add supply-chain-guard -- npx -y supply-chain-guard@latest mcp
```

PowerShell note: PowerShell consumes the bare `--` before the claude CLI sees
it, so the one-liner fails there with `error: unknown option '-y'`. Use the
global-install form above on Windows (or quote the token: `'--'`).

Or in `.mcp.json` (project scope):

```json
{
  "mcpServers": {
    "supply-chain-guard": {
      "command": "npx",
      "args": ["-y", "supply-chain-guard@latest", "mcp"]
    }
  }
}
```

## Claude Desktop

Add to `claude_desktop_config.json` (Settings > Developer > Edit Config):

```json
{
  "mcpServers": {
    "supply-chain-guard": {
      "command": "npx",
      "args": ["-y", "supply-chain-guard@latest", "mcp"]
    }
  }
}
```

## Cursor

Add to `.cursor/mcp.json` in your project (or `~/.cursor/mcp.json` globally):

```json
{
  "mcpServers": {
    "supply-chain-guard": {
      "command": "npx",
      "args": ["-y", "supply-chain-guard@latest", "mcp"]
    }
  }
}
```

## Protocol notes

- Implements `initialize` (protocol revisions 2025-06-18, 2025-03-26, 2024-11-05; mirrors the client's requested revision when supported), `notifications/initialized`, `tools/list`, `tools/call`, and `ping`.
- Tool results use the MCP content-array format (`[{ "type": "text", "text": "<json>" }]`); tool execution failures come back as results with `isError: true` so agents can react, while protocol violations use standard JSON-RPC errors (-32700 parse error, -32600 invalid request, -32601 method not found, -32602 invalid params).
- One JSON message per line; the server never writes non-protocol output to stdout.

## Example session

```
-> {"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1.0"}}}
<- {"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"supply-chain-guard","version":"5.3.0"},...}}
-> {"jsonrpc":"2.0","method":"notifications/initialized"}
-> {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ioc_lookup","arguments":{"ecosystem":"npm","name":"event-stream","version":"3.3.6"}}}
<- {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"verdict\":\"malicious\",...}"}]}}
```
