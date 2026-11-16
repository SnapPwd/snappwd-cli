# SnapPwd CLI

[![npm version](https://img.shields.io/npm/v/@snappwd/cli)](https://www.npmjs.com/package/@snappwd/cli)
[![npm downloads](https://img.shields.io/npm/dm/@snappwd/cli)](https://www.npmjs.com/package/@snappwd/cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Live App](https://img.shields.io/badge/Live_App-snappwd.io-00C853)](https://www.snappwd.io)

The official command-line interface for [SnapPwd](https://www.snappwd.io).

Share secrets and files securely from your terminal. The CLI encrypts the secret text or file contents locally (AES-GCM) before uploading, and the decryption key is never sent to the API. For files, the filename and content type are uploaded unencrypted (see [Security Model](#security-model)).

Full documentation: [snappwd.io/docs/cli](https://www.snappwd.io/docs/cli)

## Quick Start

No install needed, run it with `npx`:

```bash
npx @snappwd/cli put "My secret API key"
```

```
Secret created successfully!
URL: https://snappwd.io/g/sps-...#...
```

Send the URL to the recipient. It can be opened once, in the hosted web app or with `snappwd get`.

## Features

- **Zero-Knowledge**: Secret text and file contents are encrypted on your machine; the API never receives the key.
- **Cross-Platform**: Windows, macOS, Linux (via Node.js).
- **Interoperable**: Secrets created with the default hosted API can be opened in the hosted web app at [snappwd.io](https://www.snappwd.io).
- **Self-Hostable**: Supports custom backends (e.g., your own [snappwd-service](https://github.com/SnapPwd/snappwd-service)).

## Installation

```bash
npm install -g @snappwd/cli
```

This installs the `snappwd` command. Every example below also works without installing, by replacing `snappwd` with `npx @snappwd/cli`.

## Usage

| Command | What it does |
|---------|--------------|
| `snappwd put <text>` | Encrypt and share a text secret |
| `snappwd put-file <filePath>` | Encrypt and share a file |
| `snappwd peek <url>` | Show a secret's metadata without consuming it |
| `snappwd get <url>` | Retrieve and decrypt a secret or file (consumes it) |
| `snappwd mcp` | Run a local MCP server for AI agents (see [Use with AI Agents](#use-with-ai-agents-mcp)) |

Run `snappwd --help` or `snappwd <command> --help` for the built-in reference.

### Share a Secret

```bash
snappwd put "My secret API key"
```

```
Secret created successfully!
URL: https://snappwd.io/g/sps-...#...
```

Text secrets expire after 1 hour by default. Set a different lifetime in seconds with `-e` / `--expiration`:

```bash
# Expires in 5 minutes
snappwd put "My secret API key" --expiration 300
```

### Share a File

```bash
snappwd put-file ./database.env
```

```
File uploaded successfully!
URL: https://snappwd.io/g/spf-...#...
```

Files expire after 24 hours by default. `-e` / `--expiration` works the same way:

```bash
# Expires in 10 minutes
snappwd put-file ./database.env -e 600
```

### Check a Secret Without Opening It

`peek` shows when a secret was created and how long it has left. It does not consume the secret.

```bash
snappwd peek "https://snappwd.io/g/sps-...#..."
```

```
ID: sps-...
Created: 10/8/2026, 8:27:48 PM
Expires in: 59m 41s
```

Add `-j` / `--json` for machine-readable output:

```bash
snappwd peek "https://snappwd.io/g/sps-...#..." --json
```

```json
{
  "id": "sps-...",
  "createdAt": 1791491268,
  "ttlSeconds": 3579,
  "metadata": null
}
```

For files, `metadata` holds the original filename and content type. These are stored unencrypted and are visible to anyone who has the secret's ID, with or without the key.

### Retrieve a Secret

```bash
snappwd get "https://snappwd.io/g/sps-...#..."
```

The decrypted text is printed to stdout. Retrieval is one-time: the server deletes the secret as it returns it, so a second `get` fails with a 404.

For a file link, `get` saves the decrypted file under its original filename in the current directory. Choose another path with `-o` / `--output`:

```bash
snappwd get "https://snappwd.io/g/spf-...#..." -o ./restored.env
```

Quote the URL so your shell keeps the `#...` part, which carries the decryption key.

## Use with AI Agents (MCP)

`snappwd mcp` runs a local [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, so Claude Code, Claude Desktop, Cursor, Codex and other MCP clients can create and open one-time links directly.

**Claude Code:**

```bash
claude mcp add snappwd -- npx -y @snappwd/cli mcp
```

**Claude Desktop, Cursor and other clients** (`claude_desktop_config.json`, `.cursor/mcp.json`, ...):

```json
{
  "mcpServers": {
    "snappwd": {
      "command": "npx",
      "args": ["-y", "@snappwd/cli", "mcp"]
    }
  }
}
```

| Tool | What it does |
|------|--------------|
| `create_secret` | Encrypt `text` and return a one-time link. Optional `expiration_seconds` (default 3600, 60 to 2592000) |
| `create_file_secret` | Encrypt the file at `path` and return a one-time link. Optional `expiration_seconds` (default 86400) |
| `peek_secret` | Show a link's creation time and time left without consuming it |
| `get_secret` | Open a link. This burns the secret, and for text the plaintext enters the agent's context. Files are saved to disk (`output_path`, or the original filename in the working directory) |

Zero-knowledge holds here too: the MCP server is the same local process as the CLI. It encrypts and decrypts on your machine, the API only receives ciphertext, and the key stays in the link's `#` fragment. There is no hosted MCP endpoint.

To use a self-hosted service, set `SNAPPWD_API_URL` (for example `"env": { "SNAPPWD_API_URL": "http://localhost:8080/v1" }`) or pass `--api-url` before `mcp`: `npx -y @snappwd/cli --api-url http://localhost:8080/v1 mcp`.

## Self-Hosting

If you are running your own [SnapPwd Service](https://github.com/SnapPwd/snappwd-service), point the CLI to it with `--api-url`. The value is the service's base URL including `/v1`; the default is `https://api.snappwd.io/v1`.

```bash
snappwd put "Internal Secret" --api-url "http://localhost:8080/v1"
```

`--api-url` works with every command. You can also set it once with the `SNAPPWD_API_URL` environment variable:

```bash
snappwd get "http://localhost:8080/v1/g/sps-...#..." --api-url "http://localhost:8080/v1"
```

Retrieve self-hosted shares with `snappwd get` and the same `--api-url`. The printed link is built from the API URL (with a trailing `/api/v1` removed), so it is not a browser address. The current self-hosted web client, [snappwd-web](https://github.com/SnapPwd/snappwd-web), cannot reveal shares created by the CLI: it uses a different link and ciphertext format.

See the [self-hosting guide](https://www.snappwd.io/docs/self-hosting) for running the full stack.

## Security Model

1. **Key Gen**: A random AES key is generated locally.
2. **Encrypt**: Data is encrypted using AES-GCM.
3. **Upload**: The encrypted payload is sent to the server. For files, the original filename and content type are sent with it unencrypted, and anyone who has the ID can read them (for example with `snappwd peek`) without the key.
4. **Link**: The CLI generates a link with the key in the URL fragment (`#`). The key is not included in any API request, but it travels with the link: anyone who has the complete link can decrypt the secret, so share it only with the intended recipient.

## License

[MIT](LICENSE)
