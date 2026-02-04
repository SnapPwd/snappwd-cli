# SnapPwd CLI

The official command-line interface for [SnapPwd.io](https://snappwd.io).

Share secrets and files securely from your terminal. The CLI performs local encryption (AES-GCM) before uploading, ensuring the server never sees your data or keys.

## Features

- **Zero-Knowledge**: Secrets are encrypted on your machine.
- **Cross-Platform**: Windows, macOS, Linux (via Node.js).
- **Interoperable**: Secrets created via CLI can be opened in the web app.
- **Self-Hostable**: Supports custom backends (e.g., your own [snappwd-service](https://github.com/SnapPwd/snappwd-service)).

## Installation

```bash
npm install -g snappwd-cli
```

## Usage

### Share a Secret

```bash
snappwd put "My secret API key"
# Output: https://snappwd.io/g/uuid...#key...
```

### Share a File

```bash
snappwd put-file ./database.env
```

### Retrieve a Secret

```bash
snappwd get "https://snappwd.io/g/uuid...#key..."
```

## Self-Hosting

If you are running your own [SnapPwd Service](https://github.com/SnapPwd/snappwd-service), point the CLI to it:

```bash
snappwd put "Internal Secret" --api-url "https://secrets.internal.corp/api/v1"
```

You can also set the API URL permanently via environment variable:

```bash
export SNAPPWD_API_URL="https://secrets.internal.corp/api/v1"
snappwd put "Internal Secret"
```

## Security Model

1. **Key Gen**: A random AES key is generated locally.
2. **Encrypt**: Data is encrypted using AES-GCM.
3. **Upload**: Only the encrypted ciphertext is sent to the server.
4. **Link**: The CLI generates a link with the key in the URL fragment (`#`). This key never leaves your machine.

## License

MIT
