# SnapPwd CLI

A secure, zero-knowledge CLI tool for sharing secrets and files via [SnapPwd.io](https://snappwd.io).

The CLI performs all encryption and decryption locally using AES-128-GCM. The server never sees your raw secrets or your encryption keys.

## Features

- **Zero-Knowledge**: Secrets are encrypted on your machine before uploading.
- **Cross-Platform**: Works on macOS, Linux, and Windows (via Node.js).
- **Compatible**: Secrets created via CLI can be opened in the [SnapPwd web app](https://snappwd.io), and vice versa.
- **File Sharing**: Securely share files with one-time access links.
- **Custom Backends**: Point to your own self-hosted SnapPwd instance.

## Installation

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/SnapPwd/snappwd-cli.git
   cd snappwd-cli
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the project:
   ```bash
   npm run build
   ```

4. Link the command (optional, to use `snappwd` globally):
   ```bash
   npm link
   ```

## Usage

### Share a Text Secret

Encrypt a text string and get a shareable link.

```bash
# If linked:
snappwd put "My ultra secret password"

# Or running directly:
npm start -- put "My ultra secret password"
```

**Output:**
```
https://snappwd.io/g/sp-uuid-123...#base58-key...
```

### Share a File

Encrypt and upload a file.

```bash
snappwd put-file ./sensitive-document.pdf
```

**Output:**
```
https://snappwd.io/file/spf-uuid-456...#base58-key...
```

### Retrieve a Secret

Fetch and decrypt a secret using a SnapPwd link. The CLI automatically detects if it's a text secret or a file.

```bash
snappwd get "https://snappwd.io/g/sp-uuid-123...#base58-key..."
```

**For files**, it will prompt you for a save location or save to the current directory with the original filename.

### Custom API URL

If you are hosting your own instance of SnapPwd, use the `--api-url` flag.

```bash
snappwd put "Secret for local server" --api-url "https://my-snappwd-instance.com/api/v1"
```

## Security Model

1. **Key Generation**: A random 128-bit AES key and 96-bit IV are generated locally.
2. **Encryption**: The secret (or file) is encrypted using AES-GCM.
3. **Upload**: Only the encrypted ciphertext (and IV) is sent to the server. The key remains on your machine.
4. **Sharing**: The CLI constructs a URL containing the ID (server-side reference) and the Key (in the URL fragment).
   - URL fragments (everything after `#`) are never sent to the server by browsers or this CLI.
5. **Decryption**: The recipient uses the Key from the URL to decrypt the ciphertext locally.

## License

MIT
