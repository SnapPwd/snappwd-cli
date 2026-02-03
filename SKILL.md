---
name: snappwd
description: Securely share secrets and files via CLI (end-to-end encrypted).
homepage: https://snappwd.io
metadata: {"openclaw":{"emoji":"🔐","requires":{"bins":["npm","node"]},"install":[{"id":"npm","kind":"npm","package":"@snappwd/cli","bins":["snappwd"],"label":"Install SnapPwd CLI"}]}}
---

# SnapPwd Skill

Use the `snappwd` CLI to securely share passwords, secrets, and files. All data is encrypted locally before uploading; the server never sees the key.

## Installation

```bash
npm install -g @snappwd/cli
```

## Usage

### Share a Secret (Text)

Encrypts text and returns a one-time shareable URL.

```bash
snappwd put "my super secret password"
# Output: https://snappwd.io/g/uuid#key
```

### Share a File

Encrypts and uploads a file.

```bash
snappwd put-file ./path/to/secret.pdf
# Output: https://snappwd.io/file/uuid#key
```

### Retrieve a Secret

Fetches and decrypts content from a SnapPwd URL.

```bash
snappwd get "https://snappwd.io/g/uuid#key"
```

For files, it will save to the current directory or you can specify output:

```bash
snappwd get "https://snappwd.io/file/uuid#key" -o ./decrypted.pdf
```
