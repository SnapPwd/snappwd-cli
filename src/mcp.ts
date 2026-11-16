import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { VERSION } from './version';
import {
  DEFAULT_TEXT_EXPIRATION,
  DEFAULT_FILE_EXPIRATION,
  CreatedSecret,
  createTextSecret,
  createFileSecret,
  peekSecret,
  parseSecretUrl,
  retrieveSecret,
  safeFilename,
} from './secrets';

// Local stdio MCP server. It runs the same code paths as `put`, `put-file`,
// `peek` and `get`: secrets are encrypted and decrypted in this process, and
// the API only ever receives ciphertext. Never write to stdout here; stdout
// carries the MCP protocol. Diagnostics go to stderr.

// Limits enforced by snappwd-service; checking them here gives a clearer error.
const MIN_EXPIRATION_SECONDS = 60;
const MAX_EXPIRATION_SECONDS = 2592000; // 30 days

const expirationSchema = (defaultSeconds: number) =>
  z
    .number()
    .int()
    .min(MIN_EXPIRATION_SECONDS)
    .max(MAX_EXPIRATION_SECONDS)
    .optional()
    .describe(
      `Seconds until the link expires if nobody opens it. Default ${defaultSeconds}; ` +
        `min ${MIN_EXPIRATION_SECONDS}, max ${MAX_EXPIRATION_SECONDS} (30 days).`
    );

const json = (value: unknown): CallToolResult => ({
  content: [{ type: 'text', text: JSON.stringify(value, null, 2) }],
});

const toolError = (error: unknown): CallToolResult => ({
  content: [{ type: 'text', text: `Error: ${error instanceof Error ? error.message : String(error)}` }],
  isError: true,
});

const created = (secret: CreatedSecret) => ({
  url: secret.url,
  expires_at: secret.expiresAt.toISOString(),
  expiration_seconds: secret.expirationSeconds,
  note: 'One-time link: it works once, then the secret is deleted. The key is in the #fragment; share the full URL only with the intended recipient.',
});

/**
 * Refuse a file target that cannot be written, before the secret is burned:
 * an existing output_path, or a missing or read-only directory. GUI clients
 * often start the server in a directory the user cannot write to (such as /).
 */
function assertWritableTarget(outputPath: string | undefined): void {
  const target = outputPath ? path.resolve(outputPath) : undefined;
  if (target && fs.existsSync(target)) {
    throw new Error(`Output path already exists: ${target}. The secret was not opened.`);
  }

  const dir = target ? path.dirname(target) : process.cwd();
  try {
    if (!fs.statSync(dir).isDirectory()) {
      throw new Error('not a directory');
    }
    fs.accessSync(dir, fs.constants.W_OK);
  } catch {
    throw new Error(
      `Cannot write to ${dir}. Pass output_path as an absolute path in a writable directory. ` +
        'The secret was not opened.'
    );
  }
}

export function createMcpServer(apiUrl: string): McpServer {
  const server = new McpServer(
    { name: 'snappwd', version: VERSION },
    {
      instructions:
        'SnapPwd shares secrets and files as one-time, expiring links. Encryption happens locally in this ' +
        'server; the SnapPwd API only stores ciphertext and never receives the key. Use create_secret or ' +
        'create_file_secret instead of pasting credentials into chat, email or tickets. Use peek_secret to ' +
        'check a link without consuming it. Only call get_secret when the user asks to open a link: it ' +
        'burns the secret and puts its plaintext into your context.',
    }
  );

  server.registerTool(
    'create_secret',
    {
      title: 'Create a one-time secret link',
      description:
        'Encrypt a text secret (password, API key, token, note) locally and return a one-time SnapPwd link. ' +
        'The link can be opened once, in a browser or with get_secret, and expires after expiration_seconds ' +
        'if unopened. Only ciphertext is uploaded; the decryption key exists only in the link fragment.',
      inputSchema: {
        text: z.string().min(1).describe('The secret text to share.'),
        expiration_seconds: expirationSchema(DEFAULT_TEXT_EXPIRATION),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async ({ text, expiration_seconds }) => {
      try {
        return json(created(await createTextSecret(apiUrl, text, expiration_seconds ?? DEFAULT_TEXT_EXPIRATION)));
      } catch (error) {
        return toolError(error);
      }
    }
  );

  server.registerTool(
    'create_file_secret',
    {
      title: 'Create a one-time file link',
      description:
        'Encrypt a local file and return a one-time SnapPwd link to it. Pass an absolute path; relative paths ' +
        `resolve against the server's working directory (${process.cwd()}). The file contents are encrypted ` +
        'before upload; the original filename and content type are stored unencrypted.',
      inputSchema: {
        path: z.string().min(1).describe('Path of the file to share. Prefer an absolute path.'),
        expiration_seconds: expirationSchema(DEFAULT_FILE_EXPIRATION),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    async ({ path: filePath, expiration_seconds }) => {
      try {
        const resolved = path.resolve(filePath);
        return json(created(await createFileSecret(apiUrl, resolved, expiration_seconds ?? DEFAULT_FILE_EXPIRATION)));
      } catch (error) {
        return toolError(error);
      }
    }
  );

  server.registerTool(
    'peek_secret',
    {
      title: 'Check a secret link without opening it',
      description:
        'Return the metadata of a SnapPwd link (creation time, time left, and for files the filename and ' +
        'content type) WITHOUT consuming it. The link stays usable. Fails if the secret was already opened ' +
        'or has expired.',
      inputSchema: {
        url: z.string().url().describe('The SnapPwd link. The #key fragment is not needed and is not sent.'),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ url }) => {
      try {
        const meta = await peekSecret(apiUrl, url);
        return json({
          id: meta.id,
          type: meta.isFile ? 'file' : 'text',
          created_at: meta.createdAt > 0 ? new Date(meta.createdAt * 1000).toISOString() : null,
          ttl_seconds: meta.ttlSeconds,
          expires_at: meta.ttlSeconds >= 0 ? new Date(Date.now() + meta.ttlSeconds * 1000).toISOString() : null,
          metadata: meta.metadata || null,
        });
      } catch (error) {
        return toolError(error);
      }
    }
  );

  server.registerTool(
    'get_secret',
    {
      title: 'Open (burn) a secret link',
      description:
        'Retrieve and decrypt a SnapPwd link. This BURNS the secret: the server deletes it as it returns it, ' +
        'so the link stops working for everyone, including the intended recipient. For a text secret the ' +
        'decrypted plaintext is returned and enters your context. For a file, the decrypted file is saved ' +
        'to disk (output_path, or its original filename in the working directory) and only its path is ' +
        'returned. Use peek_secret to check a link without burning it.',
      inputSchema: {
        url: z.string().url().describe('The full SnapPwd link, including the #key fragment.'),
        output_path: z
          .string()
          .min(1)
          .optional()
          .describe('File links only: where to save the decrypted file. Must not exist yet. Prefer an absolute path.'),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async ({ url, output_path }) => {
      try {
        // Everything that can be checked is checked before the secret is burned.
        if (parseSecretUrl(url).isFile) {
          assertWritableTarget(output_path);
        }

        const secret = await retrieveSecret(apiUrl, url);

        if (secret.kind === 'text') {
          return json({ id: secret.id, type: 'text', secret: secret.text });
        }

        let outputPath = path.resolve(output_path || safeFilename(secret.metadata.originalFilename));
        if (!output_path && fs.existsSync(outputPath)) {
          const { name, ext } = path.parse(outputPath);
          outputPath = path.join(path.dirname(outputPath), `${name}-${secret.id}${ext}`);
        }

        // The secret is burned now, so a failed write must not lose it
        // (race, full disk, collision): fall back to a private temp directory.
        let note: string | undefined;
        try {
          fs.writeFileSync(outputPath, secret.data, { flag: 'wx', mode: 0o600 });
        } catch (writeError) {
          const fallbackDir = fs.mkdtempSync(path.join(os.tmpdir(), 'snappwd-'));
          const fallbackPath = path.join(fallbackDir, path.basename(outputPath));
          fs.writeFileSync(fallbackPath, secret.data, { flag: 'wx', mode: 0o600 });
          note =
            `Could not write ${outputPath} (${writeError instanceof Error ? writeError.message : String(writeError)}). ` +
            `The secret is already burned, so the file was saved to ${fallbackPath} instead.`;
          outputPath = fallbackPath;
        }

        return json({
          id: secret.id,
          type: 'file',
          saved_to: outputPath,
          original_filename: secret.metadata.originalFilename,
          content_type: secret.metadata.contentType,
          size_bytes: secret.data.length,
          ...(note ? { note } : {}),
        });
      } catch (error) {
        return toolError(error);
      }
    }
  );

  return server;
}

export async function runMcpServer(apiUrl: string): Promise<void> {
  const server = createMcpServer(apiUrl);
  await server.connect(new StdioServerTransport());
  console.error(`SnapPwd MCP server ${VERSION} running on stdio (API: ${apiUrl})`);
}
