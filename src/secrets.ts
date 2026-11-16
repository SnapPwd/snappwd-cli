import fs from 'node:fs';
import path from 'node:path';
import mime from 'mime-types';
import { SnapPwdApi, FileMetadata, SecretPeekResponse } from './api';
import {
  generateEncryptionKey,
  encryptData,
  decryptData,
  encryptFileBuffer,
  decryptFileBuffer,
} from './crypto';

// Shared by the CLI commands and the MCP server, so both encrypt, upload and
// decrypt the same way. Encryption and decryption happen in this process only:
// the API receives ciphertext, and the key stays in the link's URL fragment.

export const DEFAULT_API_URL = 'https://api.snappwd.io/v1';
export const DEFAULT_TEXT_EXPIRATION = 3600;
export const DEFAULT_FILE_EXPIRATION = 86400;

export const getWebUrl = (apiUrl: string) => {
  if (apiUrl.includes('api.snappwd.io')) {
    return 'https://snappwd.io';
  }
  return apiUrl.replace(/\/api\/v1\/?$/, '');
};

export interface ParsedSecretUrl {
  id: string;
  key: string;
  isFile: boolean;
}

/**
 * Extract the secret ID and the key from a share link.
 * Typical paths: /g/sps-123 or /g/spf-123, and /file/spf-123 (legacy).
 */
export function parseSecretUrl(urlStr: string): ParsedSecretUrl {
  const url = new URL(urlStr);
  const key = url.hash.replace('#', '');
  const pathParts = url.pathname.split('/');

  const gIndex = pathParts.indexOf('g');
  const fileIndex = pathParts.indexOf('file');

  let id: string | undefined;

  if (gIndex !== -1 && pathParts[gIndex + 1]) {
    id = pathParts[gIndex + 1];
  } else if (fileIndex !== -1 && pathParts[fileIndex + 1]) {
    id = pathParts[fileIndex + 1];
  }

  if (!id) {
    // Fallback: try last segment if it looks like an ID
    const last = pathParts[pathParts.length - 1];
    if (last && (last.startsWith('sp-') || last.startsWith('sps-') || last.startsWith('spf-'))) {
      id = last;
    }
  }

  if (!id) {
    throw new Error('Could not parse secret ID from URL');
  }

  return { id, key, isFile: id.startsWith('spf-') };
}

export interface CreatedSecret {
  id: string;
  url: string;
  expirationSeconds: number;
  expiresAt: Date;
}

export async function createTextSecret(
  apiUrl: string,
  text: string,
  expiration: number = DEFAULT_TEXT_EXPIRATION
): Promise<CreatedSecret> {
  const api = new SnapPwdApi(apiUrl);

  const key = generateEncryptionKey();
  const encryptedSecret = await encryptData(text, key);
  const response = await api.createSecret(encryptedSecret, expiration);

  return {
    id: response.secretId,
    url: `${getWebUrl(apiUrl)}/g/${response.secretId}#${key}`,
    expirationSeconds: expiration,
    expiresAt: new Date(Date.now() + expiration * 1000),
  };
}

export async function createFileSecret(
  apiUrl: string,
  filePath: string,
  expiration: number = DEFAULT_FILE_EXPIRATION
): Promise<CreatedSecret> {
  const api = new SnapPwdApi(apiUrl);

  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  const buffer = fs.readFileSync(filePath);
  const originalFilename = path.basename(filePath);
  const contentType = mime.lookup(filePath) || 'application/octet-stream';

  const key = generateEncryptionKey();
  const { iv, encryptedData } = await encryptFileBuffer(buffer, key);

  const response = await api.uploadFile(
    {
      originalFilename,
      contentType,
      iv: Buffer.from(iv).toString('base64'),
    },
    Buffer.from(encryptedData).toString('base64'),
    expiration
  );

  return {
    id: response.fileId,
    // Files share the /g/ route
    url: `${getWebUrl(apiUrl)}/g/${response.fileId}#${key}`,
    expirationSeconds: expiration,
    expiresAt: new Date(Date.now() + expiration * 1000),
  };
}

export interface PeekedSecret extends SecretPeekResponse {
  id: string;
  isFile: boolean;
}

/** Fetch a secret's metadata (creation time, TTL) without consuming it. */
export async function peekSecret(apiUrl: string, urlStr: string): Promise<PeekedSecret> {
  const api = new SnapPwdApi(apiUrl);
  const { id, isFile } = parseSecretUrl(urlStr);

  const response = isFile ? await api.getFile(id, true) : await api.getSecret(id, true);

  if ('encryptedSecret' in response || 'encryptedData' in response) {
    // Should not happen if API respects peek=true
    throw new Error('API returned the secret instead of metadata. It might have been burned.');
  }

  return { id, isFile, ...response };
}

export type RetrievedSecret =
  | { kind: 'text'; id: string; text: string }
  | { kind: 'file'; id: string; metadata: FileMetadata; data: Buffer };

/** Fetch and decrypt a secret or file. The server deletes it as it returns it. */
export async function retrieveSecret(apiUrl: string, urlStr: string): Promise<RetrievedSecret> {
  const api = new SnapPwdApi(apiUrl);
  const { id, key, isFile } = parseSecretUrl(urlStr);

  if (!key) {
    throw new Error('No encryption key found in URL fragment');
  }

  if (isFile) {
    const response = await api.getFile(id);

    if (!('encryptedData' in response)) {
      throw new Error('Unexpected response: Received metadata instead of file.');
    }

    const iv = new Uint8Array(Buffer.from(response.metadata.iv, 'base64'));
    const encryptedData = new Uint8Array(Buffer.from(response.encryptedData, 'base64')).buffer;
    const data = await decryptFileBuffer(iv, encryptedData, key);

    return { kind: 'file', id, metadata: response.metadata, data };
  }

  const response = await api.getSecret(id);

  if (!('encryptedSecret' in response)) {
    throw new Error('Unexpected response: Received metadata instead of secret.');
  }

  return { kind: 'text', id, text: await decryptData(response.encryptedSecret, key) };
}

/**
 * The filename stored with a file secret comes from whoever created it and is
 * not authenticated, so keep only its last path segment.
 */
export function safeFilename(originalFilename: string): string {
  const name = path.basename(originalFilename.replace(/\\/g, '/'));
  return name && name !== '.' && name !== '..' ? name : 'snappwd-file';
}
