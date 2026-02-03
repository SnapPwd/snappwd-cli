#!/usr/bin/env node
import { Command } from 'commander';
import fs from 'node:fs';
import path from 'node:path';
import mime from 'mime-types';
import { SnapPwdApi } from './api';
import {
  generateEncryptionKey,
  encryptData,
  decryptData,
  encryptFileBuffer,
  decryptFileBuffer,
  base58Encode,
  base58Decode
} from './crypto';

const program = new Command();

program
  .name('snappwd')
  .description('CLI for SnapPwd - Secure password and secret sharing')
  .version('1.0.0')
  .option('--api-url <url>', 'Override default API URL', 'https://api.snappwd.io/v1');

const getWebUrl = (apiUrl: string) => {
  if (apiUrl.includes('api.snappwd.io')) {
    return 'https://snappwd.io';
  }
  return apiUrl.replace(/\/api\/v1\/?$/, '');
};

program
  .command('put <text>')
  .description('Encrypt and share a text secret')
  .option('-e, --expiration <seconds>', 'Expiration time in seconds', '3600')
  .action(async (text, options) => {
    try {
      const apiUrl = program.opts().apiUrl;
      const api = new SnapPwdApi(apiUrl);
      const expiration = parseInt(options.expiration, 10);

      // 1. Generate Key
      const key = generateEncryptionKey();

      // 2. Encrypt
      const encryptedSecret = await encryptData(text, key);

      // 3. Upload
      const response = await api.createSecret(encryptedSecret, expiration);

      // 4. Output URL
      const baseUrl = getWebUrl(apiUrl);
      const shareUrl = `${baseUrl}/g/${response.secretId}#${key}`;

      console.log(`Secret created successfully!`);
      console.log(`URL: ${shareUrl}`);
    } catch (error: any) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('put-file <filePath>')
  .description('Encrypt and share a file')
  .option('-e, --expiration <seconds>', 'Expiration time in seconds', '86400')
  .action(async (filePath, options) => {
    try {
      const apiUrl = program.opts().apiUrl;
      const api = new SnapPwdApi(apiUrl);
      const expiration = parseInt(options.expiration, 10);

      if (!fs.existsSync(filePath)) {
        throw new Error(`File not found: ${filePath}`);
      }

      const buffer = fs.readFileSync(filePath);
      const originalFilename = path.basename(filePath);
      const contentType = mime.lookup(filePath) || 'application/octet-stream';

      // 1. Generate Key
      const key = generateEncryptionKey();

      // 2. Encrypt
      const { iv, encryptedData } = await encryptFileBuffer(buffer, key);

      // 3. Prepare upload
      const ivBase64 = Buffer.from(iv).toString('base64');
      const encryptedBase64 = Buffer.from(encryptedData).toString('base64');

      const response = await api.uploadFile(
        {
          originalFilename,
          contentType,
          iv: ivBase64,
        },
        encryptedBase64,
        expiration
      );

      // 4. Output URL
      const baseUrl = getWebUrl(apiUrl);
      // Files now share the /g/ route
      const shareUrl = `${baseUrl}/g/${response.fileId}#${key}`;

      console.log(`File uploaded successfully!`);
      console.log(`URL: ${shareUrl}`);

    } catch (error: any) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('get <url>')
  .description('Retrieve and decrypt a secret from a URL')
  .option('-o, --output <path>', 'Output path for file (defaults to original filename)')
  .action(async (urlStr, options) => {
    try {
      const apiUrl = program.opts().apiUrl;
      const api = new SnapPwdApi(apiUrl);

      // Parse URL
      const url = new URL(urlStr);
      const key = url.hash.replace('#', '');
      const pathParts = url.pathname.split('/');
      
      // Look for ID in path segments
      // Typical paths: /g/sp-123 or /file/spf-123 (legacy)
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
         if (last && (last.startsWith('sp-') || last.startsWith('spf-'))) {
             id = last;
         }
      }

      if (!key) {
        throw new Error('No encryption key found in URL fragment');
      }

      if (!id) {
        throw new Error('Could not parse secret ID from URL');
      }

      // Detect type by ID prefix
      if (id.startsWith('spf-')) {
        // File Secret
        const response = await api.getFile(id);
        
        const iv = new Uint8Array(Buffer.from(response.metadata.iv, 'base64'));
        const encryptedData = new Uint8Array(Buffer.from(response.encryptedData, 'base64')).buffer;

        const decryptedBuffer = await decryptFileBuffer(iv, encryptedData, key);

        const outputPath = options.output || response.metadata.originalFilename;
        fs.writeFileSync(outputPath, decryptedBuffer);
        
        console.log(`File saved to: ${outputPath}`);
      } else {
        // Text Secret (default)
        const response = await api.getSecret(id);
        const secret = await decryptData(response.encryptedSecret, key);
        console.log(secret);
      }

    } catch (error: any) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program.parse();
