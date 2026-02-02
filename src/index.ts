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
  .option('--api-url <url>', 'Override default API URL', 'https://snappwd.io/api/v1');

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
      // Construct URL based on API URL domain or default to snappwd.io if strictly API url is overridden but base is different?
      // Actually, if user overrides API URL, they might be self-hosting.
      // Usually the webapp is at root.
      const baseUrl = apiUrl.replace(/\/api\/v1\/?$/, '');
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
      const baseUrl = apiUrl.replace(/\/api\/v1\/?$/, '');
      const shareUrl = `${baseUrl}/file/${response.fileId}#${key}`;

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
      // Expected: /g/{id} or /file/{id}
      
      const type = pathParts[1]; // 'g' or 'file'
      const id = pathParts[2];

      if (!key) {
        throw new Error('No encryption key found in URL fragment');
      }

      if (type === 'g') {
        // Text Secret
        const response = await api.getSecret(id);
        const secret = await decryptData(response.encryptedSecret, key);
        console.log(secret);
      } else if (type === 'file') {
        // File Secret
        const response = await api.getFile(id);
        
        const iv = new Uint8Array(Buffer.from(response.metadata.iv, 'base64'));
        const encryptedData = new Uint8Array(Buffer.from(response.encryptedData, 'base64')).buffer;

        const decryptedBuffer = await decryptFileBuffer(iv, encryptedData, key);

        const outputPath = options.output || response.metadata.originalFilename;
        fs.writeFileSync(outputPath, decryptedBuffer);
        
        console.log(`File saved to: ${outputPath}`);
      } else {
        throw new Error('Unknown secret type in URL (expected /g/ or /file/)');
      }

    } catch (error: any) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program.parse();
