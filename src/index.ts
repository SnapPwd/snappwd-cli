#!/usr/bin/env node
import { Command } from 'commander';
import fs from 'node:fs';
import { VERSION } from './version';
import {
  DEFAULT_API_URL,
  DEFAULT_TEXT_EXPIRATION,
  DEFAULT_FILE_EXPIRATION,
  createTextSecret,
  createFileSecret,
  peekSecret,
  retrieveSecret,
  safeFilename,
} from './secrets';

const program = new Command();

program
  .name('snappwd')
  .description('CLI for SnapPwd - Secure password and secret sharing')
  .version(VERSION)
  .option(
    '--api-url <url>',
    'Override default API URL (or set SNAPPWD_API_URL)',
    process.env.SNAPPWD_API_URL || DEFAULT_API_URL
  );

program
  .command('put <text>')
  .description('Encrypt and share a text secret')
  .option('-e, --expiration <seconds>', 'Expiration time in seconds', String(DEFAULT_TEXT_EXPIRATION))
  .action(async (text, options) => {
    try {
      const apiUrl = program.opts().apiUrl;
      const expiration = parseInt(options.expiration, 10);

      const { url } = await createTextSecret(apiUrl, text, expiration);

      console.log(`Secret created successfully!`);
      console.log(`URL: ${url}`);
    } catch (error: any) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('put-file <filePath>')
  .description('Encrypt and share a file')
  .option('-e, --expiration <seconds>', 'Expiration time in seconds', String(DEFAULT_FILE_EXPIRATION))
  .action(async (filePath, options) => {
    try {
      const apiUrl = program.opts().apiUrl;
      const expiration = parseInt(options.expiration, 10);

      const { url } = await createFileSecret(apiUrl, filePath, expiration);

      console.log(`File uploaded successfully!`);
      console.log(`URL: ${url}`);

    } catch (error: any) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('peek <url>')
  .description('View secret metadata (TTL, creation time) without burning it')
  .option('-j, --json', 'Output valid JSON')
  .action(async (urlStr, options) => {
    try {
      const apiUrl = program.opts().apiUrl;

      const meta = await peekSecret(apiUrl, urlStr);
      const id = meta.id;
      
      if (options.json) {
        console.log(JSON.stringify({
          id,
          createdAt: meta.createdAt,
          ttlSeconds: meta.ttlSeconds,
          metadata: meta.metadata || null
        }, null, 2));
        return;
      }

      console.log(`ID: ${id}`);
      
      if (meta.createdAt > 0) {
        const created = new Date(meta.createdAt * 1000).toLocaleString();
        console.log(`Created: ${created}`);
      }
      
      if (meta.ttlSeconds === -1) {
         console.log('Expires: Never');
      } else if (meta.ttlSeconds === -2) {
         console.log('Status: Expired or Key Missing');
      } else {
         const days = Math.floor(meta.ttlSeconds / 86400);
         const hours = Math.floor((meta.ttlSeconds % 86400) / 3600);
         const minutes = Math.floor((meta.ttlSeconds % 3600) / 60);
         const seconds = meta.ttlSeconds % 60;
         
         const parts = [];
         if (days > 0) parts.push(`${days}d`);
         if (hours > 0) parts.push(`${hours}h`);
         if (minutes > 0) parts.push(`${minutes}m`);
         parts.push(`${seconds}s`);
         
         console.log(`Expires in: ${parts.join(' ')}`);
      }

      if (meta.metadata) {
        console.log('Custom Metadata:', JSON.stringify(meta.metadata, null, 2));
      }

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

      const secret = await retrieveSecret(apiUrl, urlStr);

      if (secret.kind === 'file') {
        const outputPath = options.output || safeFilename(secret.metadata.originalFilename);
        fs.writeFileSync(outputPath, secret.data);
        
        console.log(`File saved to: ${outputPath}`);
      } else {
        console.log(secret.text);
      }

    } catch (error: any) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('mcp')
  .description('Run a local MCP server over stdio, for AI agents (Claude Code, Claude Desktop, Cursor, ...)')
  .action(async () => {
    try {
      // Loaded on demand so the other commands don't pay for the MCP SDK.
      const { runMcpServer } = await import('./mcp');
      await runMcpServer(program.opts().apiUrl);
    } catch (error: any) {
      console.error('Error:', error.message);
      process.exit(1);
    }
  });

program.parse();
