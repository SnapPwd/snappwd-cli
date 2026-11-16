// End-to-end tests for `snappwd mcp` and the CLI against a mock snappwd-service.
// The mock records every request, so the tests can assert that neither the
// plaintext nor the key ever reaches the API. Run with `npm test` (builds first).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const CLI = path.resolve('dist/index.js');
const store = new Map();
const requests = [];
let server;
let apiUrl;
let client;
let tmp;

function startMockService() {
  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, body });
      const send = (status, payload) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(payload));
      };
      const url = new URL(req.url, 'http://mock');
      const match = url.pathname.match(/^\/v1\/(secrets|files)(?:\/([^/]+))?$/);
      if (!match) return send(404, { error: 'Not found' });
      const [, kind, id] = match;

      if (req.method === 'POST' && !id) {
        const payload = JSON.parse(body);
        const newId = (kind === 'files' ? 'spf-' : 'sps-') + randomBytes(8).toString('hex');
        store.set(newId, { kind, payload, createdAt: Math.floor(Date.now() / 1000) });
        return send(200, kind === 'files' ? { fileId: newId } : { secretId: newId });
      }
      if (req.method === 'GET' && id) {
        const entry = store.get(id);
        if (!entry) return send(404, { error: 'Secret not found' });
        if (url.searchParams.get('peek') === 'true') {
          return send(200, {
            createdAt: entry.createdAt,
            ttlSeconds: entry.payload.expiration,
            metadata: entry.payload.metadata ?? null,
          });
        }
        store.delete(id); // one-time
        return send(200, kind === 'files'
          ? { metadata: entry.payload.metadata, encryptedData: entry.payload.encryptedData }
          : { encryptedSecret: entry.payload.encryptedSecret });
      }
      send(405, { error: 'Method not allowed' });
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
}

const call = async (name, args) => {
  const result = await client.callTool({ name, arguments: args });
  const text = result.content[0].text;
  return { isError: !!result.isError, text, data: result.isError ? null : JSON.parse(text) };
};

const keyOf = (url) => new URL(url).hash.slice(1);

// Nothing the API received may contain the plaintext or the key.
const assertNeverSent = (...needles) => {
  for (const r of requests) {
    for (const needle of needles) {
      assert.ok(!r.url.includes(needle), `${r.method} ${r.url} leaked a secret value in the URL`);
      assert.ok(!r.body.includes(needle), `${r.method} ${r.url} leaked a secret value in the body`);
    }
  }
};

before(async () => {
  await startMockService();
  apiUrl = `http://127.0.0.1:${server.address().port}/v1`;
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'snappwd-mcp-'));
  client = new Client({ name: 'snappwd-test', version: '0.0.0' });
  await client.connect(new StdioClientTransport({
    command: process.execPath,
    args: [CLI, 'mcp'],
    env: { ...process.env, SNAPPWD_API_URL: apiUrl },
    cwd: tmp,
    stderr: 'ignore',
  }));
});

after(async () => {
  await client?.close();
  server?.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('lists the four tools with input schemas', async () => {
  const { tools } = await client.listTools();
  const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
  assert.deepEqual(Object.keys(byName).sort(), ['create_file_secret', 'create_secret', 'get_secret', 'peek_secret']);
  assert.deepEqual(byName.create_secret.inputSchema.required, ['text']);
  assert.ok(byName.create_secret.inputSchema.properties.expiration_seconds);
  assert.deepEqual(byName.create_file_secret.inputSchema.required, ['path']);
  assert.deepEqual(byName.peek_secret.inputSchema.required, ['url']);
  assert.deepEqual(byName.get_secret.inputSchema.required, ['url']);
  assert.match(byName.get_secret.description, /BURNS/);
  assert.match(byName.get_secret.description, /enters your context/);
  assert.equal(byName.get_secret.annotations.destructiveHint, true);
  assert.equal(byName.peek_secret.annotations.readOnlyHint, true);
});

test('create_secret -> peek_secret keeps it -> get_secret burns it', async () => {
  const plaintext = `hunter2-${randomBytes(6).toString('hex')}`;
  const created = await call('create_secret', { text: plaintext, expiration_seconds: 300 });
  assert.equal(created.isError, false, created.text);
  assert.match(created.data.url, /\/g\/sps-[0-9a-f]+#\w+$/);
  assert.equal(created.data.expiration_seconds, 300);
  const id = new URL(created.data.url).pathname.split('/').pop();
  assert.equal(store.get(id).payload.expiration, 300);

  const peeked = await call('peek_secret', { url: created.data.url });
  assert.equal(peeked.isError, false, peeked.text);
  assert.equal(peeked.data.type, 'text');
  assert.equal(peeked.data.ttl_seconds, 300);
  assert.ok(store.has(id), 'peek must not burn the secret');

  const opened = await call('get_secret', { url: created.data.url });
  assert.equal(opened.isError, false, opened.text);
  assert.equal(opened.data.secret, plaintext);
  assert.ok(!store.has(id), 'get must burn the secret');

  const again = await call('get_secret', { url: created.data.url });
  assert.equal(again.isError, true);
  assert.match(again.text, /404/);

  assertNeverSent(plaintext, keyOf(created.data.url));
});

test('create_secret uses the default expiration and rejects out-of-range values', async () => {
  const created = await call('create_secret', { text: 'default-expiry' });
  assert.equal(created.data.expiration_seconds, 3600);

  const tooShort = await client.callTool({ name: 'create_secret', arguments: { text: 'x', expiration_seconds: 10 } });
  assert.equal(tooShort.isError, true);
  const tooLong = await client.callTool({ name: 'create_secret', arguments: { text: 'x', expiration_seconds: 2592001 } });
  assert.equal(tooLong.isError, true);
});

test('create_file_secret -> get_secret round-trips a file without leaking it', async () => {
  const contents = `DB_PASSWORD=${randomBytes(12).toString('hex')}\n`;
  const source = path.join(tmp, 'database.env');
  fs.writeFileSync(source, contents);

  const created = await call('create_file_secret', { path: source });
  assert.equal(created.isError, false, created.text);
  assert.match(created.data.url, /\/g\/spf-/);
  assert.equal(created.data.expiration_seconds, 86400);

  const peeked = await call('peek_secret', { url: created.data.url });
  assert.equal(peeked.data.type, 'file');
  assert.equal(peeked.data.metadata.originalFilename, 'database.env');

  // An existing output path is refused before the secret is burned.
  const refused = await call('get_secret', { url: created.data.url, output_path: source });
  assert.equal(refused.isError, true);
  assert.match(refused.text, /already exists/);
  assert.equal((await call('peek_secret', { url: created.data.url })).isError, false);

  const target = path.join(tmp, 'restored.env');
  const opened = await call('get_secret', { url: created.data.url, output_path: target });
  assert.equal(opened.isError, false, opened.text);
  assert.equal(opened.data.saved_to, target);
  assert.equal(fs.readFileSync(target, 'utf8'), contents);
  assert.ok(!opened.text.includes(contents.trim()), 'file contents must not enter the agent context');

  assertNeverSent(contents.trim(), Buffer.from(contents).toString('base64'), keyOf(created.data.url));
});

test('get_secret keeps a stored filename inside the working directory', async () => {
  const source = path.join(tmp, 'payload.txt');
  fs.writeFileSync(source, 'traversal');
  const created = await call('create_file_secret', { path: source });
  const id = new URL(created.data.url).pathname.split('/').pop();
  store.get(id).payload.metadata.originalFilename = '../../escape.txt';

  const opened = await call('get_secret', { url: created.data.url });
  assert.equal(opened.isError, false, opened.text);
  assert.equal(opened.data.saved_to, path.join(fs.realpathSync(tmp), 'escape.txt'));
});

test('CLI put/peek/get still work through the shared code', async () => {
  const run = promisify(execFile);
  const plaintext = `cli-${randomBytes(6).toString('hex')}`;
  const put = await run(process.execPath, [CLI, 'put', plaintext, '-e', '120', '--api-url', apiUrl]);
  const url = put.stdout.match(/URL: (\S+)/)[1];

  const peek = await run(process.execPath, [CLI, 'peek', url, '--json', '--api-url', apiUrl]);
  assert.equal(JSON.parse(peek.stdout).ttlSeconds, 120);

  const get = await run(process.execPath, [CLI, 'get', url, '--api-url', apiUrl]);
  assert.equal(get.stdout.trim(), plaintext);
  await assert.rejects(run(process.execPath, [CLI, 'get', url, '--api-url', apiUrl]));

  assertNeverSent(plaintext, keyOf(url));
});
