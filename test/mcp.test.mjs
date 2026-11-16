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
let onBurn = null; // test hook: runs just before the mock deletes a secret
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
        onBurn?.(id);
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
  client = await spawnClient(tmp);
});

const spawnClient = async (cwd) => {
  const c = new Client({ name: 'snappwd-test', version: '0.0.0' });
  await c.connect(new StdioClientTransport({
    command: process.execPath,
    args: [CLI, 'mcp'],
    env: { ...process.env, SNAPPWD_API_URL: apiUrl },
    cwd,
    stderr: 'ignore',
  }));
  return c;
};

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

const createFile = async (name, contents) => {
  const source = path.join(tmp, name);
  fs.writeFileSync(source, contents);
  const created = await call('create_file_secret', { path: source });
  assert.equal(created.isError, false, created.text);
  return created.data.url;
};

test('get_secret refuses a missing output directory without burning the file', async () => {
  const url = await createFile('missing-dir.env', 'SECRET=1');
  const refused = await call('get_secret', { url, output_path: path.join(tmp, 'nope', 'x.env') });
  assert.equal(refused.isError, true);
  assert.match(refused.text, /Cannot write to .*nope.*not opened/);
  assert.equal((await call('peek_secret', { url })).isError, false, 'the secret must survive');
});

test('get_secret refuses an unwritable working directory without burning the file', async (t) => {
  if (process.getuid?.() === 0) return t.skip('root can write to read-only directories');
  const ro = fs.mkdtempSync(path.join(tmp, 'ro-'));
  fs.chmodSync(ro, 0o555);
  const roClient = await spawnClient(ro);
  try {
    const url = await createFile('ro-cwd.env', 'SECRET=2');
    const result = await roClient.callTool({ name: 'get_secret', arguments: { url } });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /Cannot write to .*output_path.*not opened/);
    assert.equal((await call('peek_secret', { url })).isError, false, 'the secret must survive');
  } finally {
    await roClient.close();
    fs.chmodSync(ro, 0o755);
  }
});

test('get_secret saves a burned file to a temp directory when the write fails', async () => {
  const contents = `RACE=${randomBytes(6).toString('hex')}`;
  const url = await createFile('race-source.env', contents);
  const target = path.join(tmp, 'race.env');
  // Simulate a race: the target appears after the pre-check but before the write.
  onBurn = () => fs.writeFileSync(target, 'someone else');
  try {
    const opened = await call('get_secret', { url, output_path: target });
    assert.equal(opened.isError, false, opened.text);
    assert.notEqual(opened.data.saved_to, target);
    assert.equal(path.dirname(path.dirname(opened.data.saved_to)), os.tmpdir());
    assert.match(opened.data.note, /already burned/);
    assert.equal(fs.readFileSync(opened.data.saved_to, 'utf8'), contents);
    assert.equal(fs.statSync(opened.data.saved_to).mode & 0o777, 0o600);
    assert.equal(fs.readFileSync(target, 'utf8'), 'someone else', 'the existing file is not replaced');
    fs.rmSync(path.dirname(opened.data.saved_to), { recursive: true, force: true });
  } finally {
    onBurn = null;
  }
});

test('CLI get does not overwrite an existing file with the stored filename', async () => {
  const run = promisify(execFile);
  const dir = fs.mkdtempSync(path.join(tmp, 'cli-get-'));
  const source = path.join(dir, '.bashrc');
  fs.writeFileSync(source, 'incoming');
  const put = await run(process.execPath, [CLI, 'put-file', source, '--api-url', apiUrl]);
  const url = put.stdout.match(/URL: (\S+)/)[1];
  fs.writeFileSync(source, 'original'); // the recipient's own .bashrc
  const get = await run(process.execPath, [CLI, 'get', url, '--api-url', apiUrl], { cwd: dir });
  const saved = get.stdout.match(/File saved to: (\S+)/)[1];
  assert.notEqual(saved, '.bashrc');
  assert.equal(fs.readFileSync(source, 'utf8'), 'original');
  assert.equal(fs.readFileSync(path.join(dir, saved), 'utf8'), 'incoming');
});

test('server.json versions match package.json', () => {
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const server = JSON.parse(fs.readFileSync('server.json', 'utf8'));
  assert.equal(server.name, pkg.mcpName);
  assert.equal(server.version, pkg.version);
  assert.deepEqual(server.packages.map((p) => [p.identifier, p.version]), [[pkg.name, pkg.version]]);
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
