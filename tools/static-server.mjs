#!/usr/bin/env node
// Plain static-file server for local development and tests.
//
// It deliberately has NO proxy, NO dynamic routes and NO request forwarding:
// it only answers GET/HEAD for files under one directory. Every request's
// method and path (never its body or query values) can be appended to a
// JSON-lines log so tests can prove the hosting origin only served assets.
//
// Usage: node tools/static-server.mjs [--root web] [--port 8080] [--log file]

import { createServer } from 'node:http';
import { createReadStream, appendFileSync, statSync } from 'node:fs';
import { extname, join, normalize, resolve, sep } from 'node:path';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, cur, i, all) => {
    if (cur.startsWith('--')) acc.push([cur.slice(2), all[i + 1]]);
    return acc;
  }, []),
);
const root = resolve(args.root ?? 'web');
const port = Number(args.port ?? 8080);
const logFile = args.log;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.wasm': 'application/wasm',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.txt': 'text/plain; charset=utf-8',
  '.ts': 'text/plain; charset=utf-8',
};

function log(entry) {
  if (logFile) appendFileSync(logFile, JSON.stringify(entry) + '\n');
}

const server = createServer((req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  const entry = { t: Date.now(), method: req.method, path };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    log({ ...entry, status: 405 });
    res.writeHead(405, { Allow: 'GET, HEAD' }).end();
    return;
  }
  let decoded;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    log({ ...entry, status: 400 });
    res.writeHead(400).end();
    return;
  }
  let file = normalize(join(root, decoded));
  if (file !== root && !file.startsWith(root + sep)) {
    log({ ...entry, status: 403 });
    res.writeHead(403).end();
    return;
  }
  try {
    if (statSync(file).isDirectory()) file = join(file, 'index.html');
    const size = statSync(file).size;
    res.writeHead(200, {
      'Content-Type': MIME[extname(file)] ?? 'application/octet-stream',
      'Content-Length': size,
      'Cache-Control': 'no-store',
      // A restrictive policy for our own origin. connect-src lists exactly the
      // Signal origins the client may contact (see VALIDATION_REPORT.md).
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; " +
        "img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; " +
        "connect-src 'self' https://*.signal.org wss://*.signal.org",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    });
    log({ ...entry, status: 200 });
    if (req.method === 'HEAD') return res.end();
    createReadStream(file).pipe(res);
  } catch {
    log({ ...entry, status: 404 });
    res.writeHead(404).end();
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`static-server: serving ${root} at http://localhost:${port}/`);
});
