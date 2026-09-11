#!/usr/bin/env node
/**
 * Expose the local AegisAudit workspace to the LAN without weakening the app.
 *
 * The control service only accepts operator sessions from the loopback
 * interface and validates Host/Origin against its bind address, so a remote
 * browser cannot talk to it directly. This proxy listens on the LAN, forwards
 * to 127.0.0.1, and rewrites Host/Origin to the upstream authority so the
 * service keeps seeing a local, same-origin request. Streaming responses
 * (WatchRun events, artifact downloads) are piped through unchanged.
 *
 * Usage:
 *   node tools/windows/lan-proxy.js --port 8080 --password <secret>
 *   node tools/windows/lan-proxy.js --port 8080            # no password: LAN-wide read/write access
 */
const http = require('http');
const os = require('os');
const { URL } = require('url');

function parseArguments(argv) {
  const options = { port: 8080, host: '0.0.0.0', target: 'http://127.0.0.1:7331', password: '' };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--port') { options.port = Number(value); index += 1; }
    else if (flag === '--host') { options.host = value; index += 1; }
    else if (flag === '--target') { options.target = value; index += 1; }
    else if (flag === '--password') { options.password = value; index += 1; }
    else if (flag === '--help') { console.log(require('fs').readFileSync(__filename, 'utf8').split('*/')[0]); process.exit(0); }
  }
  options.password = options.password || process.env.AEGIS_LAN_PASSWORD || '';
  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
    console.error('invalid --port');
    process.exit(2);
  }
  return options;
}

const options = parseArguments(process.argv.slice(2));
const upstream = new URL(options.target);
const upstreamAuthority = upstream.host;
const required = options.password ? 'Basic ' + Buffer.from('aegis:' + options.password).toString('base64') : '';

const server = http.createServer((request, response) => {
  const started = Date.now();
  if (required && request.headers.authorization !== required) {
    response.writeHead(401, {
      'www-authenticate': 'Basic realm="AegisAudit", charset="UTF-8"',
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
    });
    response.end('AegisAudit: 需要访问口令\n');
    return;
  }
  const headers = Object.assign({}, request.headers);
  delete headers.authorization;
  headers.host = upstreamAuthority;
  if (headers.origin) headers.origin = 'http://' + upstreamAuthority;
  if (headers.referer) {
    headers.referer = String(headers.referer).replace(/^https?:\/\/[^/]+/, 'http://' + upstreamAuthority);
  }
  const forward = http.request({
    host: upstream.hostname,
    port: upstream.port || 80,
    path: request.url,
    method: request.method,
    headers,
  }, (answer) => {
    response.writeHead(answer.statusCode || 502, answer.headers);
    answer.pipe(response);
    answer.on('end', () => {
      if (!response.writableEnded) response.end();
      console.log(`${new Date().toISOString()} ${request.method} ${request.url} -> ${answer.statusCode} ${Date.now() - started}ms`);
    });
  });
  forward.on('error', (error) => {
    if (!response.headersSent) {
      response.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    }
    response.end('upstream error: ' + error.message + '\n');
  });
  request.pipe(forward);
});

server.keepAliveTimeout = 65000;
server.headersTimeout = 70000;
server.listen(options.port, options.host, () => {
  const addresses = Object.values(os.networkInterfaces())
    .flat()
    .filter((entry) => entry && entry.family === 'IPv4' && !entry.internal)
    .map((entry) => entry.address);
  console.log(`AegisAudit LAN proxy listening on ${options.host}:${options.port} -> ${options.target}`);
  console.log(`password: ${options.password ? 'required' : 'NONE (anyone on the network can import and execute targets)'}`);
  for (const address of addresses) console.log(`  http://${address}:${options.port}/`);
});
