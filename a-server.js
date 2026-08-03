/*
  SVL-071 Reconciliation Console - companion server
  ---------------------------------------------------
  This is the piece a browser cannot do by itself: read files from
  C:\Data\ and append log lines to C:\Logs\. ReconDash.html talks to
  this server over plain HTTP - it never touches the filesystem
  directly.

  What it does:
    GET  /                    -> serves ReconDash.html
    GET  /data/<file>.csv     -> streams C:\Data\<file>.csv
    POST /api/log             -> appends one JSON log entry as a line
                                  to C:\Logs\svl071-console-YYYY-MM-DD.log

  Requirements: Node.js 18+ (no npm packages needed - built-in http
  and fs only, deliberately, so there's nothing to `npm install` on
  a locked-down server box).

  Run:
    node server.js
  Then open:
    http://localhost:8080/

  Configuration:
  Edit the three constants below, or set them as environment
  variables (DATA_DIR, LOG_DIR, PORT) before starting the process -
  e.g. when running as a Windows service via NSSM.
*/

const http = require('http');
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || 'C:\\Data';
const LOG_DIR = process.env.LOG_DIR || 'C:\\Logs';
const PORT = process.env.PORT || 8080;
const HTML_FILE = path.join(__dirname, 'ReconDash.html');

const VALID_LEVELS = new Set(['OFF', 'ERROR', 'WARN', 'INFO', 'DEBUG']);

function send(res, status, body, contentType){
  res.writeHead(status, { 'Content-Type': contentType || 'text/plain; charset=utf-8' });
  res.end(body);
}

function safeCsvPath(fileName){
  // Reject anything that isn't a plain "name.csv" - no slashes, no "..", nothing that
  // could escape DATA_DIR. The console only ever requests names it already knows about
  // (the File Loader schema list), but the endpoint validates independently of that.
  if (!/^[A-Za-z0-9._-]+\.csv$/.test(fileName)) return null;
  const full = path.join(DATA_DIR, fileName);
  if (path.dirname(full) !== path.resolve(DATA_DIR)) return null;
  return full;
}

function ensureDir(dir){
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function appendLogLine(entry){
  ensureDir(LOG_DIR);
  const day = (entry.time || new Date().toISOString()).slice(0, 10);
  const file = path.join(LOG_DIR, `svl071-console-${day}.log`);
  const line = `[${entry.time}] [${entry.level}] ${entry.message}` +
    (entry.meta ? ' ' + JSON.stringify(entry.meta) : '') + '\n';
  fs.appendFile(file, line, (err) => {
    if (err) console.error('Failed to write log entry:', err.message);
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'GET' && url.pathname === '/') {
    fs.readFile(HTML_FILE, (err, data) => {
      if (err) return send(res, 500, 'Could not read ReconDash.html: ' + err.message);
      send(res, 200, data, 'text/html; charset=utf-8');
    });
    return;
  }

  if (req.method === 'GET' && url.pathname.startsWith('/data/')) {
    const fileName = decodeURIComponent(url.pathname.slice('/data/'.length));
    const full = safeCsvPath(fileName);
    if (!full) return send(res, 400, 'Invalid file name.');
    fs.readFile(full, 'utf8', (err, data) => {
      if (err) return send(res, 404, `Not found: ${fileName} (looked in ${DATA_DIR})`);
      send(res, 200, data, 'text/csv; charset=utf-8');
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/log') {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => {
      try {
        const entry = JSON.parse(body);
        if (!entry.time) entry.time = new Date().toISOString();
        if (!VALID_LEVELS.has(entry.level)) entry.level = 'INFO';
        if (typeof entry.message !== 'string') entry.message = String(entry.message || '');
        appendLogLine(entry);
        send(res, 204, '');
      } catch (err) {
        send(res, 400, 'Bad log payload: ' + err.message);
      }
    });
    return;
  }

  send(res, 404, 'Not found.');
});

ensureDir(LOG_DIR);
server.listen(PORT, () => {
  console.log(`SVL-071 console server listening on http://localhost:${PORT}`);
  console.log(`Serving CSVs from: ${DATA_DIR}`);
  console.log(`Writing logs to:   ${LOG_DIR}`);
});
