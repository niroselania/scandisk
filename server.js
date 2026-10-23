const fs = require('fs');
const path = require('path');

// Carga opcional de un archivo .env (útil en Windows, sin dependencias extra)
try {
  for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (m && !line.trim().startsWith('#') && process.env[m[1]] === undefined) {
      process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  }
} catch { /* sin .env */ }

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const db = require('./db');
const scanner = require('./scanner');

const API_KEY = process.env.API_KEY;
if (!API_KEY) {
  console.error('Falta la variable de entorno API_KEY');
  process.exit(1);
}
const PORT = process.env.PORT || 3000;
const AUTO_HOURS = parseFloat(process.env.AUTO_SCAN_HOURS || '0') || 0;
const AUTO_TIME = /^\d{1,2}:\d{2}$/.test(process.env.AUTO_SCAN_TIME || '') ? process.env.AUTO_SCAN_TIME : '';

const app = express();
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (req, res) => res.json({ ok: true }));

// ---------- auth ----------
const hash = (s) => crypto.createHash('sha256').update(String(s)).digest();
app.use('/api', (req, res, next) => {
  const key = req.get('x-api-key') || req.query.key;
  if (!key || !crypto.timingSafeEqual(hash(key), hash(API_KEY))) {
    return res.status(401).json({ error: 'API key inválida' });
  }
  next();
});

// ---------- helpers ----------
const esc = (s) => String(s).replace(/[\\%_]/g, '\\$&');

function humanSize(n) {
  if (n == null) return null;
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function fmt(r) {
  if (!r) return null;
  return {
    disk: r.disk,
    path: r.path,
    name: r.name,
    type: r.is_dir ? 'folder' : 'file',
    ext: r.ext || undefined,
    size: r.size,
    size_human: humanSize(r.size),
    files_inside: r.is_dir ? r.files : undefined,
    modified: r.mtime ? new Date(r.mtime * 1000).toISOString() : null,
  };
}

function normPath(p) {
  const s = String(p || '').replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  if (s.split('/').includes('..')) return null;
  return s;
}

function resolveDisk(req, res) {
  const disks = db.prepare('SELECT DISTINCT disk FROM entries').all().map((r) => r.disk);
  if (req.query.disk) return String(req.query.disk);
  if (disks.length === 1) return disks[0];
  res.status(400).json({ error: 'Indicá el parámetro disk', disks });
  return null;
}

// ---------- endpoints ----------

// Resumen general: discos, totales y últimos escaneos
app.get('/api/stats', (req, res) => {
  const disks = db.prepare(`
    SELECT disk, SUM(is_dir = 0) AS files, SUM(is_dir = 1) AS folders,
           SUM(CASE WHEN is_dir = 0 THEN size ELSE 0 END) AS bytes
    FROM entries GROUP BY disk`).all();
  const roots = scanner.getRoots();
  const lastScan = db.prepare('SELECT disk, MAX(finished_at) AS t FROM scans WHERE files IS NOT NULL GROUP BY disk').all();
  disks.forEach((d) => {
    d.size_human = humanSize(d.bytes);
    d.root = roots[d.disk] || null;
    const l = lastScan.find((x) => x.disk === d.disk);
    d.last_scan = l && l.t ? new Date(l.t).toISOString() : null;
  });
  const lastScans = db.prepare('SELECT * FROM scans WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT 10').all()
    .map((s) => ({ ...s, started_at: new Date(s.started_at).toISOString(), finished_at: new Date(s.finished_at).toISOString() }));
  res.json({ disks, last_scans: lastScans, scan: scanner.getState(), auto_scan: { every_hours: AUTO_HOURS || null, daily_at: AUTO_TIME || null } });
});

// Buscar por nombre: ?q=facturas 2023&ext=pdf&type=file|folder&disk=&scope=name|path&limit=50
app.get('/api/search', (req, res) => {
  const q = String(req.query.q || '').trim();
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 500);
  const column = req.query.scope === 'path' ? 'path' : 'name';
  const where = [];
  const params = [];
  for (const t of q.split(/\s+/).filter(Boolean)) {
    where.push(`${column} LIKE ? ESCAPE '\\'`);
    params.push('%' + esc(t) + '%');
  }
  if (req.query.disk) { where.push('disk = ?'); params.push(String(req.query.disk)); }
  if (req.query.ext) { where.push('ext = ?'); params.push(String(req.query.ext).toLowerCase().replace(/^\./, '')); }
  if (req.query.type === 'file') where.push('is_dir = 0');
  if (req.query.type === 'folder') where.push('is_dir = 1');
  if (!where.length) return res.status(400).json({ error: 'Indicá q, ext o type' });

  const sql = `FROM entries WHERE ${where.join(' AND ')}`;
  const total = db.prepare(`SELECT COUNT(*) AS n ${sql}`).get(...params).n;
  const rows = db.prepare(`SELECT * ${sql} ORDER BY is_dir DESC, length(name), name COLLATE NOCASE LIMIT ?`).all(...params, limit);
  res.json({ total, returned: rows.length, results: rows.map(fmt) });
});

// Listar contenido de una carpeta: ?path=Fotos/2020&disk=MiDisco&limit=200&offset=0
app.get('/api/list', (req, res) => {
  const disk = resolveDisk(req, res);
  if (!disk) return;
  const p = normPath(req.query.path);
  if (p === null) return res.status(400).json({ error: 'Ruta inválida' });
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 1000);
  const offset = parseInt(req.query.offset, 10) || 0;

  const total = db.prepare('SELECT COUNT(*) AS n FROM entries WHERE disk = ? AND parent = ?').get(disk, p).n;
  const rows = db.prepare(`SELECT * FROM entries WHERE disk = ? AND parent = ?
    ORDER BY is_dir DESC, name COLLATE NOCASE LIMIT ? OFFSET ?`).all(disk, p, limit, offset);
  if (!total && p && !db.prepare('SELECT 1 FROM entries WHERE disk = ? AND path = ?').get(disk, p)) {
    return res.status(404).json({ error: 'No existe esa carpeta en el índice' });
  }
  res.json({ disk, path: p, total, offset, items: rows.map(fmt) });
});

// Detalle de un archivo o carpeta (en carpetas: top por tamaño y tipos de archivo)
app.get('/api/info', (req, res) => {
  const disk = resolveDisk(req, res);
  if (!disk) return;
  const p = normPath(req.query.path);
  if (p === null) return res.status(400).json({ error: 'Ruta inválida' });

  let entry;
  let isDir = true;
  if (p === '') {
    const agg = db.prepare('SELECT COUNT(*) AS n, SUM(size) AS s FROM entries WHERE disk = ? AND is_dir = 0').get(disk);
    entry = { disk, path: '', name: disk, type: 'disk', size: agg.s || 0, size_human: humanSize(agg.s || 0), files_inside: agg.n };
  } else {
    const row = db.prepare('SELECT * FROM entries WHERE disk = ? AND path = ?').get(disk, p);
    if (!row) return res.status(404).json({ error: 'No existe en el índice' });
    entry = fmt(row);
    isDir = !!row.is_dir;
  }
  const out = { entry };
  if (isDir) {
    const prefix = p ? esc(p) + '/%' : '%';
    out.biggest_items = db.prepare('SELECT * FROM entries WHERE disk = ? AND parent = ? ORDER BY size DESC LIMIT 10').all(disk, p).map(fmt);
    out.by_extension = db.prepare(`SELECT ext, COUNT(*) AS files, SUM(size) AS bytes FROM entries
      WHERE disk = ? AND is_dir = 0 AND path LIKE ? ESCAPE '\\' GROUP BY ext ORDER BY bytes DESC LIMIT 10`)
      .all(disk, prefix).map((r) => ({ ext: r.ext || '(sin extensión)', files: r.files, size_human: humanSize(r.bytes) }));
    out.direct_children = db.prepare('SELECT COUNT(*) AS n FROM entries WHERE disk = ? AND parent = ?').get(disk, p).n;
  } else {
    out.folder = row_parent(p);
  }
  res.json(out);
});

function row_parent(p) { const i = p.lastIndexOf('/'); return i < 0 ? '' : p.slice(0, i); }

// Explorar carpetas del servidor para elegir la ruta: ?path=D:\Datos (vacío = unidades/raíces)
app.get('/api/fs', async (req, res) => {
  try {
    res.json(await scanner.browse(String(req.query.path || '')));
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Lanzar un escaneo (en segundo plano): body {path?: "D:\\Datos", disk?: "MiDisco", force?: false}
// Sin path re-escanea el disco indicado (o todos) con la ruta guardada.
app.post('/api/scan', (req, res) => {
  try {
    const b = req.body || {};
    scanner.start({ path: b.path, disk: b.disk, force: b.force });
    res.status(202).json({ started: true });
  } catch (e) {
    res.status(409).json({ error: e.message });
  }
});

app.get('/api/scan/status', (req, res) => res.json(scanner.getState()));

// Quitar un disco del indice (no toca los archivos reales, solo borra lo indexado)
app.delete('/api/disks/:disk', (req, res) => {
  if (scanner.getState().running) return res.status(409).json({ error: 'Hay un escaneo en curso, espera a que termine' });
  const disk = req.params.disk;
  const known = db.prepare('SELECT 1 FROM entries WHERE disk = ? LIMIT 1').get(disk)
    || db.prepare('SELECT 1 FROM disks WHERE disk = ?').get(disk);
  if (!known) return res.status(404).json({ error: 'Ese disco no esta en el indice' });
  const removed = db.transaction(() => {
    const n = db.prepare('DELETE FROM entries WHERE disk = ?').run(disk).changes;
    db.prepare('DELETE FROM disks WHERE disk = ?').run(disk);
    db.prepare('DELETE FROM scans WHERE disk = ?').run(disk);
    return n;
  })();
  const still = scanner.getRoots()[disk];
  res.json({
    removed_entries: removed,
    warning: still
      ? `La carpeta ${still} sigue montada en /data: si no sacas ese volumen del docker-compose, el disco volvera a aparecer en el proximo escaneo.`
      : null,
  });
});

// ---------- escaneo automático ----------
// AUTO_SCAN_TIME=03:00  -> todos los días a esa hora (hora local del servidor/contenedor)
// AUTO_SCAN_HOURS=24    -> cada N horas
function autoScan(reason) {
  try {
    scanner.start({});
    console.log(`[auto-scan] iniciado (${reason})`);
  } catch (e) {
    console.log(`[auto-scan] omitido: ${e.message}`);
  }
}
if (AUTO_HOURS > 0) setInterval(() => autoScan(`cada ${AUTO_HOURS} h`), AUTO_HOURS * 3600 * 1000);
if (AUTO_TIME) {
  const [h, m] = AUTO_TIME.split(':').map(Number);
  let lastDay = '';
  setInterval(() => {
    const n = new Date();
    if (n.getHours() === h && n.getMinutes() === m && lastDay !== n.toDateString()) {
      lastDay = n.toDateString();
      autoScan(`diario ${AUTO_TIME}`);
    }
  }, 20 * 1000);
}

app.listen(PORT, () => console.log(`disk-index escuchando en :${PORT}`));
