// ===================== GOD MODE MULTI-TENANT STATIC HOST =====================
// Run: node server.js
// Purpose: Deploy and serve multiple static sites from ZIP uploads (local FS or S3)
// ============================================================================

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const AdmZip = require('adm-zip');
const fs = require('fs');
const path = require('path');
const sanitize = require('sanitize-filename');
const winston = require('winston');
const jwt = require('jsonwebtoken');
const mime = require('mime-types');
const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  ListObjectsV2Command,
  DeleteObjectsCommand
} = require('@aws-sdk/client-s3');

// --------------------------- ENV / CONFIG -----------------------------------
const PORT = parseInt(process.env.PORT || '3000', 10);
const UPLOAD_SECRET = process.env.UPLOAD_SECRET || 'change_me_upload_secret';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'change_me_admin_token';
const JWT_SECRET = process.env.JWT_SECRET || 'change_me_jwt_secret';
const MAX_UPLOAD_BYTES = parseInt(process.env.MAX_UPLOAD_BYTES || '52428800', 10); // 50MB default
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '120', 10);
const USE_S3 = (process.env.USE_S3 || 'false').toLowerCase() === 'true';
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const S3_BUCKET = process.env.S3_BUCKET || '';

// --------------------------- PATHS ------------------------------------------
const ROOT = __dirname;
const TMP_DIR = path.join(ROOT, 'tmp');
const SITES_DIR = path.join(ROOT, 'sites');
const DATA_DIR = path.join(ROOT, 'data');
const SITES_META = path.join(DATA_DIR, 'sites.json');
const BACKUPS_DIR = path.join(ROOT, 'backups');

// Ensure directories exist
[ TMP_DIR, SITES_DIR, DATA_DIR, BACKUPS_DIR ].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// --------------------------- LOGGER -----------------------------------------
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.File({ filename: path.join(ROOT, 'godmode-error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(ROOT, 'godmode-combined.log') })
  ]
});
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({ format: winston.format.simple() }));
}

// --------------------------- AWS S3 CLIENT ---------------------------------
let s3Client = null;
if (USE_S3) s3Client = new S3Client({ region: AWS_REGION });

// --------------------------- EXPRESS APP -----------------------------------
const app = express();
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));

// --------------------------- RATE LIMIT -------------------------------------
app.use(rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false
}));

// --------------------------- MULTER (UPLOADS) -------------------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, TMP_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${sanitize(file.originalname)}`)
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_BYTES },
  fileFilter: (req, file, cb) => {
    if (!file.originalname.match(/\.zip$/i)) return cb(new Error('Only .zip files allowed'), false);
    cb(null, true);
  }
});

// --------------------------- HELPERS ----------------------------------------
function readSitesMeta() {
  try {
    if (!fs.existsSync(SITES_META)) return {};
    return JSON.parse(fs.readFileSync(SITES_META, 'utf8'));
  } catch (e) {
    logger.error('readSitesMeta error', e);
    return {};
  }
}
function writeSitesMeta(obj) {
  const tmp = SITES_META + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), 'utf8');
  fs.renameSync(tmp, SITES_META);
}
function isZipFile(fp) {
  try {
    const fd = fs.openSync(fp, 'r');
    const buf = Buffer.alloc(4);
    fs.readSync(fd, buf, 0, 4, 0);
    fs.closeSync(fd);
    return buf.slice(0,4).toString('binary').startsWith('PK');
  } catch (e) { return false; }
}
function extractZipSafely(zipPath, destDir) {
  const zip = new AdmZip(zipPath);
  for (const entry of zip.getEntries()) {
    const entryName = entry.entryName;
    if (entryName.includes('..') || path.isAbsolute(entryName)) throw new Error('Invalid zip entry path');
    const targetPath = path.join(destDir, entryName);
    const resolved = path.resolve(targetPath);
    if (!resolved.startsWith(path.resolve(destDir))) throw new Error('Zip entry escapes target dir');
    if (entry.isDirectory) {
      if (!fs.existsSync(resolved)) fs.mkdirSync(resolved, { recursive: true });
    } else {
      fs.mkdirSync(path.dirname(resolved), { recursive: true });
      fs.writeFileSync(resolved, entry.getData());
    }
  }
}
async function uploadDirToS3(localDir, prefix) {
  if (!s3Client) throw new Error('S3 not configured');
  const files = [];
  (function walk(dir) {
    for (const f of fs.readdirSync(dir)) {
      const full = path.join(dir, f);
      if (fs.statSync(full).isDirectory()) walk(full);
      else files.push(full);
    }
  })(localDir);
  for (const filePath of files) {
    const rel = path.relative(localDir, filePath).replace(/\\/g, '/');
    const key = `${prefix}/${rel}`;
    await s3Client.send(new PutObjectCommand({
      Bucket: S3_BUCKET,
      Key: key,
      Body: fs.createReadStream(filePath),
      ContentType: mime.lookup(filePath) || 'application/octet-stream'
    }));
    logger.info('Uploaded to S3', { key });
  }
}
async function streamS3ToRes(bucket, key, res) {
  const out = await s3Client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  if (out.ContentType) res.setHeader('content-type', out.ContentType);
  out.Body.pipe(res);
}
function requireAdmin(req, res, next) {
  const token = req.header('x-admin-token') || req.query.admin_token;
  if (!token || token !== ADMIN_TOKEN) return res.status(403).json({ error: 'forbidden' });
  next();
}

// --------------------------- ROUTES ----------------------------------------

// Health check
app.get('/health', (req,res) => {
  const meta = readSitesMeta();
  res.json({ ok: true, uptime: process.uptime(), sites: Object.keys(meta).length });
});

// Root dashboard
app.get('/', (req, res) => {
  const meta = readSitesMeta();
  const sitesList = Object.values(meta)
    .map(s => `<li><a href="/s/${s.client}/" target="_blank">${s.client}</a></li>`)
    .join('') || '<li>No sites deployed yet</li>';

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>🚀 God Mode Server</title>
      <style>
        body { font-family: Arial, sans-serif; background:#111; color:#eee; text-align:center; padding:40px; }
        h1 { color:#0f0; }
        .card { background:#222; border-radius:12px; padding:20px; margin:20px auto; max-width:600px; box-shadow:0 0 10px rgba(0,255,0,0.3); }
        ul { list-style:none; padding:0; }
        li { margin:8px 0; }
        a { color:#0f0; text-decoration:none; font-weight:bold; }
        a:hover { text-decoration:underline; }
      </style>
    </head>
    <body>
      <h1>🚀 God Mode Server</h1>
      <div class="card">
        <p>Uptime: ${process.uptime().toFixed(0)}s</p>
        <p>Sites deployed: ${Object.keys(meta).length}</p>
        <h3>Sites:</h3>
        <ul>${sitesList}</ul>
        <hr>
        <p><a href="/health" target="_blank">/health</a> | 
           <a href="/admin/sites?admin_token=${ADMIN_TOKEN}" target="_blank">/admin/sites</a></p>
      </div>
    </body>
    </html>
  `);
});

// Create client JWT (admin only)
app.post('/admin/create-client-token', requireAdmin, (req,res) => {
  const client = req.body?.client;
  if (!client) return res.status(400).json({ error: 'client required' });
  const clientSafe = sanitize(client).toLowerCase().replace(/\s+/g, '-');
  const token = jwt.sign({ client: clientSafe }, JWT_SECRET, { expiresIn: '365d' });
  const meta = readSitesMeta();
  meta[clientSafe] = meta[clientSafe] || { client: clientSafe, createdAt: new Date().toISOString() };
  writeSitesMeta(meta);
  res.json({ ok: true, token });
});

// Upload ZIP
app.post('/upload', upload.single('site'), async (req,res) => {
  try {
    const headerToken = req.header('x-upload-token') || '';
    let clientFromJwt = null;
    const auth = req.header('authorization');
    if (auth?.startsWith('Bearer ')) {
      try { clientFromJwt = jwt.verify(auth.slice(7), JWT_SECRET).client; } catch {}
    }
    if (headerToken !== UPLOAD_SECRET && !clientFromJwt) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(403).json({ error: 'forbidden' });
    }
    if (!req.file) return res.status(400).json({ error: 'zip file required' });

    const clientRaw = clientFromJwt || req.body?.client;
    if (!clientRaw) { fs.unlinkSync(req.file.path); return res.status(400).json({ error: 'client required' }); }
    const clientSafe = sanitize(clientRaw).toLowerCase().replace(/\s+/g, '-');
    if (!/^[a-z0-9\-_]+$/.test(clientSafe)) { fs.unlinkSync(req.file.path); return res.status(400).json({ error: 'invalid client name' }); }

    if (!isZipFile(req.file.path)) { fs.unlinkSync(req.file.path); return res.status(400).json({ error: 'invalid zip' }); }

    const destDir = path.join(SITES_DIR, clientSafe);
    if (fs.existsSync(destDir)) fs.rmSync(destDir, { recursive: true, force: true });
    fs.mkdirSync(destDir, { recursive: true });

    extractZipSafely(req.file.path, destDir);
    fs.unlinkSync(req.file.path);

    if (!fs.existsSync(path.join(destDir, 'index.html'))) {
      fs.rmSync(destDir, { recursive: true, force: true });
      return res.status(400).json({ error: 'index.html required at root' });
    }

    const meta = readSitesMeta();
    meta[clientSafe] = { client: clientSafe, uploadedAt: new Date().toISOString(), storage: USE_S3 ? 's3' : 'local', urlPath: `/s/${clientSafe}/` };
    writeSitesMeta(meta);

    if (USE_S3) {
      await uploadDirToS3(destDir, clientSafe);
      fs.rmSync(destDir, { recursive: true, force: true });
    }

    logger.info('site-deployed', { client: clientSafe, ip: req.ip });
    res.json({ ok: true, url: `/s/${clientSafe}/` });

  } catch (err) {
    logger.error('upload-error', { msg: err.message });
    res.status(500).json({ error: 'internal' });
  }
});

// Serve site
app.get('/s/:client/*', async (req,res) => {
  const client = sanitize(req.params.client).toLowerCase().replace(/\s+/g, '-');
  const rel = req.params[0] || 'index.html';
  if (USE_S3) {
    try { await streamS3ToRes(S3_BUCKET, `${client}/${rel}`, res); }
    catch { try { await streamS3ToRes(S3_BUCKET, `${client}/index.html`, res); } catch { res.status(404).send('not found'); } }
  } else {
    const filePath = path.join(SITES_DIR, client, rel);
    if (fs.existsSync(filePath)) return res.sendFile(filePath);
    const idx = path.join(SITES_DIR, client, 'index.html');
    if (fs.existsSync(idx)) return res.sendFile(idx);
    res.status(404).send('not found');
  }
});

// Redirect /s/:client → /s/:client/
app.get('/s/:client', (req,res) => {
  res.redirect(301, `/s/${sanitize(req.params.client).toLowerCase()}/`);
});

// Admin list sites
app.get('/admin/sites', requireAdmin, (req,res) => res.json({ sites: readSitesMeta() }));

// Admin delete site
app.delete('/admin/site/:client', requireAdmin, async (req,res) => {
  const client = sanitize(req.params.client).toLowerCase();
  const meta = readSitesMeta();
  if (!meta[client]) return res.status(404).json({ error: 'not found' });
  if (USE_S3) {
    try {
      const out = await s3Client.send(new ListObjectsV2Command({ Bucket: S3_BUCKET, Prefix: `${client}/` }));
      if (out.Contents?.length) {
        await s3Client.send(new DeleteObjectsCommand({
          Bucket: S3_BUCKET,
          Delete: { Objects: out.Contents.map(o => ({ Key: o.Key })) }
        }));
      }
    } catch (err) { logger.error('s3-delete-error', err); }
  } else {
    fs.rmSync(path.join(SITES_DIR, client), { recursive: true, force: true });
  }
  delete meta[client];
  writeSitesMeta(meta);
  res.json({ ok: true });
});

// Admin backup
app.post('/admin/backup', requireAdmin, (req,res) => {
  try {
    const t = Date.now();
    const out = path.join(BACKUPS_DIR, `backup-${t}.zip`);
    const zip = new AdmZip();
    zip.addLocalFolder(SITES_DIR, 'sites');
    zip.writeZip(out);
    res.json({ ok: true, file: `/backups/backup-${t}.zip` });
  } catch (err) {
    res.status(500).json({ error: 'backup failed' });
  }
});

// Admin view backups
app.get('/admin/backups', requireAdmin, (req,res) => {
  const files = fs.readdirSync(BACKUPS_DIR).map(f => ({ file: f, ts: fs.statSync(path.join(BACKUPS_DIR, f)).mtime }));
  res.json({ backups: files });
});

// Error handler
app.use((err, req,res,next) => {
  logger.error('unhandled', { msg: err.message });
  res.status(500).json({ error: 'internal' });
});

// Start server
app.listen(PORT, () => {
  logger.info(`GodMode Server listening on ${PORT}`);
  console.log(`🚀 GodMode Server listening on ${PORT}`);
});
