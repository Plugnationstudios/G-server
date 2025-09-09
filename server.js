// ===================== G SERVER | PLUGNATION STUDIOS =====================
// Author: Marshall Junior Kyalla
// Purpose: Multi-tenant static hosting with MPESA monetization & futuristic dashboard
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
const nodemailer = require('nodemailer');
const { Server } = require('socket.io');
const http = require('http');

// ------------------- ENV -------------------
const PORT = parseInt(process.env.PORT || '3000', 10);
const UPLOAD_SECRET = process.env.UPLOAD_SECRET;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const JWT_SECRET = process.env.JWT_SECRET;
const MAX_UPLOAD_BYTES = parseInt(process.env.MAX_UPLOAD_BYTES || '52428800', 10);
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '120', 10);

// MPESA config
const MPESA_CONSUMER_KEY = process.env.MPESA_CONSUMER_KEY;
const MPESA_CONSUMER_SECRET = process.env.MPESA_CONSUMER_SECRET;
const MPESA_SHORTCODE = process.env.MPESA_SHORTCODE;
const MPESA_PASSKEY = process.env.MPESA_PASSKEY;
const MPESA_CALLBACK_URL = process.env.MPESA_CALLBACK_URL;

// Optional S3 storage
const USE_S3 = process.env.USE_S3 === 'true';
const S3_BUCKET = process.env.S3_BUCKET;
const AWS_REGION = process.env.AWS_REGION;

// ------------------- PATHS -------------------
const ROOT = __dirname;
const TMP_DIR = path.join(ROOT, 'tmp');
const SITES_DIR = path.join(ROOT, 'sites');
const DATA_DIR = path.join(ROOT, 'data');
const SITES_META = path.join(DATA_DIR, 'sites.json');
const CLIENTS_META = path.join(DATA_DIR, 'clients.json');
const BACKUPS_DIR = path.join(ROOT, 'backups');

// Ensure directories
[ TMP_DIR, SITES_DIR, DATA_DIR, BACKUPS_DIR ].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});
if (!fs.existsSync(CLIENTS_META)) fs.writeFileSync(CLIENTS_META,'{}');
if (!fs.existsSync(SITES_META)) fs.writeFileSync(SITES_META,'{}');

// ------------------- LOGGER -------------------
const logger = winston.createLogger({
  level:'info',
  format:winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports:[
    new winston.transports.File({ filename:path.join(ROOT,'gserver-error.log'), level:'error' }),
    new winston.transports.File({ filename:path.join(ROOT,'gserver-combined.log') })
  ]
});
if(process.env.NODE_ENV!=='production') logger.add(new winston.transports.Console({ format:winston.format.simple() }));

// ------------------- EXPRESS -------------------
const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit:'1mb' }));
app.use(morgan('combined',{ stream:{ write: msg => logger.info(msg.trim()) } }));

// ------------------- RATE LIMIT -------------------
app.use(rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false
}));

// ------------------- MULTER -------------------
const storage = multer.diskStorage({
  destination:(req,file,cb)=>cb(null,TMP_DIR),
  filename:(req,file,cb)=>cb(null,`${Date.now()}-${sanitize(file.originalname)}`)
});
const upload = multer({ storage, limits:{ fileSize: MAX_UPLOAD_BYTES } });

// ------------------- HELPERS -------------------
function readJSON(file){ try{ return JSON.parse(fs.readFileSync(file,'utf8')); }catch(e){ return {}; } }
function writeJSON(file,obj){ fs.writeFileSync(file,file+'.tmp',JSON.stringify(obj,null,2)); fs.renameSync(file+'.tmp',file); }
function isZipFile(fp){ try{ const fd=fs.openSync(fp,'r'); const buf=Buffer.alloc(4); fs.readSync(fd,buf,0,4,0); fs.closeSync(fd); return buf.slice(0,4).toString('binary').startsWith('PK'); }catch(e){return false;} }
function extractZipSafely(zipPath,destDir){ const zip=new AdmZip(zipPath); for(const entry of zip.getEntries()){ const entryName=entry.entryName; if(entryName.includes('..')||path.isAbsolute(entryName)) throw new Error('Invalid zip entry'); const target=path.join(destDir,entryName); if(!path.resolve(target).startsWith(path.resolve(destDir))) throw new Error('Zip escapes target dir'); if(entry.isDirectory){ if(!fs.existsSync(target)) fs.mkdirSync(target,{recursive:true}); } else { fs.mkdirSync(path.dirname(target),{recursive:true}); fs.writeFileSync(target,entry.getData()); } } }
function requireAdmin(req,res,next){ const token=req.header('x-admin-token')||req.query.admin_token; if(!token||token!==ADMIN_TOKEN) return res.status(403).json({error:'forbidden'}); next(); }

// ------------------- EMAIL -------------------
const transporter = nodemailer.createTransport({
  service:'gmail',
  auth:{ user:'plugnationstudios@gmail.com', pass:process.env.EMAIL_PASSWORD }
});
function sendNotification(to,subject,text){ transporter.sendMail({ from:'PlugNation Studios <plugnationstudios@gmail.com>', to, subject, text }); }

// ------------------- SOCKET.IO -------------------
io.on('connection', socket=>{
  console.log('Client connected');
  socket.emit('init',{ clients: readJSON(CLIENTS_META), sites: readJSON(SITES_META) });
});

// ------------------- DASHBOARD -------------------
app.get('/',(req,res)=>{
  const sites=readJSON(SITES_META), clients=readJSON(CLIENTS_META);
  let sitesList = Object.values(sites).map(s=>`<li>${s.client} - ${s.uploadedAt}</li>`).join('')||'<li>No sites yet</li>';
  let clientsList = Object.values(clients).map(c=>{
    const glow=c.paid?'glow':'';
    return `<div class="client-card ${glow}">${c.client} - Tier:${c.tier} - Joined:${c.joined}</div>`;
  }).join('')||'<p>No clients yet</p>';

  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>G Server Dashboard</title>
    <style>
      body{margin:0;padding:0;background:#000;color:#ffd700;font-family:Orbitron,sans-serif;text-align:center;overflow:hidden;}
      canvas{position:fixed;top:0;left:0;z-index:-1;}
      .client-card{display:inline-block;background:#111;padding:15px;margin:10px;border-radius:15px;box-shadow:0 0 10px #ff0;transition:0.5s;}
      .glow{animation:glowPulse 2s infinite alternate;}
      @keyframes glowPulse{0%{box-shadow:0 0 15px #ff0;}100%{box-shadow:0 0 40px #fff;}}
      .chart-container{margin:20px auto;width:80%;max-width:900px;}
      .notification{padding:15px;background:#222;margin:10px;border-radius:10px;animation:notifyGlow 3s infinite alternate;}
      @keyframes notifyGlow{0%{box-shadow:0 0 10px #ffd700;}100%{box-shadow:0 0 30px #ff6600;}}
    </style>
  </head>
  <body>
    <h1>🚀 G Server Dashboard</h1>
    <h2>Sites Deployed</h2><ul>${sitesList}</ul>
    <h2>Clients</h2>${clientsList}
    <div class="chart-container"><canvas id="visitsChart"></canvas></div>
    <div class="chart-container"><canvas id="uptimeChart"></canvas></div>
    <div id="notifications"></div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="/socket.io/socket.io.js"></script>
    <script>
      const socket=io();
      socket.on('updateClients',data=>{ location.reload(); });
      socket.on('init',data=>{
        // Chart.js example
        const visitsCtx=document.getElementById('visitsChart').getContext('2d');
        new Chart(visitsCtx,{type:'line',data:{labels:['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],datasets:[{label:'Visits',data:[12,19,15,22,18,25,30],borderColor:'#ffd700',backgroundColor:'rgba(255,215,0,0.2)'}]},options:{responsive:true}});
        const uptimeCtx=document.getElementById('uptimeChart').getContext('2d');
        new Chart(uptimeCtx,{type:'doughnut',data:{labels:['Up','Down'],datasets:[{data:[99,1],backgroundColor:['#ffd700','#111']}]},options:{responsive:true}});
      });
    </script>
  </body>
  </html>
  `);
});

// ------------------- UPLOAD -------------------
app.post('/upload', upload.single('site'), (req,res)=>{
  try{
    const token=req.header('authorization')?.replace('Bearer ','');
    if(token!==UPLOAD_SECRET) return res.status(403).json({error:'forbidden'});
    if(!req.file) return res.status(400).json({error:'zip required'});
    if(!isZipFile(req.file.path)){ fs.unlinkSync(req.file.path); return res.status(400).json({error:'invalid zip'}); }

    const client=req.body.client;
    if(!client){ fs.unlinkSync(req.file.path); return res.status(400).json({error:'client required'}); }
    const safeClient=sanitize(client.toLowerCase());

    const destDir=path.join(SITES_DIR,safeClient);
    if(fs.existsSync(destDir)) fs.rmSync(destDir,{recursive:true,force:true});
    fs.mkdirSync(destDir,{recursive:true});
    extractZipSafely(req.file.path,destDir);
    fs.unlinkSync(req.file.path);

    const sites=readJSON(SITES_META);
    sites[safeClient]={client:safeClient,uploadedAt:new Date().toISOString()};
    writeJSON(SITES_META,sites);

    io.emit('updateClients', sites);

    res.json({ok:true,url:`/s/${safeClient}/`});
  } catch(err){ logger.error('upload-error',err); res.status(500).json({error:'internal'}); }
});

// ------------------- MPESA CALLBACK -------------------
app.post('/mpesa/callback', async (req,res)=>{
  try{
    const {Body:{stkCallback}}=req.body;
    if(stkCallback.ResultCode===0){
      const phone=stkCallback.CallbackMetadata.Item.find(i=>i.Name==='PhoneNumber').Value;
      const amount=stkCallback.CallbackMetadata.Item.find(i=>i.Name==='Amount').Value;
      const clients=readJSON(CLIENTS_META);
      const clientId=stkCallback.MerchantRequestID;
      clients[clientId]={client:clientId,phone,paid:true,tier:'Premium',joined:new Date().toISOString()};
      writeJSON(CLIENTS_META,clients);

      io.emit('updateClients', clients);
      sendNotification('plugnationstudios@gmail.com','New MPESA Payment',`Client: ${clientId} paid ${amount} KES`);
      logger.info('mpesa-payment-success',{client:clientId,amount,phone});
    }
    res.json({ResultCode:0,ResultDesc:'Accepted'});
  }catch(e){ logger.error('mpesa-callback-error',e); res.status(500).json({error:'fail'}); }
});

// ------------------- STATIC SERVE -------------------
app.use('/s',express.static(SITES_DIR));

// ------------------- ADMIN -------------------
app.get('/admin/sites',requireAdmin,(req,res)=>res.json({sites:readJSON(SITES_META)}));
app.get('/admin/clients',requireAdmin,(req,res)=>res.json({clients:readJSON(CLIENTS_META)}));

// ------------------- START SERVER -------------------
server.listen(PORT,()=>console.log(`🚀 G Server running on port ${PORT}`));
