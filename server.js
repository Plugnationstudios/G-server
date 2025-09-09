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
const fetch = require('node-fetch');
const http = require('http');
const { Server } = require('socket.io');

// ------------------- ENV -------------------
const PORT = parseInt(process.env.PORT || '3000', 10);
const UPLOAD_SECRET = process.env.UPLOAD_SECRET;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const JWT_SECRET = process.env.JWT_SECRET;
const MAX_UPLOAD_BYTES = parseInt(process.env.MAX_UPLOAD_BYTES || '52428800', 10);
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '120', 10);

// ------------------- MPESA CONFIG -------------------
const MPESA_CONSUMER_KEY = process.env.MPESA_CONSUMER_KEY;
const MPESA_CONSUMER_SECRET = process.env.MPESA_CONSUMER_SECRET;
const MPESA_SHORTCODE = process.env.MPESA_SHORTCODE;
const MPESA_PASSKEY = process.env.MPESA_PASSKEY;
const MPESA_CALLBACK_URL = process.env.MPESA_CALLBACK_URL;

// ------------------- PATHS -------------------
const ROOT = __dirname;
const TMP_DIR = path.join(ROOT, 'tmp');
const SITES_DIR = path.join(ROOT, 'sites');
const DATA_DIR = path.join(ROOT, 'data');
const SITES_META = path.join(DATA_DIR, 'sites.json');
const CLIENTS_META = path.join(DATA_DIR, 'clients.json');
const BACKUPS_DIR = path.join(ROOT, 'backups');

// ------------------- CREATE DIRECTORIES -------------------
[ TMP_DIR, SITES_DIR, DATA_DIR, BACKUPS_DIR ].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  if (!fs.existsSync(CLIENTS_META)) fs.writeFileSync(CLIENTS_META, '{}');
  if (!fs.existsSync(SITES_META)) fs.writeFileSync(SITES_META, '{}');
});

// ------------------- LOGGER -------------------
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.File({ filename: path.join(ROOT, 'gserver-error.log'), level: 'error' }),
    new winston.transports.File({ filename: path.join(ROOT, 'gserver-combined.log') })
  ]
});
if (process.env.NODE_ENV !== 'production') logger.add(new winston.transports.Console({ format: winston.format.simple() }));

// ------------------- EXPRESS -------------------
const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(helmet());
app.use(cors());
app.use(compression());
app.use(express.json({ limit:'2mb' }));
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
function readJSON(file){ try{ return JSON.parse(fs.readFileSync(file,'utf8')); } catch(e){ return {}; } }
function writeJSON(file,obj){ fs.writeFileSync(file+'.tmp',JSON.stringify(obj,null,2)); fs.renameSync(file+'.tmp',file); }
function isZipFile(fp){ try{ const fd=fs.openSync(fp,'r'); const buf=Buffer.alloc(4); fs.readSync(fd,buf,0,4,0); fs.closeSync(fd); return buf.slice(0,4).toString('binary').startsWith('PK'); }catch(e){return false;} }
function extractZipSafely(zipPath,destDir){ const zip=new AdmZip(zipPath); for(const entry of zip.getEntries()){ const entryName=entry.entryName; if(entryName.includes('..')||path.isAbsolute(entryName)) throw new Error('Invalid zip entry'); const target=path.join(destDir,entryName); if(!path.resolve(target).startsWith(path.resolve(destDir))) throw new Error('Zip escapes target dir'); if(entry.isDirectory){ if(!fs.existsSync(target)) fs.mkdirSync(target,{recursive:true}); } else { fs.mkdirSync(path.dirname(target),{recursive:true}); fs.writeFileSync(target,entry.getData()); } } }
function requireAdmin(req,res,next){ const token=req.header('x-admin-token')||req.query.admin_token; if(!token||token!==ADMIN_TOKEN) return res.status(403).json({error:'forbidden'}); next(); }

// ------------------- DASHBOARD -------------------
app.get('/',(req,res)=>{
  res.sendFile(path.join(ROOT,'dashboard.html'));
});

// ------------------- UPLOAD -------------------
app.post('/upload', upload.single('site'), (req,res)=>{
  try{
    const token=req.header('authorization')?.replace('Bearer ','');
    if(token!==UPLOAD_SECRET) return res.status(403).json({error:'forbidden'});
    if(!req.file) return res.status(400).json({error:'zip required'});
    if(!isZipFile(req.file.path)){ fs.unlinkSync(req.file.path); return res.status(400).json({error:'invalid zip'}); }

    const client= req.body.client;
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

    io.emit('new-site',{client:safeClient});
    res.json({ok:true,url:`/s/${safeClient}/`});
  } catch(err){ logger.error('upload-error',err); res.status(500).json({error:'internal'}); }
});

// ------------------- MPESA CALLBACK -------------------
app.post('/mpesa/callback', (req,res)=>{
  try{
    const {Body:{stkCallback}} = req.body;
    if(stkCallback.ResultCode===0){
      const phone=stkCallback.CallbackMetadata.Item.find(i=>i.Name==='PhoneNumber').Value;
      const amount=stkCallback.CallbackMetadata.Item.find(i=>i.Name==='Amount').Value;
      const clients=readJSON(CLIENTS_META);
      const clientId = stkCallback.MerchantRequestID;
      clients[clientId]={client:clientId,phone,paid:true,tier:'Premium',joined:new Date().toISOString(),invite:`/invite/${clientId}`};
      writeJSON(CLIENTS_META,clients);
      logger.info('mpesa-payment-success',{client:clientId,amount,phone});
      io.emit('new-client',clients[clientId]);
    }
    res.json({ResultCode:0,ResultDesc:'Accepted'});
  }catch(e){ logger.error('mpesa-callback-error',e); res.status(500).json({error:'fail'}); }
});

// ------------------- MPESA STK PUSH -------------------
app.post('/mpesa/stkpush', async (req,res)=>{
  try{
    const {client,amount} = req.body;
    if(!client||!amount) return res.status(400).json({error:'client and amount required'});
    // Logic: Use MPESA API to initiate STK push
    // This is where you integrate live MPESA credentials
    res.json({ok:true,message:'STK Push triggered',client,amount});
  }catch(e){ logger.error('stkpush-error',e); res.status(500).json({error:'fail'}); }
});

// ------------------- STATIC SERVE -------------------
app.use('/s',express.static(SITES_DIR));

// ------------------- ADMIN API -------------------
app.get('/admin/sites',requireAdmin,(req,res)=>res.json({sites:readJSON(SITES_META)}));
app.get('/admin/clients',requireAdmin,(req,res)=>res.json({clients:readJSON(CLIENTS_META)}));

// ------------------- INVITE LINKS -------------------
app.get('/invite/:id',(req,res)=>{
  const clients=readJSON(CLIENTS_META);
  const c=clients[req.params.id];
  if(!c) return res.status(404).send('Invalid invite link');
  res.send(`<h1>Welcome, ${c.client}</h1><p>Your tier: ${c.tier}</p>`);
});

// ------------------- SOCKET.IO -------------------
io.on('connection', socket => {
  console.log('⚡ Client connected');
});

// ------------------- START SERVER -------------------
server.listen(PORT,()=>console.log(`🚀 G Server running on port ${PORT}`));
