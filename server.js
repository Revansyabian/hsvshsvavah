import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import webtopupbussid, { decryptRequest, encryptResponse } from './api/webtopupbussid.js';
import rvnstore from './api/rvnstore.js';
import adminHandler from './api/admin.js';

const __filename=fileURLToPath(import.meta.url);
const __dirname=path.dirname(__filename);
const server=express();
const PAGES_DIR=path.join(__dirname,'pages');

server.disable('x-powered-by');
server.set('trust proxy',1);
server.use(express.json({limit:'200kb',strict:true}));
server.use(express.urlencoded({extended:false,limit:'20kb'}));

const allowedOrigins=(process.env.ALLOWED_ORIGINS||'').split(',').map(v=>v.trim()).filter(Boolean);
server.use((req,res,next)=>{
  const origin=req.headers.origin;
  if(origin && allowedOrigins.length && !allowedOrigins.includes(origin)) return res.status(403).json({error:'Origin tidak diizinkan'});
  if(origin){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Access-Control-Allow-Credentials','true');res.setHeader('Vary','Origin');}
  res.setHeader('Access-Control-Allow-Headers','Content-Type, X-Requested-With, X-Fingerprint, X-Client-Key');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,DELETE,OPTIONS');
  if(req.method==='OPTIONS') return res.status(204).end();
  next();
});

function isExempt(req){
  const p=req.path;
  return p==='/api/rvnstore' || p==='/api/admin' || (p==='/api/webtopup' || p==='/api/webtopupbussid') && req.query.action==='key';
}
function encryptedTransport(req,res,next){
  if(isExempt(req)) return next();
  if(req.method==='GET' && req.path.startsWith('/api/') && !req.body) return next();
  const clientKey=req.headers['x-client-key'];
  if(req.body && Object.keys(req.body).length){
    try { req.body=decryptRequest(req.body); } catch { return res.status(400).json({error:'Encrypted request tidak valid'}); }
  }
  if(!clientKey) return res.status(400).json({error:'Client public key diperlukan'});
  const json=res.json.bind(res);
  res.json=(body)=>json(encryptResponse(body,clientKey));
  next();
}
server.use('/api',encryptedTransport);
server.all('/api/webtopupbussid',async(req,res)=>{try{return await webtopupbussid(req,res)}catch(e){console.error(e?.message||e);if(!res.headersSent)return res.status(500).json({error:'Internal server error'})}});
server.all('/api/webtopup',async(req,res)=>{try{return await webtopupbussid(req,res)}catch(e){console.error(e?.message||e);if(!res.headersSent)return res.status(500).json({error:'Internal server error'})}});
server.all('/api/rvnstore',async(req,res)=>{try{return await rvnstore(req,res)}catch(e){console.error(e?.message||e);if(!res.headersSent)return res.status(500).json({error:'Internal server error'})}});
server.all('/api/admin',async(req,res)=>{try{return await adminHandler(req,res)}catch(e){console.error(e?.message||e);if(!res.headersSent)return res.status(500).json({error:'Internal server error'})}});

server.get('/',(_req,res)=>res.sendFile(path.join(__dirname,'index.html')));
server.get('/admin',(_req,res)=>res.sendFile(path.join(__dirname,'admin.html')));
for(const name of ['login','dashboard','register','reset-password','confirm-password']) server.get('/pages/'+name,(_req,res)=>res.sendFile(path.join(PAGES_DIR,name+'.html')));
server.use('/pages',express.static(PAGES_DIR,{index:false}));
server.use(express.static(__dirname,{index:false}));
server.use((_req,res)=>res.status(404).send('Not Found'));

