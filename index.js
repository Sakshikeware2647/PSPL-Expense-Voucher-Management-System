import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import Database from 'better-sqlite3';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.resolve(__dirname, '..');
const uploadDir = path.join(serverRoot, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me';
app.use(cors({ origin: process.env.CLIENT_ORIGIN || 'http://localhost:5173' }));
app.use(express.json({ limit: '1mb' }));
app.use('/uploads', express.static(uploadDir));

const db = new Database(path.join(serverRoot, 'expense-vouchers.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('EMPLOYEE','DIRECTOR','ACCOUNTS')),
 employee_id TEXT, department TEXT, signature_path TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vouchers (
 id INTEGER PRIMARY KEY AUTOINCREMENT, voucher_number TEXT UNIQUE NOT NULL,
 owner_id INTEGER NOT NULL REFERENCES users(id), voucher_date TEXT NOT NULL, expense_date TEXT NOT NULL,
 department TEXT NOT NULL, title TEXT NOT NULL, category TEXT NOT NULL, description TEXT DEFAULT '',
 amount REAL NOT NULL CHECK(amount > 0), employee_signature TEXT,
 director_signature TEXT, status TEXT NOT NULL DEFAULT 'DRAFT',
 approval_date TEXT, rejection_reason TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS voucher_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, voucher_id INTEGER NOT NULL REFERENCES vouchers(id),
 actor_id INTEGER NOT NULL REFERENCES users(id), action TEXT NOT NULL, note TEXT DEFAULT '',
 created_at TEXT NOT NULL
);
`);
const now = () => new Date().toISOString();
const addEvent = (voucherId, actorId, action, note='') =>
  db.prepare('INSERT INTO voucher_events (voucher_id,actor_id,action,note,created_at) VALUES (?,?,?,?,?)')
    .run(voucherId, actorId, action, note, now());

const seed = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
if (!seed) {
  const insert = db.prepare(`INSERT INTO users (name,email,password_hash,role,employee_id,department,created_at) VALUES (?,?,?,?,?,?,?)`);
  const demo = [
    ['Aarav Mehta','employee@pspl.demo','EMPLOYEE','PSPL-104','Product'],
    ['Ananya Rao','director@pspl.demo','DIRECTOR','PSPL-DIR','Leadership'],
    ['Finance Operations','accounts@pspl.demo','ACCOUNTS','PSPL-ACC','Finance']
  ];
  const transaction = db.transaction(() => demo.forEach(([name,email,role,eid,dept]) =>
    insert.run(name,email,bcrypt.hashSync('Password123!',10),role,eid,dept,now())));
  transaction();
}

const safeUser = (u) => ({ id:u.id, name:u.name, email:u.email, role:u.role, employeeId:u.employee_id, department:u.department, signaturePath:u.signature_path });
function auth(req,res,next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i,'');
  if (!token) return res.status(401).json({ error:'Please sign in to continue.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(payload.sub);
    if (!user) return res.status(401).json({ error:'Account not found.' });
    req.user = user; next();
  } catch { return res.status(401).json({ error:'Your session expired. Please sign in again.' }); }
}
const allow = (...roles) => (req,res,next) => roles.includes(req.user.role) ? next() : res.status(403).json({error:'You do not have permission to do that.'});
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req,_file,cb) => cb(null,uploadDir),
    filename: (_req,file,cb) => cb(null,`${Date.now()}-${crypto.randomBytes(5).toString('hex')}${path.extname(file.originalname).toLowerCase()}`)
  }),
  limits:{ fileSize:2*1024*1024 },
  fileFilter:(_req,file,cb) => ['image/png','image/jpeg','image/webp'].includes(file.mimetype) ? cb(null,true) : cb(new Error('Signature must be a PNG, JPG or WEBP image.'))
});
function shape(v) {
  const owner = db.prepare('SELECT name,email,employee_id FROM users WHERE id=?').get(v.owner_id);
  return {...v, employeeName:owner?.name || 'Unknown', employeeEmail:owner?.email, employeeId:owner?.employee_id,
    employeeSignatureUrl:v.employee_signature ? `/uploads/${v.employee_signature}` : null,
    directorSignatureUrl:v.director_signature ? `/uploads/${v.director_signature}` : null};
}
function makeVoucherNumber() {
  const day = new Date().toISOString().slice(0,10).replaceAll('-','');
  return `PSPL-${day}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}
function validateVoucher(body) {
  const errors = {};
  for (const key of ['department','title','expenseDate','category']) if (!String(body[key] || '').trim()) errors[key] = `${key} is required.`;
  if (!(Number(body.amount) > 0)) errors.amount = 'Amount must be greater than zero.';
  return errors;
}
app.get('/api/health', (_req,res)=>res.json({ok:true,service:'PSPL Expense Voucher API'}));
app.post('/api/auth/login', (req,res) => {
  const {email,password} = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(String(email||'').toLowerCase().trim());
  if (!user || !bcrypt.compareSync(String(password||''),user.password_hash)) return res.status(401).json({error:'Email or password is incorrect.'});
  const token = jwt.sign({sub:user.id,role:user.role},JWT_SECRET,{expiresIn:'8h'});
  res.json({token,user:safeUser(user)});
});
app.get('/api/auth/me',auth,(req,res)=>res.json({user:safeUser(req.user)}));
app.post('/api/users/signature',auth,upload.single('signature'),(req,res)=>{
  if (!req.file) return res.status(400).json({error:'Choose a signature image.'});
  db.prepare('UPDATE users SET signature_path=? WHERE id=?').run(req.file.filename,req.user.id);
  res.json({signatureUrl:`/uploads/${req.file.filename}`});
});

app.get('/api/vouchers',auth,(req,res)=>{
  const {q='',status='',department='',category='',from='',to='',minAmount='',maxAmount=''} = req.query;
  let sql = `SELECT v.* FROM vouchers v JOIN users u ON u.id=v.owner_id WHERE 1=1`;
  const params = [];
  if (req.user.role === 'EMPLOYEE') { sql += ' AND v.owner_id=?'; params.push(req.user.id); }
  if (q) { sql += ' AND (v.voucher_number LIKE ? OR u.name LIKE ? OR v.department LIKE ? OR v.title LIKE ?)'; params.push(...Array(4).fill(`%${q}%`)); }
  if (status) { sql += ' AND v.status=?'; params.push(status); }
  if (department) { sql += ' AND v.department=?'; params.push(department); }
  if (category) { sql += ' AND v.category=?'; params.push(category); }
  if (from) { sql += ' AND v.expense_date>=?'; params.push(from); }
  if (to) { sql += ' AND v.expense_date<=?'; params.push(to); }
  if (minAmount !== '') { sql += ' AND v.amount>=?'; params.push(Number(minAmount)); }
  if (maxAmount !== '') { sql += ' AND v.amount<=?'; params.push(Number(maxAmount)); }
  sql += ' ORDER BY v.created_at DESC';
  res.json({vouchers:db.prepare(sql).all(...params).map(shape)});
});
app.post('/api/vouchers',auth,allow('EMPLOYEE'),(req,res)=>{
  const errors = validateVoucher(req.body);
  if (Object.keys(errors).length) return res.status(422).json({error:'Please fix the highlighted fields.',fields:errors});
  const b=req.body, t=now(), number=makeVoucherNumber();
  const result=db.prepare(`INSERT INTO vouchers (voucher_number,owner_id,voucher_date,expense_date,department,title,category,description,amount,employee_signature,status,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,'DRAFT',?,?)`).run(number,req.user.id,b.voucherDate||t.slice(0,10),b.expenseDate,b.department.trim(),b.title.trim(),b.category,b.description||'',Number(b.amount),b.employeeSignature||req.user.signature_path,t,t);
  const id=result.lastInsertRowid; addEvent(id,req.user.id,'CREATED','Draft created');
  res.status(201).json({voucher:shape(db.prepare('SELECT * FROM vouchers WHERE id=?').get(id))});
});
app.get('/api/vouchers/:id',auth,(req,res)=>{
  const v=db.prepare('SELECT * FROM vouchers WHERE id=?').get(req.params.id);
  if(!v) return res.status(404).json({error:'Voucher not found.'});
  if(req.user.role==='EMPLOYEE' && v.owner_id!==req.user.id) return res.status(403).json({error:'You can only view your own vouchers.'});
  const events=db.prepare(`SELECT e.*,u.name AS actor_name FROM voucher_events e JOIN users u ON u.id=e.actor_id WHERE e.voucher_id=? ORDER BY e.created_at DESC`).all(v.id);
  res.json({voucher:shape(v),events});
});
app.put('/api/vouchers/:id',auth,allow('EMPLOYEE'),(req,res)=>{
  const v=db.prepare('SELECT * FROM vouchers WHERE id=?').get(req.params.id);
  if(!v) return res.status(404).json({error:'Voucher not found.'});
  if(v.owner_id!==req.user.id || v.status!=='DRAFT') return res.status(403).json({error:'Only your own draft vouchers can be edited.'});
  const errors=validateVoucher(req.body); if(Object.keys(errors).length) return res.status(422).json({error:'Please fix the highlighted fields.',fields:errors});
  const b=req.body;
  db.prepare(`UPDATE vouchers SET voucher_date=?,expense_date=?,department=?,title=?,category=?,description=?,amount=?,employee_signature=?,updated_at=? WHERE id=?`)
    .run(b.voucherDate||v.voucher_date,b.expenseDate,b.department.trim(),b.title.trim(),b.category,b.description||'',Number(b.amount),b.employeeSignature||v.employee_signature,now(),v.id);
  addEvent(v.id,req.user.id,'UPDATED','Draft updated');
  res.json({voucher:shape(db.prepare('SELECT * FROM vouchers WHERE id=?').get(v.id))});
});
app.delete('/api/vouchers/:id',auth,allow('EMPLOYEE'),(req,res)=>{
  const v=db.prepare('SELECT * FROM vouchers WHERE id=?').get(req.params.id);
  if(!v) return res.status(404).json({error:'Voucher not found.'});
  if(v.owner_id!==req.user.id || v.status!=='DRAFT') return res.status(403).json({error:'Only your own draft vouchers can be deleted.'});
  db.prepare('DELETE FROM voucher_events WHERE voucher_id=?').run(v.id); db.prepare('DELETE FROM vouchers WHERE id=?').run(v.id);
  res.json({ok:true});
});
app.post('/api/vouchers/:id/submit',auth,allow('EMPLOYEE'),(req,res)=>{
  const v=db.prepare('SELECT * FROM vouchers WHERE id=?').get(req.params.id);
  if(!v) return res.status(404).json({error:'Voucher not found.'});
  if(v.owner_id!==req.user.id || v.status!=='DRAFT') return res.status(403).json({error:'Only your own draft vouchers can be submitted.'});
  if(!(v.employee_signature || req.user.signature_path)) return res.status(422).json({error:'Upload your signature before submitting.'});
  db.prepare(`UPDATE vouchers SET status='PENDING_APPROVAL',employee_signature=?,updated_at=? WHERE id=?`).run(v.employee_signature||req.user.signature_path,now(),v.id);
  addEvent(v.id,req.user.id,'SUBMITTED','Sent for director approval');
  res.json({voucher:shape(db.prepare('SELECT * FROM vouchers WHERE id=?').get(v.id))});
});
app.post('/api/vouchers/:id/approve',auth,allow('DIRECTOR'),upload.single('signature'),(req,res)=>{
  const v=db.prepare('SELECT * FROM vouchers WHERE id=?').get(req.params.id);
  if(!v) return res.status(404).json({error:'Voucher not found.'});
  if(v.status!=='PENDING_APPROVAL') return res.status(409).json({error:'Only pending vouchers can be approved.'});
  const signature=req.file?.filename || req.user.signature_path;
  if(!signature) return res.status(422).json({error:'Upload your director signature before approving.'});
  const t=now();
  db.prepare(`UPDATE vouchers SET status='APPROVED',director_signature=?,approval_date=?,updated_at=? WHERE id=?`).run(signature,t,t,v.id);
  addEvent(v.id,req.user.id,'APPROVED','Approved by Director');
  res.json({voucher:shape(db.prepare('SELECT * FROM vouchers WHERE id=?').get(v.id))});
});
app.post('/api/vouchers/:id/reject',auth,allow('DIRECTOR'),(req,res)=>{
  const v=db.prepare('SELECT * FROM vouchers WHERE id=?').get(req.params.id);
  if(!v) return res.status(404).json({error:'Voucher not found.'});
  const reason=String(req.body?.reason||'').trim();
  if(!reason) return res.status(422).json({error:'A rejection reason is required.'});
  if(v.status!=='PENDING_APPROVAL') return res.status(409).json({error:'Only pending vouchers can be rejected.'});
  const t=now();
  db.prepare(`UPDATE vouchers SET status='REJECTED',rejection_reason=?,updated_at=? WHERE id=?`).run(reason,t,v.id);
  addEvent(v.id,req.user.id,'REJECTED',reason);
  res.json({voucher:shape(db.prepare('SELECT * FROM vouchers WHERE id=?').get(v.id))});
});
app.use((err,_req,res,_next)=>{
  if(err instanceof multer.MulterError) return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'Image must be 2MB or smaller.':err.message});
  if(err) return res.status(400).json({error:err.message||'Unexpected server error.'});
  res.status(500).json({error:'Unexpected server error.'});
});
app.listen(PORT,()=>console.log(`PSPL API ready at http://localhost:${PORT}`));
