// server.js — Backend (Mongo + JWT + Mailtrap)
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const dayjs = require('dayjs');

// ----- Config -----
const {
  PORT = 3000,
  MONGODB_URI,
  JWT_SECRET,
  MAILTRAP_HOST,
  MAILTRAP_PORT = 2525,
  MAILTRAP_USER,
  MAILTRAP_PASS,
  APP_BASE_URL = 'http://localhost:5173',
} = process.env;

if (!MONGODB_URI || !JWT_SECRET) {
  console.error('❌ Missing ENV: MONGODB_URI or JWT_SECRET');
  process.exit(1);
}

// ----- App -----
const app = express();

// CORS universel (et OPTIONS)
app.use((req, res, next) => {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    req.headers['access-control-request-headers'] || 'Content-Type, Authorization, Accept'
  );
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// Parsers JSON + x-www-form-urlencoded
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// ----- DB (retry) -----
mongoose.set('strictQuery', true);
async function connectWithRetry() {
  try {
    await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
    console.log('✅ MongoDB connected');
  } catch (e) {
    console.error('MongoDB connection error:', e?.message || e);
    setTimeout(connectWithRetry, 5000);
  }
}
connectWithRetry();

// ----- Schemas -----
const AdminSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  name:  { type: String, required: true },
  passwordHash: { type: String, required: true },
}, { timestamps: true });

const RequestSchema = new mongoose.Schema({
  full_name: String,
  applicant_email: String,
  entity: String,
  date_from: String,
  date_to: String,
  start_period: { type: String, default: 'FULL' },
  end_period:   { type: String, default: 'FULL' },
  place: String,
  type: String,
  days: Number,
  comment: String,
  manager_email: String,
  hr_email: String,
  status: { type: String, default: 'pending' }, // pending | sent | refused | cancelled
  created_at: { type: Date, default: () => new Date() },
  reminder2_sent_at: Date,
  reminder4_sent_at: Date,
}, { timestamps: true });

const Admin = mongoose.model('Admin', AdminSchema);
const Request = mongoose.model('Request', RequestSchema);

// ----- Mailer (Mailtrap) -----
const transporter = nodemailer.createTransport({
  host: MAILTRAP_HOST,
  port: Number(MAILTRAP_PORT),
  auth: { user: MAILTRAP_USER, pass: MAILTRAP_PASS },
});
async function sendMail({ to, cc = [], subject, html }) {
  return transporter.sendMail({
    from: '"CSEC SG - Détachements" <no-reply@csec-sg.com>',
    to: Array.isArray(to) ? to.join(', ') : to,
    cc: Array.isArray(cc) ? cc.join(', ') : cc,
    subject, html,
  });
}

// ----- Utils -----
function signToken(admin) {
  return jwt.sign({ sub: admin._id.toString(), name: admin.name, email: admin.email }, JWT_SECRET, { expiresIn: '7d' });
}
async function authRequired(req, res, next) {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const admin = await Admin.findById(payload.sub);
    if (!admin) return res.status(401).json({ error: 'Unauthorized' });
    req.admin = admin;
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}
function toFR(d) {
  if (!d || !/\d{4}-\d{2}-\d{2}/.test(d)) return d || '—';
  const [y,m,dd] = d.split('-');
  return `${dd}/${m}/${y}`;
}

// ----- Seed admins quand DB connectée -----
mongoose.connection.on('connected', async () => {
  const existing = await Admin.find({}).lean();
  if (existing.length) return;
  const SEB_EMAIL = 'sebastien.delgado@csec-sg.com';
  const LUDI_EMAIL = 'ludivine.perreaut@gmail.com';
  const SEB_PASS = 'SeB!24-9vQ@csec';
  const LUDI_PASS = 'LuD!24-7mX@csec';

  const a1 = new Admin({ email: SEB_EMAIL, name: 'Sébastien DELGADO', passwordHash: await bcrypt.hash(SEB_PASS, 10) });
  const a2 = new Admin({ email: LUDI_EMAIL, name: 'Ludivine PERREAUT', passwordHash: await bcrypt.hash(LUDI_PASS, 10) });
  await a1.save(); await a2.save();
  console.log('Admins seeded.');
});

// ----- Health -----
app.get('/api/health', (req,res) => res.json({ ok: true }));

// ----- Auth -----
app.post('/api/auth/login', async (req,res) => {
  const { email, password } = req.body || {};
  const admin = await Admin.findOne({ email });
  if (!admin) return res.status(401).json({ error: 'Identifiants invalides' });
  const ok = await bcrypt.compare(password || '', admin.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Identifiants invalides' });
  const token = signToken(admin);
  return res.json({ token, name: admin.name, email: admin.email });
});

app.post('/api/auth/change-password', authRequired, async (req,res) => {
  const { currentPassword, newPassword } = req.body || {};
  const ok = await bcrypt.compare(currentPassword || '', req.admin.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Mot de passe actuel invalide' });
  req.admin.passwordHash = await bcrypt.hash(newPassword, 10);
  await req.admin.save();
  return res.json({ ok: true });
});

// ----- Requests -----
// Création
app.post('/api/requests', async (req,res) => {
  const b = req.body || {};
  // 🔧 ligne corrigée : 'days' à la fin
  const required = ['fullName','applicantEmail','entity','dateFrom','dateTo','place','type','managerEmail','hrEmail','days'];
  for (const k of required) {
    if (!b[k]) return res.status(400).json({ error: `Champ manquant: ${k}` });
  }
  const rec = await Request.create({
    full_name: b.fullName,
    applicant_email: b.applicantEmail,
    entity: b.entity,
    date_from: b.dateFrom,
    date_to: b.dateTo,
    start_period: b.startPeriod || 'FULL',
    end_period: b.endPeriod || 'FULL',
    place: b.place,
    type: b.type,
    days: Number(b.days),
    comment: b.comment || '',
    manager_email: b.managerEmail,
    hr_email: b.hrEmail,
    status: 'pending',
    created_at: new Date(),
  });
  return res.json({ ok: true, id: rec._id.toString() });
});

// Liste (par statut)
app.get('/api/requests', authRequired, async (req,res) => {
  const status = (req.query.status || '').toLowerCase();
  const q = status ? { status } : {};
  const items = await Request.find(q).sort({ created_at: -1 }).lean();
  return res.json({ items });
});

// ----- Actions : VALIDATE / REFUSE / CANCEL -----
app.post('/api/requests/:id/validate', authRequired, async (req,res) => {
  const rec = await Request.findById(req.params.id);
  if (!rec) return res.status(404).json({ error: 'Not found' });

  rec.status = 'sent';
  await rec.save();

  const signName = req.admin.name || 'Administrateur';
  const subject = `Détachement – ${rec.full_name}`;
  const html = `
    <p>Bonjour,</p>
    <p>Merci de bien vouloir noter le détachement de :
      <br/><span style="color:#D71620">${rec.full_name}${rec.entity ? ' – ' + rec.entity : ''}</span>
    </p>
    <p>
      Le(s) : <span style="color:#D71620">${toFR(rec.date_from)} au ${toFR(rec.date_to)}</span><br/>
      À : <span style="color:#D71620">${rec.place}</span><br/>
      En article 21 : <span style="color:#D71620">${rec.type} – ${rec.days} jour(s)</span><br/>
      (Hors délai de route)
    </p>
    ${rec.comment ? `<p>Commentaire du demandeur : <span style="color:#D71620">${rec.comment}</span></p>` : ''}
    <p>Bonne fin de journée,</p>
    <p><strong>${signName}</strong><br/>CSEC SG</p>
  `;
  try {
    const to = [rec.manager_email, rec.hr_email].filter(Boolean);
    const cc = [rec.applicant_email].filter(Boolean);
    const transporter = nodemailer.createTransport({
      host: MAILTRAP_HOST, port: Number(MAILTRAP_PORT),
      auth: { user: MAILTRAP_USER, pass: MAILTRAP_PASS },
    });
    await transporter.sendMail({
      from: '"CSEC SG - Détachements" <no-reply@csec-sg.com>',
      to: to.join(', '), cc: cc.join(', '), subject, html
    });
  } catch(e){ console.error('Mail validate err:', e.message); }

  return res.json({ ok: true });
});

app.post('/api/requests/:id/refuse', authRequired, async (req,res) => {
  const rec = await Request.findById(req.params.id);
  if (!rec) return res.status(404).json({ error: 'Not found' });
  rec.status = 'refused';
  rec.refuse_reason = (req.body && req.body.reason) || '';
  await rec.save();
  return res.json({ ok: true });
});

app.post('/api/requests/:id/cancel', authRequired, async (req,res) => {
  const rec = await Request.findById(req.params.id);
  if (!rec) return res.status(404).json({ error: 'Not found' });
  rec.status = 'cancelled';
  rec.cancel_reason = (req.body && req.body.reason) || '';
  await rec.save();
  return res.json({ ok: true });
});

// ----- Start -----
app.listen(PORT, () => {
  console.log(`🚀 API listening on port ${PORT}`);
});
