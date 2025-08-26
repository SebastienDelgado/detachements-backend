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
  const required = ['fullName','applicantEmail','entity','dateFrom','dateTo','place','type','managerEmail','hrEmail','da]()
