// server.js — Backend (Mongo + JWT + SMTP Gmail + Alertes + Relances quotidiennes)
// Gmail (app password) sur smtp.gmail.com:587 STARTTLS
// Patches inclus : compat id (_id -> id) + contrôle d'ObjectId

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// ====== ENV ======
const {
  PORT = 3000,
  MONGODB_URI,
  JWT_SECRET,
  APP_BASE_URL = 'http://localhost:5173',
  CRON_SECRET,

  // === SMTP (GMAIL) ===
  SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com',
  SMTP_PORT = Number(process.env.SMTP_PORT || 587),     // 👈 Gmail: 587
  SMTP_SECURE = String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true' ? true : false, // 👈 false (STARTTLS)
  SMTP_USER,    // ex: detachements.art21.csecsg@gmail.com
  SMTP_PASS,    // app password (16 chars sans espaces)

  // Émetteur (depuis ENV)
  MAIL_FROM = process.env.MAIL_FROM || (SMTP_USER ? SMTP_USER : 'no-reply@example.com'),
  MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || 'Détachements CGT-SG Article 21 CSEC-SG',

  // CORS (liste d’origines séparées par des virgules)
  CORS_ORIGINS = process.env.CORS_ORIGINS || APP_BASE_URL,
} = process.env;

if (!MONGODB_URI || !JWT_SECRET) {
  console.error('❌ Missing ENV: MONGODB_URI or JWT_SECRET');
  process.exit(1);
}
if (!SMTP_USER || !SMTP_PASS) {
  console.warn('⚠️ SMTP_USER / SMTP_PASS non définis : l’envoi d’e-mails échouera.');
}

// ====== APP & CORS ======
const app = express();
const allowedOrigins = (CORS_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowedOrigins.length === 0) return cb(null, true); // open
    if (allowedOrigins.includes(origin)) return cb(null, true);
    return cb(null, true); // en prod tu peux restreindre : cb(new Error('Not allowed'), false)
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','Accept'],
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// ====== DB ======
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

// ====== Schemas ======
const AdminSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  name:  { type: String, required: true },
  passwordHash: { type: String, required: true },
}, { timestamps: true });

const RequestSchema = new mongoose.Schema({
  full_name: String,
  applicant_email: String,
  entity: String,
  date_from: String, // yyyy-mm-dd
  date_to: String,   // yyyy-mm-dd
  start_period: { type: String, default: 'FULL' }, // FULL | AM | PM
  end_period:   { type: String, default: 'FULL' }, // FULL | AM | PM
  place: String,
  type: String,
  days: Number,
  comment: String,
  manager_email: String,
  hr_email: String,
  status: { type: String, default: 'pending' }, // pending | sent | refused | cancelled
  created_at: { type: Date, default: () => new Date() },
  reminder_last_sent_on: String, // "YYYY-MM-DD"
}, { timestamps: true });

const Admin = mongoose.model('Admin', AdminSchema);
const Request = mongoose.model('Request', RequestSchema);

// ====== Helpers ======
function isValidId(id) {
  return typeof id === 'string' && mongoose.Types.ObjectId.isValid(id);
}
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
    req.admin = admin; next();
  } catch { return res.status(401).json({ error: 'Unauthorized' }); }
}
function toFR(d) {
  if (!d || !/\d{4}-\d{2}-\d{2}/.test(d)) return d || '—';
  const [y,m,dd] = d.split('-'); return `${dd}/${m}/${y}`;
}
function datePhrase(rec) {
  const a = rec.date_from, b = rec.date_to, sp = (rec.start_period||'FULL').toUpperCase(), ep = (rec.end_period||'FULL').toUpperCase();
  const A = toFR(a), B = toFR(b || a);
  if (!b || a === b) {
    if (sp === 'AM' && ep === 'AM') return `${A} (Matin)`;
    if (sp === 'PM' && ep === 'PM') return `${A} (Après-midi)`;
    return `${A}`;
  }
  const tail = [];
  if (sp === 'PM') tail.push('Début : Après-midi');
  if (ep === 'AM') tail.push('Fin : Matin');
  return `Du ${A} au ${B}${tail.length ? ' — ' + tail.join(', ') : ''}`;
}
function todayParisISO() {
  const parts = new Intl.DateTimeFormat('fr-FR', {
    timeZone: 'Europe/Paris',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).formatToParts(new Date());
  const dd = parts.find(p => p.type === 'day').value;
  const mm = parts.find(p => p.type === 'month').value;
  const yyyy = parts.find(p => p.type === 'year').value;
  return `${yyyy}-${mm}-${dd}`;
}
function getSignTitle(email) {
  if (email === 'sebastien.delgado@csec-sg.com') return 'Secrétaire Adjoint du CSEC SG';
  if (email === 'ludivine.perreaut@gmail.com') return 'Représentante Syndicale Nationale CGT';
  return 'CSEC SG';
}

// ====== Mailer (Gmail) ======
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,          // 'smtp.gmail.com'
  port: SMTP_PORT,          // 587
  secure: SMTP_SECURE,      // false (STARTTLS)
  auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
  requireTLS: true,         // force STARTTLS
});
async function sendMail({ to, cc = [], subject, html }) {
  return transporter.sendMail({
    from: `"${MAIL_FROM_NAME}" <${MAIL_FROM}>`,
    to: Array.isArray(to) ? to.join(', ') : to,
    cc: Array.isArray(cc) ? cc.join(', ') : cc,
    subject,
    html,
  });
}
transporter.verify()
  .then(() => console.log(`📮 SMTP ready (smtp.gmail.com:587 STARTTLS) FROM=${MAIL_FROM_NAME} <${MAIL_FROM}>`))
  .catch(e => console.error('📮 SMTP verify failed:', e?.message || e));

// ====== Seed admins (1re exécution) ======
mongoose.connection.on('connected', async () => {
  const existing = await Admin.find({}).lean();
  if (existing.length) return;

  const SEB_EMAIL = 'sebastien.delgado@csec-sg.com';
  const LUDI_EMAIL = 'ludivine.perreaut@gmail.com';
  const SEB_PASS = 'SeB!24-9vQ@csec';
  const LUDI_PASS = 'LuD!24-7mX@csec';

  await new Admin({ email: SEB_EMAIL, name: 'Sébastien DELGADO',  passwordHash: await bcrypt.hash(SEB_PASS, 10) }).save();
  await new Admin({ email: LUDI_EMAIL,  name: 'Ludivine PERREAUT', passwordHash: await bcrypt.hash(LUDI_PASS, 10) }).save();

  console.log('👥 Admins seeded.');
});

// ====== Health / Debug ======
app.get('/api/health', (req,res) => res.json({ ok: true }));
app.get('/api/mail-verify', async (req,res) => {
  try { await transporter.verify(); res.json({ ok:true, host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_SECURE, from: `${MAIL_FROM_NAME} <${MAIL_FROM}>` }); }
  catch(e){ res.status(500).json({ ok:false, error:e.message, host:SMTP_HOST, port:SMTP_PORT, secure: SMTP_SECURE }); }
});

// ====== Auth ======
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

// ====== Requests ======
// Création ➜ notifie les admins
app.post('/api/requests', async (req,res) => {
  const b = req.body || {};
  const required = ['fullName','applicantEmail','entity','dateFrom','dateTo','place','type','managerEmail','hrEmail','days'];
  for (const k of required) if (!b[k]) return res.status(400).json({ error: `Champ manquant: ${k}` });

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

  try {
    const admins = await Admin.find({}).lean();
    const adminEmails = admins.map(a => a.email);
    const subject = `Nouvelle demande de détachement – ${rec.full_name}`;
    const html = `
      <p>Bonjour,</p>
      <p>Nouvelle demande en attente :</p>
      <ul>
        <li><strong>${rec.full_name}</strong> (${rec.entity})</li>
        <li>Date(s) : ${datePhrase(rec)}</li>
        <li>Lieu : ${rec.place}</li>
        <li>Article 21 : ${rec.type} – ${rec.days} jour(s)</li>
        <li>Commentaire : ${rec.comment || '—'}</li>
      </ul>
      <p>Espace validation : ${APP_BASE_URL}</p>
    `;
    await sendMail({ to: adminEmails, subject, html });
  } catch(e){ console.error('Mail admins (création) err:', e?.message || e); }

  return res.json({ ok: true, id: rec._id.toString() });
});

// Liste (normalisée avec id)
app.get('/api/requests', authRequired, async (req,res) => {
  const status = (req.query.status || '').toLowerCase();
  const q = status ? { status } : {};
  const items = await Request.find(q).sort({ created_at: -1 }).lean();
  return res.json({
    items: (items || []).map(x => ({
      ...x,
      id: (x._id || x.id || '').toString(),
      _id: undefined
    }))
  });
});

// Validation (envoi signé par l’admin connecté)
app.post('/api/requests/:id/validate', authRequired, async (req,res) => {
  const { id } = req.params;
  if (!isValidId(id)) return res.status(400).json({ error: 'Invalid id' });

  const rec = await Request.findById(id);
  if (!rec) return res.status(404).json({ error: 'Not found' });

  rec.status = 'sent'; await rec.save();

  const signTitle = getSignTitle(req.admin.email);
  const subject = `Détachement – ${rec.full_name}`;
  const html = `
    <p>Bonjour,</p>
    <p>Merci de bien vouloir noter le détachement de :
      <br/><span style="color:#D71620">${rec.full_name}${rec.entity ? ' – ' + rec.entity : ''}</span>
    </p>
    <p>
      Date(s) : <span style="color:#D71620">${datePhrase(rec)}</span><br/>
      À : <span style="color:#D71620">${rec.place}</span><br/>
      En article 21 : <span style="color:#D71620">${rec.type} – ${rec.days} jour(s)</span><br/>
      (Hors délai de route)
    </p>
    ${rec.comment ? `<p>Commentaire du demandeur : <span style="color:#D71620">${rec.comment}</span></p>` : ''}
    <p>Bonne fin de journée,</p>
    <p><strong>${req.admin.name}</strong><br/>${signTitle}</p>
  `;

  // TO = manager + RH + Reine + Chrystelle ; CC = demandeur + (pas de valideurs en copie)
  const TO = [rec.manager_email, rec.hr_email, 'reine.allaglo@csec-sg.com', 'chrystelle.agea@socgen.com'].filter(Boolean);
  const CC = [rec.applicant_email].filter(Boolean);

  try { await sendMail({ to: TO, cc: CC, subject, html }); }
  catch(e){ console.error('Mail validate err:', e?.message || e); }

  return res.json({ ok: true });
});

// Refus
app.post('/api/requests/:id/refuse', authRequired, async (req,res) => {
  const { id } = req.params;
  if (!isValidId(id)) return res.status(400).json({ error: 'Invalid id' });

  const rec = await Request.findById(id);
  if (!rec) return res.status(404).json({ error: 'Not found' });

  const reason = (req.body && req.body.reason) || '';
  rec.status = 'refused'; rec.refuse_reason = reason; await rec.save();

  const signTitle = getSignTitle(req.admin.email);
  const subject = `Refus de détachement – ${rec.full_name}`;
  const html = `
    <p>Bonjour,</p>
    <p>Votre demande de détachement a été <strong>refusée</strong>.</p>
    <p>
      Date(s) : <span style="color:#D71620">${datePhrase(rec)}</span><br/>
      Lieu : <span style="color:#D71620">${rec.place}</span><br/>
      Article 21 : <span style="color:#D71620">${rec.type} – ${rec.days} jour(s)</span>
    </p>
    ${reason ? `<p>Motif : <em>${reason}</em></p>` : ''}
    <p>Cordialement,</p>
    <p><strong>${req.admin.name}</strong><br/>${signTitle}</p>
  `;
  try { await sendMail({ to: rec.applicant_email, subject, html }); }
  catch(e){ console.error('Mail refuse err:', e?.message || e); }

  return res.json({ ok: true });
});

// Annulation
app.post('/api/requests/:id/cancel', authRequired, async (req,res) => {
  const { id } = req.params;
  if (!isValidId(id)) return res.status(400).json({ error: 'Invalid id' });

  const rec = await Request.findById(id);
  if (!rec) return res.status(404).json({ error: 'Not found' });

  const reason = (req.body && req.body.reason) || '';
  rec.status = 'cancelled'; rec.cancel_reason = reason; await rec.save();

  const signTitle = getSignTitle(req.admin.email);
  const subject = `Annulation de détachement – ${rec.full_name}`;
  const html = `
    <p>Bonjour,</p>
    <p>Votre demande de détachement a été <strong>annulée</strong>.</p>
    <p>
      Date(s) : <span style="color:#D71620">${datePhrase(rec)}</span><br/>
      Lieu : <span style="color:#D71620">${rec.place}</span><br/>
      Article 21 : <span style="color:#D71620">${rec.type} – ${rec.days} jour(s)</span>
    </p>
    ${reason ? `<p>Motif : <em>${reason}</em></p>` : ''}
    <p>Cordialement,</p>
    <p><strong>${req.admin.name}</strong><br/>${signTitle}</p>
  `;
  try { await sendMail({ to: rec.applicant_email, subject, html }); }
  catch(e){ console.error('Mail cancel err:', e?.message || e); }

  return res.json({ ok: true });
});

// Relances quotidiennes (à déclencher via Cron Render à 08:00 Europe/Paris)
app.post('/internal/cron/reminders', async (req,res) => {
  if (CRON_SECRET && req.query.token !== CRON_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const today = todayParisISO();
  const pending = await Request.find({ status: 'pending' });

  const admins = await Admin.find({}).lean();
  const adminEmails = admins.map(a => a.email);

  let sent = 0;
  for (const r of pending) {
    if (r.reminder_last_sent_on === today) continue;

    const subject = `Relance quotidienne — Détachement en attente — ${r.full_name}`;
    const html = `
      <p>Une demande de détachement est toujours en attente :</p>
      <ul>
        <li>Demandeur : <strong>${r.full_name}</strong> (${r.entity})</li>
        <li>Date(s) : ${datePhrase(r)}</li>
        <li>Lieu : ${r.place}</li>
        <li>Article 21 : ${r.type} – ${r.days} jour(s)</li>
        ${r.comment ? `<li>Commentaire : ${r.comment}</li>` : ''}
      </ul>
      <p>Espace validation : ${APP_BASE_URL}</p>
    `;
    try { await sendMail({ to: adminEmails, subject, html }); r.reminder_last_sent_on = today; await r.save(); sent++; }
    catch(e){ console.error('relance quotidienne — erreur mail:', e?.message || e); }
  }

  return res.json({ ok: true, sent });
});

// ====== Start ======
app.listen(PORT, () => console.log(`🚀 API listening on port ${PORT}`));
