// server.js — Backend (Mongo + JWT + SMTP/Mailtrap + Alertes + Relances + mails refus/annulation)
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const dayjs = require('dayjs');

// ----- ENV -----
const {
  PORT = 3000,
  MONGODB_URI,
  JWT_SECRET,
  APP_BASE_URL = 'http://localhost:5173',
  CRON_SECRET,

  // SMTP prioritaire (ou Mailtrap en fallback)
  SMTP_HOST = process.env.MAILTRAP_HOST || 'sandbox.smtp.mailtrap.io',
  SMTP_PORT = Number(process.env.MAILTRAP_PORT || process.env.SMTP_PORT || 2525),
  SMTP_USER = process.env.MAILTRAP_USER || process.env.SMTP_USER,
  SMTP_PASS = process.env.MAILTRAP_PASS || process.env.SMTP_PASS,

  MAIL_FROM = process.env.MAIL_FROM || 'no-reply@csec-sg.com',
  MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || 'CSEC SG - Détachements',
} = process.env;

if (!MONGODB_URI || !JWT_SECRET) {
  console.error('❌ Missing ENV: MONGODB_URI or JWT_SECRET');
  process.exit(1);
}

// ----- App & CORS -----
const app = express();
app.use((req, res, next) => {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || 'Content-Type, Authorization, Accept');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});
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

// ----- Models -----
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
  reminder2_sent_at: Date,
  reminder4_sent_at: Date,
  refuse_reason: String,
  cancel_reason: String,
}, { timestamps: true });

const Admin = mongoose.model('Admin', AdminSchema);
const Request = mongoose.model('Request', RequestSchema);

// ----- Mailer (SMTP / Mailtrap) -----
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
});
async function sendMail({ to, cc = [], subject, html }) {
  return transporter.sendMail({
    from: `"${MAIL_FROM_NAME}" <${MAIL_FROM}>`,
    to: Array.isArray(to) ? to.join(', ') : to,
    cc: Array.isArray(cc) ? cc.join(', ') : cc,
    subject, html,
  });
}
transporter.verify()
  .then(() => console.log(`📮 SMTP ready (${SMTP_HOST}:${SMTP_PORT})`))
  .catch(e => console.error('📮 SMTP verify failed:', e?.message || e));

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
    req.admin = admin; next();
  } catch { return res.status(401).json({ error: 'Unauthorized' }); }
}
function toFR(d) {
  if (!d || !/\d{4}-\d{2}-\d{2}/.test(d)) return d || '—';
  const [y,m,dd] = d.split('-'); return `${dd}/${m}/${y}`;
}

// Formatte les dates avec 1/2 journées (pour les e-mails)
function datePhrase(rec) {
  const a = rec.date_from, b = rec.date_to, sp = (rec.start_period||'FULL'), ep = (rec.end_period||'FULL');
  const A = toFR(a), B = toFR(b);
  if (!a && !b) return '—';
  if (!b || a === b) {
    if (sp === 'AM' && ep === 'AM') return `${A} (Matin)`;
    if (sp === 'PM' && ep === 'PM') return `${A} (Après-midi)`;
    if (sp === 'AM' && ep === 'PM') return `${A}`; // journée entière
    if (sp === 'FULL' || ep === 'FULL') return `${A}`; // journée entière
    return `${A}`; // fallback
  }
  // plage multi-jours
  let tail = [];
  if (sp === 'PM') tail.push('Début : Après-midi');
  if (ep === 'AM') tail.push('Fin : Matin');
  return `Du ${A} au ${B}${tail.length ? ' — ' + tail.join(', ') : ''}`;
}

// ----- Seed admins à la 1ère connexion -----
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

// ----- Health & debug -----
app.get('/api/health', (req,res) => res.json({ ok: true }));
app.get('/api/mail-verify', async (req,res) => {
  try { await transporter.verify(); res.json({ ok:true, host: SMTP_HOST, port: SMTP_PORT }); }
  catch(e){ res.status(500).json({ ok:false, error:e.message, host:SMTP_HOST, port:SMTP_PORT }); }
});

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
// Création + alerte aux admins
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

// Liste par statut
app.get('/api/requests', authRequired, async (req,res) => {
  const status = (req.query.status || '').toLowerCase();
  const q = status ? { status } : {};
  const items = await Request.find(q).sort({ created_at: -1 }).lean();
  return res.json({ items });
});

// ----- VALIDATE -----
app.post('/api/requests/:id/validate', authRequired, async (req,res) => {
  const rec = await Request.findById(req.params.id);
  if (!rec) return res.status(404).json({ error: 'Not found' });

  rec.status = 'sent'; await rec.save();

  const signName = req.admin.name || 'Administrateur';
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
    <p><strong>${signName}</strong><br/>CSEC SG</p>
  `;

  // Destinataires :
  // A = manager + RH + Reine + Chrystelle
  // CC = demandeur + Sébastien + Ludivine
  const TO = [rec.manager_email, rec.hr_email, 'reine.allaglo@csec-sg.com', 'chrystelle.agea@socgen.com'].filter(Boolean);
  const CC = [rec.applicant_email, 'sebastien.delgado@csec-sg.com', 'ludivine.perreaut@gmail.com'].filter(Boolean);

  try { await sendMail({ to: TO, cc: CC, subject, html }); }
  catch(e){ console.error('Mail validate err:', e?.message || e); }

  return res.json({ ok: true });
});

// ----- REFUSE -----
app.post('/api/requests/:id/refuse', authRequired, async (req,res) => {
  const rec = await Request.findById(req.params.id);
  if (!rec) return res.status(404).json({ error: 'Not found' });
  const reason = (req.body && req.body.reason) || '';
  rec.status = 'refused'; rec.refuse_reason = reason; await rec.save();

  const subject = `Refus de détachement – ${rec.full_name}`;
  const html = `
    <p>Bonjour,</p>
    <p>Votre demande de détachement a été <strong>refusée</strong>.</p>
    <ul>
      <li>Demandeur : ${rec.full_name} (${rec.entity})</li>
      <li>Date(s) : ${datePhrase(rec)}</li>
      <li>Lieu : ${rec.place}</li>
      <li>Article 21 : ${rec.type} – ${rec.days} jour(s)</li>
    </ul>
    ${reason ? `<p>Motif : <em>${reason}</em></p>` : ''}
    <p>Cordialement,</p>
    <p><strong>${req.admin.name || 'CSEC SG'}</strong></p>
  `;
  try {
    const admins = await Admin.find({}).lean();
    const cc = admins.map(a => a.email);
    await sendMail({ to: rec.applicant_email, cc, subject, html });
  } catch(e){ console.error('Mail refuse err:', e?.message || e); }

  return res.json({ ok: true });
});

// ----- CANCEL -----
app.post('/api/requests/:id/cancel', authRequired, async (req,res) => {
  const rec = await Request.findById(req.params.id);
  if (!rec) return res.status(404).json({ error: 'Not found' });
  const reason = (req.body && req.body.reason) || '';
  rec.status = 'cancelled'; rec.cancel_reason = reason; await rec.save();

  const subject = `Annulation de détachement – ${rec.full_name}`;
  const html = `
    <p>Bonjour,</p>
    <p>Votre demande de détachement a été <strong>annulée</strong>.</p>
    <ul>
      <li>Demandeur : ${rec.full_name} (${rec.entity})</li>
      <li>Date(s) : ${datePhrase(rec)}</li>
      <li>Lieu : ${rec.place}</li>
      <li>Article 21 : ${rec.type} – ${rec.days} jour(s)</li>
    </ul>
    ${reason ? `<p>Motif : <em>${reason}</em></p>` : ''}
    <p>Cordialement,</p>
    <p><strong>${req.admin.name || 'CSEC SG'}</strong></p>
  `;
  try {
    const admins = await Admin.find({}).lean();
    const cc = admins.map(a => a.email);
    await sendMail({ to: rec.applicant_email, cc, subject, html });
  } catch(e){ console.error('Mail cancel err:', e?.message || e); }

  return res.json({ ok: true });
});

// ----- Cron: relances J+2 & J+4 -----
app.post('/internal/cron/reminders', async (req,res) => {
  if (CRON_SECRET && req.query.token !== CRON_SECRET) return res.status(403).json({ error: 'Forbidden' });

  const now = dayjs();
  const pending = await Request.find({ status: 'pending' });
  const admins = await Admin.find({}).lean();
  const adminEmails = admins.map(a => a.email);

  let sent2 = 0, sent4 = 0;

  for (const r of pending) {
    const ageDays = now.diff(dayjs(r.created_at), 'day');

    if (ageDays >= 2 && !r.reminder2_sent_at) {
      const subject = `Relance J+2 – Détachement en attente – ${r.full_name}`;
      const html = `
        <p>Relance J+2 — la demande suivante est toujours en attente :</p>
        <ul>
          <li>Demandeur : ${r.full_name} (${r.entity})</li>
          <li>Date(s) : ${datePhrase(r)}</li>
          <li>Lieu : ${r.place}</li>
          <li>Article 21 : ${r.type} – ${r.days} jour(s)</li>
        </ul>
        <p>Espace validation : ${APP_BASE_URL}</p>
      `;
      try { await sendMail({ to: adminEmails, subject, html }); r.reminder2_sent_at = new Date(); sent2++; }
      catch(e){ console.error('reminder J+2 mail err:', e?.message || e); }
      await r.save();
    }

    if (ageDays >= 4 && !r.reminder4_sent_at) {
      const subject = `Relance J+4 – Détachement en attente – ${r.full_name}`;
      const html = `
        <p>Relance J+4 — la demande suivante est toujours en attente :</p>
        <ul>
          <li>Demandeur : ${r.full_name} (${r.entity})</li>
          <li>Date(s) : ${datePhrase(r)}</li>
          <li>Lieu : ${r.place}</li>
          <li>Article 21 : ${r.type} – ${r.days} jour(s)</li>
        </ul>
        <p>Espace validation : ${APP_BASE_URL}</p>
      `;
      try { await sendMail({ to: adminEmails, subject, html }); r.reminder4_sent_at = new Date(); sent4++; }
      catch(e){ console.error('reminder J+4 mail err:', e?.message || e); }
      await r.save();
    }
  }

  return res.json({ ok: true, sent2, sent4 });
});

// ----- Start -----
app.listen(PORT, () => console.log(`🚀 API listening on port ${PORT}`));
