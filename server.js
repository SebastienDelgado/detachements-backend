// server.js — Backend production-ready (Mongo + JWT + SMTP + Reminders)
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// ----- Config -----
const {
  PORT = 3000,
  MONGODB_URI,
  JWT_SECRET,
  SMTP_HOST,
  SMTP_PORT = 587,
  SMTP_USER,
  SMTP_PASS,
  APP_BASE_URL = 'http://localhost:5173',
  CRON_SECRET
} = process.env;

if (!MONGODB_URI || !JWT_SECRET) {
  console.error('Missing ENV: MONGODB_URI or JWT_SECRET');
  process.exit(1);
}

const ALLOWED_ORIGINS = [
  APP_BASE_URL,
  'http://localhost:5173',
  'http://localhost:3000',
];

// ----- App -----
const app = express();
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(null, true);
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','Accept'],
}));
app.use(express.json());

// ----- DB -----
mongoose.set('strictQuery', true);
mongoose.connect(MONGODB_URI).then(()=>console.log('MongoDB connected')).catch((e)=>{console.error("MongoDB connection error:", e); process.exit(1);});

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
  status: { type: String, default: 'pending' },
  created_at: { type: Date, default: () => new Date() },
  reminder_last_sent_on: String
}, { timestamps: true });

const Admin = mongoose.model('Admin', AdminSchema);
const Request = mongoose.model('Request', RequestSchema);

// ----- Mailer -----
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT),
  auth: { user: SMTP_USER, pass: SMTP_PASS },
});

async function sendMail({ to, cc = [], subject, html }) {
  return transporter.sendMail({
    from: '"CSEC SG - Détachements" <no-reply@csec-sg.com>',
    to: Array.isArray(to) ? to.join(', ') : to,
    cc: Array.isArray(cc) ? cc.join(', ') : cc,
    subject,
    html,
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

function fmtDatePhrase(r) {
  if (!r.date_from) return "—";
  if (r.date_from === r.date_to) {
    if (r.start_period === 'PM') return `${toFR(r.date_from)} (Après-midi)`;
    if (r.end_period === 'AM') return `${toFR(r.date_from)} (Matin)`;
    return toFR(r.date_from);
  }
  let phrase = `${toFR(r.date_from)} au ${toFR(r.date_to)}`;
  if (r.start_period === 'PM') phrase += " (Début: Après-midi)";
  if (r.end_period === 'AM') phrase += " (Fin: Matin)";
  return phrase;
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
  if (email === 'sebastien.delgado@csec-sg.com') {
    return 'Secrétaire Adjoint du CSEC SG';
  } else if (email === 'ludivine.perreaut@gmail.com') {
    return 'Représentante Syndicale Nationale CGT';
  }
  return 'CSEC SG';
}

// ----- Seed admins -----
async function seedAdmins() {
  const existing = await Admin.find({}).lean();
  if (existing.length) return;
  const SEB_EMAIL = 'sebastien.delgado@csec-sg.com';
  const LUDI_EMAIL = 'ludivine.perreaut@gmail.com';
  const SEB_PASS = 'SeB!24-9vQ@csec';
  const LUDI_PASS = 'LuD!24-7mX@csec';
  const a1 = new Admin({
    email: SEB_EMAIL,
    name: 'Sébastien DELGADO',
    passwordHash: await bcrypt.hash(SEB_PASS, 10),
  });
  const a2 = new Admin({
    email: LUDI_EMAIL,
    name: 'Ludivine PERREAUT',
    passwordHash: await bcrypt.hash(LUDI_PASS, 10),
  });
  await a1.save(); await a2.save();
}
seedAdmins().catch(console.error);

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
app.post('/api/requests', async (req,res) => {
  const b = req.body || {};
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
    days: b.days,
    comment: b.comment || '',
    manager_email: b.managerEmail,
    hr_email: b.hrEmail,
    status: 'pending',
    created_at: new Date(),
  });

  const admins = await Admin.find({}).lean();
  const adminEmails = admins.map(a => a.email);

  const subject = `Nouvelle demande de détachement – ${rec.full_name}`;
  const html = `
    <p>Bonjour,</p>
    <p>Nouvelle demande de détachement soumise par <strong>${rec.full_name}</strong>.</p>
    <ul>
      <li>Entité : ${rec.entity}</li>
      <li>Date(s) : ${fmtDatePhrase(rec)}</li>
      <li>Lieu : ${rec.place}</li>
      <li>Article 21 : ${rec.type} – ${rec.days} jour(s)</li>
      <li>Commentaire : ${rec.comment || '—'}</li>
    </ul>
    <p>Accéder à l'espace validation : ${APP_BASE_URL}</p>
  `;
  try { await sendMail({ to: adminEmails, subject, html }); } catch (e) { console.error(e.message); }

  return res.json({ ok: true, id: rec._id.toString() });
});

app.get('/api/requests', authRequired, async (req,res) => {
  const status = (req.query.status || '').toLowerCase();
  const q = status ? { status } : {};
  const items = await Request.find(q).sort({ created_at: -1 }).lean();
  return res.json({ items });
});

app.post('/api/requests/:id/validate', authRequired, async (req,res) => {
  const rec = await Request.findById(req.params.id);
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
      Date(s) : <span style="color:#D71620">${fmtDatePhrase(rec)}</span><br/>
      À : <span style="color:#D71620">${rec.place}</span><br/>
      En article 21 : <span style="color:#D71620">${rec.type} – ${rec.days} jour(s)</span><br/>
      (Hors délai de route)
    </p>
    ${rec.comment ? `<p>Commentaire du demandeur : <span style="color:#D71620">${rec.comment}</span></p>` : ''}
    <p>Bonne fin de journée,</p>
    <p><strong>${req.admin.name}</strong><br/>${signTitle}</p>
  `;

  const to = [rec.manager_email, rec.hr_email, "reine.allaglo@csec-sg.com", "chrystelle.agea@socgen.com"].filter(Boolean);
  const cc = [rec.applicant_email, "sebastien.delgado@csec-sg.com", "ludivine.perreaut@gmail.com"].filter(Boolean);

  try { await sendMail({ to, cc, subject, html }); } catch (e) { console.error(e.message); }

  return res.json({ ok: true });
});

app.post('/api/requests/:id/refuse', authRequired, async (req,res) => {
  const rec = await Request.findById(req.params.id);
  if (!rec) return res.status(404).json({ error: 'Not found' });
  rec.status = 'refused';
  rec.refuse_reason = (req.body && req.body.reason) || '';
  await rec.save();

  const signTitle = getSignTitle(req.admin.email);
  const subject = `Refus – Détachement – ${rec.full_name}`;
  const html = `
    <p>Bonjour,</p>
    <p>Votre demande a été <strong>refusée</strong>.</p>
    <p>Date(s) : ${fmtDatePhrase(rec)}<br/>
    Lieu : ${rec.place}<br/>
    Article 21 : ${rec.type} – ${rec.days} jour(s)</p>
    ${rec.refuse_reason ? `<p>Motif : ${rec.refuse_reason}</p>` : ''}
    <p>Cordialement,</p>
    <p><strong>${req.admin.name}</strong><br/>${signTitle}</p>
  `;

  try { await sendMail({ to: rec.applicant_email, subject, html }); } catch (e) { console.error(e.message); }

  return res.json({ ok: true });
});

app.post('/api/requests/:id/cancel', authRequired, async (req,res) => {
  const rec = await Request.findById(req.params.id);
  if (!rec) return res.status(404).json({ error: 'Not found' });
  rec.status = 'cancelled';
  rec.cancel_reason = (req.body && req.body.reason) || '';
  await rec.save();

  const signTitle = getSignTitle(req.admin.email);
  const subject = `Annulation – Détachement – ${rec.full_name}`;
  const html = `
    <p>Bonjour,</p>
    <p>Votre demande a été <strong>annulée</strong>.</p>
    <p>Date(s) : ${fmtDatePhrase(rec)}<br/>
    Lieu : ${rec.place}<br/>
    Article 21 : ${rec.type} – ${rec.days} jour(s)</p>
    ${rec.cancel_reason ? `<p>Motif : ${rec.cancel_reason}</p>` : ''}
    <p>Cordialement,</p>
    <p><strong>${req.admin.name}</strong><br/>${signTitle}</p>
  `;

  try { await sendMail({ to: rec.applicant_email, subject, html }); } catch (e) { console.error(e.message); }

  return res.json({ ok: true });
});

// ----- Cron: relance quotidienne -----
app.post('/internal/cron/reminders', async (req,res) => {
  if (CRON_SECRET && req.query.token !== CRON_SECRET) return res.status(403).json({ error: 'Forbidden' });

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
        <li>Date(s) : ${fmtDatePhrase(r)}</li>
        <li>Lieu : ${r.place}</li>
        <li>Article 21 : ${r.type} – ${r.days} jour(s)</li>
        ${r.comment ? `<li>Commentaire : ${r.comment}</li>` : ''}
      </ul>
      <p>Espace validation : ${APP_BASE_URL}</p>
    `;
    try { await sendMail({ to: adminEmails, subject, html }); r.reminder_last_sent_on = today; await r.save(); sent++; } catch(e){ console.error(e.message); }
  }
  return res.json({ ok: true, sent });
});

// ----- Start -----
app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
