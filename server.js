// server.js — Backend (Mongo + JWT + Mailtrap + Reminders) — CORS patché
const express = require('express');
const cors = require('cors');
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
  // URL de l’app front (affiché dans les emails)
  APP_BASE_URL = 'https://cgtsg-detachements-art21-csecsg.netlify.app',
  // secret pour la route cron
  CRON_SECRET = null,
} = process.env;

if (!MONGODB_URI || !JWT_SECRET) {
  console.error('Missing ENV: MONGODB_URI or JWT_SECRET');
  process.exit(1);
}

// ----- App -----
const app = express();

// CORS ULTRA-PERMISSIF (corrige les échecs "Load failed" dus au pré-vol)
const corsOptions = {
  origin: true, // reflète automatiquement l’Origin de la page appelante
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: false,
  maxAge: 86400, // cache du pré-vol (s)
};
app.use(cors(corsOptions));
// Répondre explicitement aux pré-vols (OPTIONS) pour toutes les routes
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '1mb' }));

// ----- DB -----
mongoose.set('strictQuery', true);
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });

// ----- Schemas -----
const AdminSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true, required: true },
    name: { type: String, required: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);

const RequestSchema = new mongoose.Schema(
  {
    full_name: String,
    applicant_email: String,
    entity: String,
    date_from: String, // yyyy-mm-dd
    date_to: String,
    start_period: { type: String, default: 'FULL' },
    end_period: { type: String, default: 'FULL' },
    place: String,
    type: String,
    days: Number,
    comment: String,
    manager_email: String,
    hr_email: String,
    status: { type: String, default: 'pending' }, // pending | sent | refused | cancelled
    created_at: { type: Date, default: () => new Date() },

    // relances
    reminder2_sent_at: Date, // J+2
    reminder4_sent_at: Date, // J+4

    // motifs (optionnels)
    refuse_reason: String,
    cancel_reason: String,
  },
  { timestamps: true }
);

const Admin = mongoose.model('Admin', AdminSchema);
const Request = mongoose.model('Request', RequestSchema);

// ----- Mailer (Mailtrap) -----
const transporter = nodemailer.createTransport({
  host: MAILTRAP_HOST,
  port: Number(MAILTRAP_PORT),
  auth: MAILTRAP_USER && MAILTRAP_PASS ? { user: MAILTRAP_USER, pass: MAILTRAP_PASS } : undefined,
});

async function sendMail({ to, cc = [], subject, html }) {
  // En mode test Mailtrap, l’envoi échoue si les credentials manquent : on no-op mais on log
  if (!MAILTRAP_HOST || !MAILTRAP_USER || !MAILTRAP_PASS) {
    console.log('[MAIL MOCK]', { to, cc, subject });
    return;
  }
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
  return jwt.sign(
    { sub: admin._id.toString(), name: admin.name, email: admin.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
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
  const [y, m, dd] = d.split('-');
  return `${dd}/${m}/${y}`;
}

// ----- Seed admins (1ère exécution) -----
async function seedAdmins() {
  const existing = await Admin.find({}).lean();
  if (existing.length) return;

  // MDP initiaux (à changer après la 1ère connexion)
  const SEB_EMAIL = 'sebastien.delgado@csec-sg.com';
  const LUDI_EMAIL = 'ludivine.perreaut@gmail.com';
  const SEB_PASS = 'SeB!24-9vQ@csec'; // ➜ à changer
  const LUDI_PASS = 'LuD!24-7mX@csec'; // ➜ à changer

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
  await a1.save();
  await a2.save();

  console.log('Admins seeded:');
  console.log(` - ${a1.name} <${SEB_EMAIL}> / MDP initial: ${SEB_PASS}`);
  console.log(` - ${a2.name} <${LUDI_EMAIL}> / MDP initial: ${LUDI_PASS}`);
}
seedAdmins().catch(console.error);

// ----- Health -----
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ----- Auth -----
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const admin = await Admin.findOne({ email });
  if (!admin) return res.status(401).json({ error: 'Identifiants invalides' });
  const ok = await bcrypt.compare(password || '', admin.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Identifiants invalides' });
  const token = signToken(admin);
  return res.json({ token, name: admin.name, email: admin.email });
});

app.post('/api/auth/change-password', authRequired, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const ok = await bcrypt.compare(currentPassword || '', req.admin.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Mot de passe actuel invalide' });
  req.admin.passwordHash = await bcrypt.hash(newPassword, 10);
  await req.admin.save();
  return res.json({ ok: true });
});

// ----- Requests -----
// Création : envoie un mail aux 2 admins
app.post('/api/requests', async (req, res) => {
  const b = req.body || {};
  const required = [
    'fullName',
    'applicantEmail',
    'entity',
    'dateFrom',
    'dateTo',
    'place',
    'type',
    'managerEmail',
    'hrEmail',
    'days',
  ];
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
    days: b.days,
    comment: b.comment || '',
    manager_email: b.managerEmail,
    hr_email: b.hrEmail,
    status: 'pending',
    created_at: new Date(),
  });

  // Récupère tous les admins
  const admins = await Admin.find({}).lean();
  const adminEmails = admins.map((a) => a.email);

  // Mail d’alerte aux admins
  const subject = `Nouvelle demande de détachement – ${rec.full_name}`;
  const html = `
    <p>Bonjour,</p>
    <p>Nouvelle demande de détachement soumise par <strong>${rec.full_name}</strong>.</p>
    <ul>
      <li>Entité : ${rec.entity}</li>
      <li>Dates : ${toFR(rec.date_from)} → ${toFR(rec.date_to)}</li>
      <li>Lieu : ${rec.place}</li>
      <li>Article 21 : ${rec.type} – ${rec.days} jour(s)</li>
      <li>Commentaire : ${rec.comment || '—'}</li>
    </ul>
    <p>Accéder à l'espace validation : ${APP_BASE_URL}</p>
  `;
  try {
    await sendMail({ to: adminEmails, subject, html });
  } catch (e) {
    console.error('Mail admins (création) err:', e.message);
  }

  return res.json({ ok: true, id: rec._id.toString() });
});

// Liste (par statut)
app.get('/api/requests', authRequired, async (req, res) => {
  const status = (req.query.status || '').toLowerCase();
  const q = status ? { status } : {};
  const items = await Request.find(q).sort({ created_at: -1 }).lean();
  return res.json({ items });
});

// Valider : envoie l’email signé par l’admin connecté
app.post('/api/requests/:id/validate', authRequired, async (req, res) => {
  const rec = await Request.findById(req.params.id);
  if (!rec) return res.status(404).json({ error: 'Not found' });
  rec.status = 'sent';
  await rec.save();

  const signName = req.admin.name;
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

  // Destinataires métier (manager + RH) + le demandeur en CC
  const to = [rec.manager_email, rec.hr_email].filter(Boolean);
  const cc = [rec.applicant_email].filter(Boolean);

  try {
    await sendMail({ to, cc, subject, html });
  } catch (e) {
    console.error('Mail validate err:', e.message);
  }

  return res.json({ ok: true });
});

// Refuser / Annuler
app.post('/api/requests/:id/refuse', authRequired, async (req, res) => {
  const rec = await Request.findById(req.params.id);
  if (!rec) return res.status(404).json({ error: 'Not found' });
  rec.status = 'refused';
  rec.refuse_reason = (req.body && req.body.reason) || '';
  await rec.save();
  return res.json({ ok: true });
});

app.post('/api/requests/:id/cancel', authRequired, async (req, res) => {
  const rec = await Request.findById(req.params.id);
  if (!rec) return res.status(404).json({ error: 'Not found' });
  rec.status = 'cancelled';
  rec.cancel_reason = (req.body && req.body.reason) || '';
  await rec.save();
  return res.json({ ok: true });
});

// ----- Cron: relances J+2 et J+4 -----
// Crée un "Cron Job" Render qui appelle cette route chaque jour à 08:00 Europe/Paris.
// Ajoute un secret ?token=XXX dans l’URL (et configure le même secret en ENV CRON_SECRET)
app.post('/internal/cron/reminders', async (req, res) => {
  if (CRON_SECRET && req.query.token !== CRON_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const now = dayjs(); // UTC
  const pending = await Request.find({ status: 'pending' });

  const admins = await Admin.find({}).lean();
  const adminEmails = admins.map((a) => a.email);

  let sent2 = 0,
    sent4 = 0;

  for (const r of pending) {
    const created = dayjs(r.created_at);
    const ageDays = now.diff(created, 'day');

    // J+2
    if (ageDays >= 2 && !r.reminder2_sent_at) {
      const subject = `Relance J+2 – Détachement en attente – ${r.full_name}`;
      const html = `
        <p>Relance J+2 — la demande suivante est toujours en attente :</p>
        <ul>
          <li>Demandeur : ${r.full_name} (${r.entity})</li>
          <li>Dates : ${toFR(r.date_from)} → ${toFR(r.date_to)}</li>
          <li>Lieu : ${r.place}</li>
          <li>Article 21 : ${r.type} – ${r.days} jour(s)</li>
        </ul>
        <p>Espace validation : ${APP_BASE_URL}</p>
      `;
      try {
        await sendMail({ to: adminEmails, subject, html });
        r.reminder2_sent_at = new Date();
        sent2++;
      } catch (e) {
        console.error('reminder J+2 mail err:', e.message);
      }
      await r.save();
    }

    // J+4
    if (ageDays >= 4 && !r.reminder4_sent_at) {
      const subject = `Relance J+4 – Détachement en attente – ${r.full_name}`;
      const html = `
        <p>Relance J+4 — la demande suivante est toujours en attente :</p>
        <ul>
          <li>Demandeur : ${r.full_name} (${r.entity})</li>
          <li>Dates : ${toFR(r.date_from)} → ${toFR(r.date_to)}</li>
          <li>Lieu : ${r.place}</li>
          <li>Article 21 : ${r.type} – ${r.days} jour(s)</li>
        </ul>
        <p>Espace validation : ${APP_BASE_URL}</p>
      `;
      try {
        await sendMail({ to: adminEmails, subject, html });
        r.reminder4_sent_at = new Date();
        sent4++;
      } catch (e) {
        console.error('reminder J+4 mail err:', e.message);
      }
      await r.save();
    }
  }

  return res.json({ ok: true, sent2, sent4 });
});

// ----- Start -----
app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
// ----- Global error handler (debug) -----
app.use((err, req, res, next) => {
  console.error('[ERROR]', err && err.stack ? err.stack : err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Server error', message: String(err && err.message || err) });
});
