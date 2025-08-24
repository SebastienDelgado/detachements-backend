// server.js — Détachements CSEC SG (in-memory)
// Fonctions : Auth, création/listing/validation/refus/annulation, envoi mails (Mailtrap par défaut)

const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

/* =========================
   CORS
   ========================= */
app.use(cors({
  origin: (origin, cb) => {
    const allowed = (process.env.CORS_ORIGINS || '*')
      .split(',').map(o => o.trim()).filter(Boolean);
    if (!origin || allowed.includes('*') || allowed.includes(origin)) cb(null, true);
    else cb(new Error('Not allowed by CORS'));
  }
}));
app.use(express.json());

/* =========================
   SMTP (Mailtrap par défaut)
   ========================= */
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "sandbox.smtp.mailtrap.io",
  port: Number(process.env.SMTP_PORT || 587),
  auth: {
    user: process.env.SMTP_USER || "YOUR_MAILTRAP_USER",
    pass: process.env.SMTP_PASS || "YOUR_MAILTRAP_PASS",
  }
});

// Expéditeur
const MAIL_FROM = process.env.MAIL_FROM || "no-reply@example.com";
const MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || "CSEC SG – Détachements";

/* =========================
   Helpers
   ========================= */
function cleanEmail(s) {
  return (s || "")
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, '')
    .replace(/[\u00A0\u1680\u2000-\u200D\u202F\u205F\u3000\uFEFF]/g, '')
    .trim();
}
function isEmail(s) {
  const x = cleanEmail(s);
  const re = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;
  return re.test(x);
}
function mustBeEmail(label, s) {
  const v = cleanEmail(s);
  if (!isEmail(v)) throw new Error(`${label} invalide`);
  return v;
}
function formatDateFR(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr + 'T00:00:00Z');
  if (isNaN(d.getTime())) return dateStr;
  return d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric' });
}
function fmtDays(n) {
  const v = Number(n) || 0;
  const s = (v % 1 === 0.5) ? (Math.floor(v) + ',5') : String(v);
  return `${s} jour${v > 1 ? 's' : ''}`;
}
function computeDays(dFrom, dTo, sp, ep) {
  if (!dFrom) return 0;
  if (!dTo) dTo = dFrom;
  const from = new Date(dFrom + "T00:00:00Z");
  const to = new Date(dTo + "T00:00:00Z");
  if (isNaN(from) || isNaN(to)) return 0;
  const base = Math.floor((to - from) / (24 * 3600 * 1000)) + 1;
  sp = (sp || 'FULL').toUpperCase();
  ep = (ep || 'FULL').toUpperCase();
  if (dFrom === dTo) {
    if (sp === 'FULL' || ep === 'FULL') return 1;
    if (sp === 'AM' && ep === 'PM') return 1;
    if (sp === 'AM' && ep === 'AM') return 0.5;
    if (sp === 'PM' && ep === 'PM') return 0.5;
    return 1;
  }
  let total = base;
  if (sp === 'PM') total -= 0.5;
  if (ep === 'AM') total -= 0.5;
  return total;
}

/* =========================
   Storage en mémoire
   ========================= */
const DB = {
  requests: new Map(), // id -> record
  tokens: new Set(),   // jetons actifs
};

// Normalisation et validation de payload côté serveur
function normalizeRequestPayload(body) {
  const fullName = (body.fullName || body.full_name || '').toString().trim();
  const applicantEmail = mustBeEmail('E-mail demandeur', body.applicantEmail || body.applicant_email);
  const entity = (body.entity || '').toString().trim();

  const dateFrom = (body.dateFrom || body.date_from || '').toString().trim();
  const dateTo = (body.dateTo || body.date_to || dateFrom || '').toString().trim();
  const startPeriod = (body.startPeriod || body.start_period || 'FULL').toString().toUpperCase();
  const endPeriod = (body.endPeriod || body.end_period || 'FULL').toString().toUpperCase();

  const place = (body.place || '').toString().trim();
  const type = (body.type || '').toString().trim(); // "21B" | "21C" | "Pour Information"
  const managerEmail = mustBeEmail('E-mail N+1', body.managerEmail || body.manager_email);
  const hrEmail = mustBeEmail('E-mail DDRH/RH', body.hrEmail || body.hr_email);
  const comment = (body.comment || '').toString().trim();

  // Guard règles de date
  if (!dateFrom) throw new Error("Date de début manquante");
  if (dateTo && dateTo < dateFrom) throw new Error("La date de fin ne peut pas être antérieure à la date de début");
  if (dateFrom === dateTo && startPeriod === 'PM' && endPeriod === 'AM') {
    throw new Error("Pour une même journée, choisissez Matin puis Après-midi, ou Journée complète");
  }

  const days = Number(body.days ?? computeDays(dateFrom, dateTo, startPeriod, endPeriod)) || 0;

  return {
    full_name: fullName,
    applicant_email: applicantEmail,
    entity,
    date_from: dateFrom,
    date_to: dateTo,
    start_period: startPeriod,
    end_period: endPeriod,
    place,
    type,
    manager_email: managerEmail,
    hr_email: hrEmail,
    comment,
    days
  };
}

/* =========================
   Auth très simple (admin)
   ========================= */
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@example.com').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'adminpass';

function authMiddleware(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
  if (token && DB.tokens.has(token)) return next();
  return res.status(401).json({ error: 'Non autorisé' });
}

app.post('/api/auth/login', (req, res) => {
  const email = (req.body.email || '').toLowerCase().trim();
  const password = req.body.password || '';
  if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
    const token = crypto.randomBytes(24).toString('hex');
    DB.tokens.add(token);
    return res.json({ token });
  }
  return res.status(401).json({ error: 'Identifiants invalides' });
});

/* =========================
   Health
   ========================= */
app.get('/api/health', (req, res) => res.json({ ok: true }));

/* =========================
   API demandes (in-memory)
   ========================= */

// Création
app.post('/api/requests', (req, res) => {
  try {
    const payload = normalizeRequestPayload(req.body || {});
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const rec = {
      id,
      status: 'pending',
      created_at: now,
      validated_at: null,
      decision_at: null,
      decision_reason: null,
      ...payload,
    };

    DB.requests.set(id, rec);
    return res.json({ ok: true, id });
  } catch (err) {
    return res.status(400).json({ error: err.message || 'Payload invalide' });
  }
});

// Listing par statut (admin uniquement)
app.get('/api/requests', authMiddleware, (req, res) => {
  const status = (req.query.status || '').toLowerCase();
  const items = [];
  for (const r of DB.requests.values()) {
    if (!status || r.status === status) items.push(r);
  }
  // Tri du plus récent au plus ancien
  items.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
  return res.json({ items });
});

// Validation + envoi mail
app.post('/api/requests/:id/validate', authMiddleware, async (req, res) => {
  try {
    const rec = DB.requests.get(req.params.id);
    if (!rec) return res.status(404).json({ error: 'Demande introuvable' });

    // Règles destinataires
    const toList = [
      cleanEmail(rec.manager_email),
      cleanEmail(rec.hr_email),
      "reine.allaglo@csec-sg.com",
      "chrystelle.agea@socgen.com"
    ].filter(isEmail);

    const ccList = [
      "sebastien.delgado@csec-sg.com",
      "ludivine.perreaut@gmail.com",
      cleanEmail(rec.applicant_email)
    ].filter(isEmail);

    const subject = `Détachement – ${rec.full_name || '—'}`;
    const dateFR = (rec.date_from === rec.date_to || !rec.date_to)
      ? formatDateFR(rec.date_from)
      : `${formatDateFR(rec.date_from)} au ${formatDateFR(rec.date_to)}`;

    const html = `
      <div style="font-family: Arial, sans-serif; font-size: 12pt; color: #000;">
        <p>Bonjour,</p>
        <p>Merci de bien vouloir noter le détachement de :<br/>
          <span style="color:#D71620;">${(rec.full_name || '—')}${rec.entity ? ' – ' + rec.entity : ''}</span></p>
        <p>
          Le(s) : <span style="color:#D71620;">${dateFR}</span><br/>
          À : <span style="color:#D71620;">${rec.place || '—'}</span><br/>
          En article 21 : <span style="color:#D71620;">${(rec.type || '—')} – ${fmtDays(rec.days)}</span><br/>
          (Hors délai de route)
        </p>
        ${rec.comment ? `<p>Commentaire du demandeur : <span style="color:#D71620;">${rec.comment}</span></p>` : ''}
        <p>Bonne fin de journée,</p>
        <p><strong>Sébastien DELGADO</strong><br/>Secrétaire Adjoint – CSEC SG<br/>sebastien.delgado@csec-sg.com<br/>06 74 98 48 68</p>
        <p style="margin-top:8px;"><strong>Ludivine PERREAUT</strong><br/>Responsable Syndicale Nationale CGT SG auprès du CSEC SG<br/>ludivine.perreaut@gmail.com<br/>06 82 83 84 84</p>
      </div>
    `;

    await transporter.sendMail({
      from: `"${MAIL_FROM_NAME}" <${MAIL_FROM}>`,
      to: toList.join(', '),
      cc: ccList.join(', '),
      subject,
      html
    });

    rec.status = 'sent';
    rec.validated_at = new Date().toISOString();
    DB.requests.set(rec.id, rec);

    return res.json({ ok: true, id: rec.id, to: toList, cc: ccList });
  } catch (err) {
    console.error('Erreur envoi validation:', err);
    return res.status(500).json({ error: 'Envoi email échoué' });
  }
});

// Refus (mail au demandeur, double signature)
app.post('/api/requests/:id/refuse', authMiddleware, async (req, res) => {
  try {
    const rec = DB.requests.get(req.params.id);
    if (!rec) return res.status(404).json({ error: 'Demande introuvable' });
    const reason = (req.body && req.body.reason || '').toString().trim();
    if (!reason) return res.status(400).json({ error: 'Motif requis' });

    const subject = "Refus de votre demande de détachement";
    const html = `
      <div style="font-family: Arial, sans-serif; font-size: 12pt; color: #000;">
        <p>Bonjour <span style="color:#D71620;">${rec.full_name || '—'}</span>,</p>
        <p>Votre demande de détachement a été 
          <strong style="color:#D71620;">refusée</strong>.
        </p>
        <p><u>Motif :</u> <span style="color:#D71620;">${reason}</span></p>
        <br/>
        <p>Cordialement,</p>
        <p><strong>Sébastien DELGADO</strong><br/>Secrétaire Adjoint – CSEC SG</p>
        <p><strong>Ludivine PERREAUT</strong><br/>Responsable Syndicale Nationale CGT SG auprès du CSEC SG<br/>06 82 83 84 84</p>
      </div>
    `;

    await transporter.sendMail({
      from: `"Sébastien & Ludivine (CSEC SG)" <${MAIL_FROM}>`,
      to: cleanEmail(rec.applicant_email),
      subject,
      html
    });

    rec.status = 'refused';
    rec.decision_at = new Date().toISOString();
    rec.decision_reason = reason;
    DB.requests.set(rec.id, rec);

    return res.json({ ok: true });
  } catch (err) {
    console.error('Erreur refus:', err);
    return res.status(500).json({ error: 'Envoi email échoué' });
  }
});

// Annulation (mail au demandeur, double signature)
app.post('/api/requests/:id/cancel', authMiddleware, async (req, res) => {
  try {
    const rec = DB.requests.get(req.params.id);
    if (!rec) return res.status(404).json({ error: 'Demande introuvable' });
    const reason = (req.body && req.body.reason || '').toString().trim();
    if (!reason) return res.status(400).json({ error: 'Motif requis' });

    const subject = "Annulation de votre demande de détachement";
    const html = `
      <div style="font-family: Arial, sans-serif; font-size: 12pt; color: #000;">
        <p>Bonjour <span style="color:#D71620;">${rec.full_name || '—'}</span>,</p>
        <p>Votre demande de détachement a été 
          <strong style="color:#D71620;">annulée</strong>.
        </p>
        <p><u>Motif :</u> <span style="color:#D71620;">${reason}</span></p>
        <br/>
        <p>Cordialement,</p>
        <p><strong>Sébastien DELGADO</strong><br/>Secrétaire Adjoint – CSEC SG</p>
        <p><strong>Ludivine PERREAUT</strong><br/>Responsable Syndicale Nationale CGT SG auprès du CSEC SG<br/>06 82 83 84 84</p>
      </div>
    `;

    await transporter.sendMail({
      from: `"Sébastien & Ludivine (CSEC SG)" <${MAIL_FROM}>`,
      to: cleanEmail(rec.applicant_email),
      subject,
      html
    });

    rec.status = 'cancelled';
    rec.decision_at = new Date().toISOString();
    rec.decision_reason = reason;
    DB.requests.set(rec.id, rec);

    return res.json({ ok: true });
  } catch (err) {
    console.error('Erreur annulation:', err);
    return res.status(500).json({ error: 'Envoi email échoué' });
  }
});

/* =========================
   Accueil & démarrage
   ========================= */
app.get('/', (req, res) => {
  res.type('html').send(`
    <h1>Détachements API</h1>
    <p>Service en ligne ✅</p>
    <p>Healthcheck: <a href="/api/health">/api/health</a></p>
  `);
});

app.listen(PORT, () => {
  console.log(`✅ API running on port ${PORT}`);
});
