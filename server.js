// server.js — backend complet (mémoire) pour la recette/POC
// Routes utilisées par le front :
//  - POST   /api/auth/login
//  - GET    /api/health
//  - POST   /api/requests
//  - GET    /api/requests?status=pending|sent|refused|cancelled
//  - POST   /api/requests/:id/validate
//  - POST   /api/requests/:id/refuse   (body: { reason })
//  - POST   /api/requests/:id/cancel   (body: { reason })

const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// ---------- Utilitaires ----------
function normalizeEmail(s) { return (s || '').trim().replace(/\s+/g, ''); }
function isEmail(s) { return /^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/.test((s || '').trim()); }
function toFR(dateStr) {
  try { if (!dateStr) return '—'; const [y, m, d] = dateStr.split('-'); return `${d}/${m}/${y}`; }
  catch { return dateStr || '—'; }
}
function computeDays(dFrom, dTo, startP, endP) {
  if (!dFrom) return 0;
  if (!dTo) dTo = dFrom;
  const from = new Date(dFrom + "T00:00:00Z");
  const to   = new Date(dTo   + "T00:00:00Z");
  const day  = 24 * 60 * 60 * 1000;
  const base = Math.floor((to - from) / day) + 1;
  if (isNaN(base)) return 0;
  startP = (startP || "FULL").toUpperCase();
  endP   = (endP   || "FULL").toUpperCase();
  if (dFrom === dTo) {
    if (startP === "FULL" || endP === "FULL") return 1;
    if (startP === "AM" && endP === "PM") return 1;
    if (startP === "AM" && endP === "AM") return 0.5;
    if (startP === "PM" && endP === "PM") return 0.5;
    return 1;
  }
  let total = base;
  if (startP === "PM") total -= 0.5;
  if (endP   === "AM") total -= 0.5;
  return total;
}
function fmtDaysFR(n) {
  if (n === undefined || n === null) return '—';
  const s = (n % 1 === 0.5) ? (Math.floor(n) + ",5") : String(n);
  return `${s} jour${n > 1 ? 's' : ''}`;
}
function uid() {
  if (global.crypto?.randomUUID) return global.crypto.randomUUID();
  return require('crypto').randomUUID();
}

// ---------- Config Admin / Mail ----------
const ADMIN_EMAIL    = (process.env.ADMIN_EMAIL || '').trim();
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || '').trim();
const ADMIN_TOKEN    = process.env.ADMIN_TOKEN || 'detachements-demo-token';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "sandbox.smtp.mailtrap.io",
  port: Number(process.env.SMTP_PORT || 587),
  auth: {
    user: process.env.SMTP_USER || "YOUR_MAILTRAP_USER",
    pass: process.env.SMTP_PASS || "YOUR_MAILTRAP_PASS"
  }
});
const MAIL_FROM      = process.env.MAIL_FROM      || 'test@example.com';
const MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || 'Sébastien DELGADO';

// ---------- Middleware ----------
app.use(cors({
  origin: (origin, cb) => {
    const allowed = (process.env.CORS_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean);
    if (!origin || allowed.length === 0 || allowed.includes(origin)) cb(null, true);
    else cb(new Error('Not allowed by CORS'));
  }
}));
app.use(express.json());

// ---------- Stockage en mémoire (recette) ----------
const REQUESTS = [];

// ---------- Routes ----------
app.get('/', (req, res) => {
  res.type('html').send(`
    <h1>Détachements API</h1>
    <p>Service en ligne ✅</p>
    <p>Healthcheck: <a href="/api/health">/api/health</a></p>
  `);
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/auth/login', (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || '');
    if (!email || !password) {
      return res.status(400).json({ error: "Email et mot de passe requis." });
    }
    if (ADMIN_EMAIL && ADMIN_PASSWORD) {
      if (email !== normalizeEmail(ADMIN_EMAIL) || password !== ADMIN_PASSWORD) {
        return res.status(401).json({ error: "Identifiants invalides." });
      }
    } else {
      console.warn("⚠️ ADMIN_EMAIL/ADMIN_PASSWORD non définis — mode démo (tout est accepté).");
    }
    return res.json({ token: ADMIN_TOKEN });
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).json({ error: "Erreur de connexion." });
  }
});

function requireAuth(req, res, next) {
  const hdr = req.headers['authorization'] || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: "Non autorisé." });
  }
  next();
}

// Création d'une demande (publique)
app.post('/api/requests', async (req, res) => {
  try {
    let {
      fullName, applicantEmail, entity,
      dateFrom, dateTo, startPeriod, endPeriod,
      place, type, managerEmail, hrEmail, comment
    } = req.body || {};

    applicantEmail = normalizeEmail(applicantEmail);
    managerEmail   = normalizeEmail(managerEmail);
    hrEmail        = normalizeEmail(hrEmail);

    if (!fullName || !entity || !place || !dateFrom) {
      return res.status(400).json({ error: "Champs requis manquants (nom, entité, lieu, date de début)." });
    }
    if (!isEmail(applicantEmail)) return res.status(400).json({ error: "Adresse e-mail du demandeur invalide." });
    if (!isEmail(managerEmail))   return res.status(400).json({ error: "Adresse e-mail N+1 invalide." });
    if (!isEmail(hrEmail))        return res.status(400).json({ error: "Adresse e-mail DDRH/RH invalide." });

    if (!dateTo) dateTo = dateFrom;
    if (dateFrom === dateTo && startPeriod === "PM" && endPeriod === "AM") {
      return res.status(400).json({ error: "Pour une même journée, choisissez Matin puis Après-midi, ou Journée complète." });
    }

    const days = computeDays(dateFrom, dateTo, startPeriod, endPeriod);
    const now  = new Date().toISOString();

    const rec = {
      id: uid(),
      full_name: fullName,
      applicant_email: applicantEmail,
      entity,
      date_from: dateFrom,
      date_to:   dateTo,
      start_period: (startPeriod || 'FULL').toUpperCase(),
      end_period:   (endPeriod   || 'FULL').toUpperCase(),
      place,
      type: (type || '21B').toUpperCase(),
      days,
      comment: (comment || '').trim(),
      status: 'pending',
      created_at: now,
      validated_at: null,
      decision_at: null,
      decision_reason: null,
      manager_email: managerEmail,
      hr_email: hrEmail,
    };

    REQUESTS.unshift(rec);
    res.json({ ok: true, id: rec.id });
  } catch (e) {
    console.error("Create request error:", e);
    res.status(500).json({ error: "Erreur lors de l'enregistrement." });
  }
});

// Liste filtrée (admin)
app.get('/api/requests', requireAuth, (req, res) => {
  const status = (req.query.status || '').trim();
  let items = REQUESTS;
  if (status) items = items.filter(r => r.status === status);
  res.json({ items });
});

// Validation (admin) + envoi mail à N+1, RH, CC Reine + Chrystelle
app.post('/api/requests/:id/validate', requireAuth, async (req, res) => {
  try {
    const rec = REQUESTS.find(r => r.id === req.params.id);
    if (!rec) return res.status(404).json({ error: "Demande introuvable." });

    rec.status = 'sent';
    rec.validated_at = new Date().toISOString();

    const subject = `Détachement – ${rec.full_name}`;
    const datesFR = rec.date_from === rec.date_to
      ? toFR(rec.date_from)
      : `${toFR(rec.date_from)} au ${toFR(rec.date_to)}`;

    const html = `
      <div style="font-family: Arial, sans-serif; font-size: 12pt; color: #000;">
        <p>Bonjour,</p>
        <p>Merci de bien vouloir noter le détachement de :<br/>
        <span style="color:#D71620;">${rec.full_name}${rec.entity ? ' – ' + rec.entity : ''}</span></p>
        <p>Le(s) : <span style="color:#D71620;">${datesFR}</span><br/>
        À : <span style="color:#D71620;">${rec.place}</span><br/>
        En article 21 : <span style="color:#D71620;">${rec.type} – ${fmtDaysFR(rec.days)}</span><br/>
        (Hors délai de route)</p>
        ${rec.comment ? `<p>Commentaire du demandeur : <span style="color:#D71620;">${rec.comment}</span></p>` : ''}
        <p>Bonne fin de journée,</p>
        <p><strong>Sébastien DELGADO</strong><br/>
        Secrétaire Adjoint – CSEC SG<br/>
        sebastien.delgado@csec-sg.com<br/>
        06 74 98 48 68</p>
      </div>
    `;

    await transporter.sendMail({
      from: `"${MAIL_FROM_NAME}" <${MAIL_FROM}>`,
      to: [rec.manager_email, rec.hr_email].filter(Boolean).join(','),
      cc: ['reine.allaglo@csec-sg.com', 'chrystelle.agea@socgen.com'].join(','),
      subject,
      html
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("Validate error:", e);
    res.status(500).json({ error: "Erreur lors de la validation / envoi." });
  }
});

// Refus (admin) — mail au demandeur
app.post('/api/requests/:id/refuse', requireAuth, async (req, res) => {
  try {
    const rec = REQUESTS.find(r => r.id === req.params.id);
    if (!rec) return res.status(404).json({ error: "Demande introuvable." });

    const reason = String(req.body?.reason || '').trim();
    if (!reason) return res.status(400).json({ error: "Motif requis." });

    rec.status = 'refused';
    rec.decision_reason = reason;
    rec.decision_at = new Date().toISOString();

    const html = `
      <div style="font-family: Arial, sans-serif; font-size: 12pt; color: #000;">
        <p>Bonjour <span style="color:#D71620;">${rec.full_name}</span>,</p>
        <p>Votre demande de détachement a été <strong style="color:#D71620;">refusée</strong>.</p>
        <p><u>Motif :</u> <span style="color:#D71620;">${reason}</span></p>
        <br/>
        <p>Cordialement,</p>
        <p><strong>Sébastien DELGADO - Secrétaire Adjoint CSEC SG</strong></p>
      </div>
    `;

    await transporter.sendMail({
      from: `"${MAIL_FROM_NAME}" <${MAIL_FROM}>`,
      to: rec.applicant_email,
      subject: "Refus de votre demande de détachement",
      html
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("Refuse error:", e);
    res.status(500).json({ error: "Erreur lors du refus / envoi." });
  }
});

// Annulation (admin) — mail au demandeur
app.post('/api/requests/:id/cancel', requireAuth, async (req, res) => {
  try {
    const rec = REQUESTS.find(r => r.id === req.params.id);
    if (!rec) return res.status(404).json({ error: "Demande introuvable." });

    const reason = String(req.body?.reason || '').trim();
    if (!reason) return res.status(400).json({ error: "Motif requis." });

    rec.status = 'cancelled';
    rec.decision_reason = reason;
    rec.decision_at = new Date().toISOString();

    const html = `
      <div style="font-family: Arial, sans-serif; font-size: 12pt; color: #000;">
        <p>Bonjour <span style="color:#D71620;">${rec.full_name}</span>,</p>
        <p>Votre demande de détachement a été <strong style="color:#D71620;">annulée</strong>.</p>
        <p><u>Motif :</u> <span style="color:#D71620;">${reason}</span></p>
        <br/>
        <p>Cordialement,</p>
        <p><strong>Sébastien DELGADO - Secrétaire Adjoint CSEC SG</strong></p>
      </div>
    `;

    await transporter.sendMail({
      from: `"${MAIL_FROM_NAME}" <${MAIL_FROM}>`,
      to: rec.applicant_email,
      subject: "Annulation de votre demande de détachement",
      html
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("Cancel error:", e);
    res.status(500).json({ error: "Erreur lors de l'annulation / envoi." });
  }
});

// ---------- Lancement ----------
app.listen(PORT, () => {
  console.log(`✅ API running on port ${PORT}`);
});
