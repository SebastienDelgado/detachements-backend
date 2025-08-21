// server.js — Détachements API (CommonJS, sans BDD, prêt pour Render)
// Dépendances nécessaires (déjà dans ton package.json minimal) : express, cors, dotenv

const express = require('express');
const cors = require('cors');
const { randomUUID } = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// --- CORS ---
app.use(
  cors({
    origin: (origin, cb) => {
      const allowed = (process.env.CORS_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean);
      if (!origin) return cb(null, true); // autoriser accès direct (curl, même origine)
      if (allowed.includes('*') || allowed.includes(origin)) return cb(null, true);
      cb(new Error('Not allowed by CORS: ' + origin));
    },
  })
);

// --- Body JSON ---
app.use(express.json());

// --- Page d'accueil + Health ---
app.get('/', (req, res) => {
  res.type('html').send(`
    <style>body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:2rem;line-height:1.5}code{background:#f6f8fa;border-radius:6px;padding:.1rem .3rem}</style>
    <h1>Détachements API</h1>
    <p>Service en ligne ✅</p>
    <p>Healthcheck : <a href="/api/health">/api/health</a></p>
    <h3>Endpoints</h3>
    <ul>
      <li><code>POST /api/requests</code> — créer une demande</li>
      <li><code>POST /api/auth/login</code> — login admin</li>
      <li><code>GET /api/requests?status=pending|sent</code> — lister (admin)</li>
      <li><code>POST /api/requests/:id/validate</code> — valider & envoyer (simulation)</li>
    </ul>
  `);
});
app.get('/api/health', (req, res) => res.json({ ok: true }));

// --- Mémoire (simple) ---
// ⚠️ Simple pour démarrer : se réinitialise si le service redémarre.
// Pour la “prod” durable, on passera à SQLite/Postgres.
const REQUESTS = [];

// --- Utils ---
function normalizeDate(input) {
  if (!input) return input;
  // déjà au bon format YYYY-MM-DD
  if (/^\d{4}-\d{2}-\d{2}$/.test(input)) return input;
  // format européen DD/MM/YYYY
  const m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(input);
  if (m) {
    const [, dd, mm, yyyy] = m;
    return `${yyyy}-${mm}-${dd}`;
  }
  return input; // autre chose : laisser tel quel (laisser l'erreur côté contrôle)
}

function computeDays(dFrom, dTo, startP, endP) {
  if (!dFrom || !dTo) return 0;
  // On force en UTC pour ne pas avoir de décalages
  const from = new Date(dFrom + 'T00:00:00Z');
  const to = new Date(dTo + 'T00:00:00Z');
  const dayMs = 24 * 60 * 60 * 1000;
  const baseDays = Math.floor((to - from) / dayMs) + 1;

  if (dFrom === dTo) {
    if (startP === 'FULL' || endP === 'FULL') return 1;
    if (startP === 'AM' && endP === 'PM') return 1;
    if (startP === 'AM' && endP === 'AM') return 0.5;
    if (startP === 'PM' && endP === 'PM') return 0.5;
    return 1;
  }
  let total = baseDays;
  if (startP === 'PM') total -= 0.5;
  if (endP === 'AM') total -= 0.5;
  return total;
}

function isEmail(x) {
  return typeof x === 'string' && /.+@.+\..+/.test(x);
}

// --- Auth minimal (sans JWT) ---
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@example.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me';

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
    // token ultra simple pour débuter
    return res.json({ token: 'ok' });
  }
  return res.status(401).json({ error: 'Invalid credentials' });
});

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (token === 'ok') return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

// --- Créer une demande (publique) ---
app.post('/api/requests', (req, res) => {
  try {
    const body = req.body || {};

    // normaliser les dates AVANT contrôle
    body.dateFrom = normalizeDate(body.dateFrom);
    body.dateTo = normalizeDate(body.dateTo || body.dateFrom);

    // contrôles simples
    if (!body.fullName || !body.entity || !body.place) {
      return res.status(400).json({ error: 'Champs requis manquants (nom, entité, lieu)' });
    }
    if (!body.dateFrom) {
      return res.status(400).json({ error: 'Date de début manquante' });
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(body.dateFrom) || !/^\d{4}-\d{2}-\d{2}$/.test(body.dateTo)) {
      return res.status(400).json({ error: 'Format de date invalide (utiliser AAAA-MM-JJ)' });
    }
    if (!['AM', 'PM', 'FULL'].includes((body.startPeriod || '').toUpperCase())) {
      return res.status(400).json({ error: 'startPeriod doit être AM, PM ou FULL' });
    }
    if (!['AM', 'PM', 'FULL'].includes((body.endPeriod || '').toUpperCase())) {
      return res.status(400).json({ error: 'endPeriod doit être AM, PM ou FULL' });
    }
    if (!['21B', '21C'].includes((body.type || '').toUpperCase())) {
      return res.status(400).json({ error: 'type doit être 21B ou 21C' });
    }
    if (!isEmail(body.managerEmail)) {
      return res.status(400).json({ error: "E-mail du N+1 invalide" });
    }
    if (!isEmail(body.hrEmail)) {
      return res.status(400).json({ error: "E-mail du DDRH/RH invalide" });
    }

    const id = randomUUID();
    const startPeriod = (body.startPeriod || 'FULL').toUpperCase();
    const endPeriod = (body.endPeriod || 'FULL').toUpperCase();
    const type = (body.type || '21B').toUpperCase();
    const days = computeDays(body.dateFrom, body.dateTo, startPeriod, endPeriod);

    const item = {
      id,
      full_name: body.fullName.trim(),
      entity: body.entity,
      date_from: body.dateFrom,
      date_to: body.dateTo,
      start_period: startPeriod,
      end_period: endPeriod,
      place: body.place,
      type,
      manager_email: body.managerEmail,
      hr_email: body.hrEmail,
      days,
      comment: body.comment || null,
      status: 'pending',
      created_at: new Date().toISOString(),
      validated_at: null,
    };
    REQUESTS.unshift(item);
    return res.json({ id, days, status: 'pending' });
  } catch (e) {
    console.error(e);
    return res.status(400).json({ error: e.message || 'Invalid payload' });
  }
});

// --- Lister (admin) ---
app.get('/api/requests', requireAuth, (req, res) => {
  const { status, entity, type } = req.query;
  let items = REQUESTS.slice();
  if (status) items = items.filter(r => r.status === status);
  if (entity) items = items.filter(r => r.entity === entity);
  if (type) items = items.filter(r => r.type === type);
  return res.json({ items });
});

// --- Valider & "envoyer" (admin) ---
app.post('/api/requests/:id/validate', requireAuth, (req, res) => {
  const { id } = req.params;
  const r = REQUESTS.find(x => x.id === id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  if (r.status === 'sent') return res.json({ ok: true, already: true });

  // Simulation d'envoi (console). Quand SMTP sera prêt, on branchera un vrai envoi.
  const subject = `Détachement – ${r.full_name}`;
  const dates = r.date_from === r.date_to ? r.date_from : `${r.date_from} au ${r.date_to}`;
  const body = [
    'Bonjour,','',
    'Merci de bien vouloir noter le détachement de :',
    `${r.full_name}${r.entity ? ' – ' + r.entity : ''}`,'',
    `Le(s) : ${dates}`,
    `À : ${r.place}`,
    `En article 21 : ${r.type}${r.days ? ' – ' + r.days + ' jour(s)' : ''}`,'',
    'Bonne fin de journée,','',
    'Sébastien DELGADO','Secrétaire Adjoint – CSEC SG',
    'sebastien.delgado@csec-sg.com','06 74 98 48 68',
  ].join('\n');

  console.log('[MAIL SIMULATION]');
  console.log('TO   :', r.manager_email, ',', r.hr_email);
  console.log('CC   : reine.allaglo@csec-sg.com, chrystelle.agea@socgen.com');
  console.log('SUBJ :', subject);
  console.log('BODY :\n' + body);

  r.status = 'sent';
  r.validated_at = new Date().toISOString();

  return res.json({ ok: true, message: 'Email simulated (console). Configure SMTP to send real emails.' });
});

// --- Start ---
app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});
