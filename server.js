// server.js — Détachements API (CommonJS) avec envoi d'e-mails via Nodemailer

const express = require('express');
const cors = require('cors');
const { randomUUID } = require('crypto');
const nodemailer = require('nodemailer');
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
      <li><code>POST /api/requests/:id/validate</code> — valider & envoyer</li>
    </ul>
  `);
});
app.get('/api/health', (req, res) => res.json({ ok: true }));

// --- Mémoire (simple) ---
// ⚠️ Simple pour démarrer : se réinitialise si le service redémarre.
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
  return input; // autre chose : laisser tel quel
}

function computeDays(dFrom, dTo, startP, endP) {
  if (!dFrom || !dTo) return 0;
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
    return res.json({ token: 'ok' }); // token simple
  }
  return res.status(401).json({ error: 'Invalid credentials' });
});

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (token === 'ok') return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

// --- Transport mail (Nodemailer) ---
function createTransport() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host) {
    console.warn('[MAIL] SMTP non configuré. Remplis SMTP_HOST/PORT/USER/PASS pour envoyer des e-mails.');
    // Transport “no-op” qui n’envoie pas mais évite de crasher
    return {
      sendMail: async () => {
        throw new Error('SMTP non configuré (SMTP_HOST manquant)');
      },
    };
  }

  const secure = port === 465; // 465 = SSL, sinon STARTTLS sur 587
  const base = {
    host,
    port,
    secure,
  };

  if (user && pass) {
    base.auth = { user, pass };
  }

  const transporter = nodemailer.createTransport(base);
  console.log('[MAIL] SMTP prêt :', host + ':' + port, secure ? '(SSL)' : '(STARTTLS)');
  return transporter;
}

const mailer = createTransport();

// --- Créer une demande (publique) ---
app.post('/api/requests', (req, res) => {
  try {
    const body = req.body || {};

    // Normaliser dates
    body.dateFrom = normalizeDate(body.dateFrom);
    body.dateTo = normalizeDate(body.dateTo || body.dateFrom);

    // Contrôles
    if (!body.fullName || !body.entity || !body.place) {
      return res.status(400).json({ error: 'Champs requis manquants (nom, entité, lieu)' });
    }
    if (!body.dateFrom) return res.status(400).json({ error: 'Date de début manquante' });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(body.dateFrom) || !/^\d{4}-\d{2}-\d{2}$/.test(body.dateTo)) {
      return res.status(400).json({ error: 'Format de date invalide (utiliser AAAA-MM-JJ)' });
    }
    const startPeriod = (body.startPeriod || 'FULL').toUpperCase();
    const endPeriod = (body.endPeriod || 'FULL').toUpperCase();
    if (!['AM', 'PM', 'FULL'].includes(startPeriod)) return res.status(400).json({ error: 'startPeriod doit être AM, PM ou FULL' });
    if (!['AM', 'PM', 'FULL'].includes(endPeriod)) return res.status(400).json({ error: 'endPeriod doit être AM, PM ou FULL' });
    const type = (body.type || '21B').toUpperCase();
    if (!['21B', '21C'].includes(type)) return res.status(400).json({ error: 'type doit être 21B ou 21C' });
    if (!isEmail(body.managerEmail)) return res.status(400).json({ error: 'E-mail du N+1 invalide' });
    if (!isEmail(body.hrEmail)) return res.status(400).json({ error: 'E-mail du DDRH/RH invalide' });

    const id = randomUUID();
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

// --- Valider & envoyer (admin) ---
app.post('/api/requests/:id/validate', requireAuth, async (req, res) => {
  const { id } = req.params;
  const r = REQUESTS.find(x => x.id === id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  if (r.status === 'sent') return res.json({ ok: true, already: true });

  const subject = `Détachement – ${r.full_name}`;
  const dates = r.date_from === r.date_to ? r.date_from : `${r.date_from} au ${r.date_to}`;
  const text = [
    'Bonjour,','',
    'Merci de bien vouloir noter le détachement de :',
    `${r.full_name}${r.entity ? ' – ' + r.entity : ''}`,'',
    `Le(s) : ${dates}`,
    `À : ${r.place}`,
    `En article 21 : ${r.type}${r.days ? ' – ' + (r.days % 1 === 0.5 ? (Math.floor(r.days)+',5') : r.days) + ' jour(s)' : ''}`,'',
    'Bonne fin de journée,','',
    'Sébastien DELGADO','Secrétaire Adjoint – CSEC SG',
    'sebastien.delgado@csec-sg.com','06 74 98 48 68',
  ].join('\n');

  const from = {
    name: process.env.MAIL_FROM_NAME || 'CSEC SG – Détachements',
    address: process.env.MAIL_FROM || 'no-reply@example.com',
  };
  const to = [r.manager_email, r.hr_email].filter(Boolean).join(', ');
  const cc = ['sdelgado.csecsg@gmail.com', 'sebastien.delgado@socgen.com'].join(', ');

  try {
    const info = await mailer.sendMail({ from, to, cc, subject, text });
    r.status = 'sent';
    r.validated_at = new Date().toISOString();
    return res.json({ ok: true, messageId: info && info.messageId ? info.messageId : 'sent' });
  } catch (e) {
    console.error('[MAIL ERROR]', e);
    return res.status(500).json({ error: 'Email send failed', detail: e.message });
  }
});

// --- Start ---
app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});
ort ${PORT}`);
});
