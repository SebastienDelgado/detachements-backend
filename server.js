// server.js — Détachements API (Express + Nodemailer)
// Features : create request, validate (mail aux destinataires + cc), refuse/cancel (mail au demandeur), export CSV,
// dates FR, e-mail HTML Arial 12 noir + variables en #D71620.

const express = require('express');
const cors = require('cors');
const { randomUUID } = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// ---------------- CORS ----------------
app.use(
  cors({
    origin: (origin, cb) => {
      const allowed = (process.env.CORS_ORIGINS || '*')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean);
      if (!origin) return cb(null, true); // autorise curl / tests locaux
      if (allowed.includes('*') || allowed.includes(origin)) return cb(null, true);
      return cb(new Error('Not allowed by CORS: ' + origin));
    },
  })
);

// ---------------- Body JSON ----------------
app.use(express.json());

// ---------------- Accueil + Health ----------------
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
      <li><code>GET /api/requests?status=pending|sent|refused|cancelled</code> — lister (admin)</li>
      <li><code>POST /api/requests/:id/validate</code> — valider & envoyer</li>
      <li><code>POST /api/requests/:id/refuse</code> — refuser & notifier le demandeur</li>
      <li><code>POST /api/requests/:id/cancel</code> — annuler & notifier le demandeur</li>
      <li><code>GET /api/requests/export.csv</code> — export CSV complet (admin)</li>
    </ul>
  `);
});
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ---------------- Mémoire (simple, sans BDD) ----------------
const REQUESTS = []; // se vide à chaque redémarrage

// ---------------- Utils ----------------
function normalizeDate(input) {
  if (!input) return input;
  if (/^\d{4}-\d{2}-\d{2}$/.test(input)) return input; // déjà AAAA-MM-JJ
  const m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(input); // JJ/MM/AAAA
  if (m) {
    const [, dd, mm, yyyy] = m;
    return `${yyyy}-${mm}-${dd}`;
  }
  return input;
}
function toFR(d) { // 'YYYY-MM-DD' -> 'DD/MM/YYYY'
  if (!d || !/^\d{4}-\d{2}-\d{2}$/.test(d)) return d || "";
  const [y, m, dd] = d.split("-");
  return `${dd}/${m}/${y}`;
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
function isEmail(x) { return typeof x === 'string' && /.+@.+\..+/.test(x); }
function escapeHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ---------------- Auth minimal ----------------
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'sebastien.delgado@csec-sg.com';
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

// ---------------- Mail (Nodemailer) ----------------
function createTransport() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host) {
    console.warn('[MAIL] SMTP non configuré (SMTP_HOST manquant) → aucun envoi possible.');
    return { sendMail: async () => { throw new Error('SMTP non configuré'); } };
  }

  const secure = port === 465; // 465 = SSL
  const base = { host, port, secure };
  if (user && pass) base.auth = { user, pass };
  const transporter = nodemailer.createTransport(base);
  console.log('[MAIL] SMTP prêt :', host + ':' + port, secure ? '(SSL)' : '(STARTTLS)');
  return transporter;
}
const mailer = createTransport();

const VAR_COLOR = '#D71620'; // couleur des variables dans les e-mails

// ---------------- Créer une demande (publique) ----------------
app.post('/api/requests', (req, res) => {
  try {
    const body = req.body || {};

    // normaliser dates
    body.dateFrom = normalizeDate(body.dateFrom);
    body.dateTo   = normalizeDate(body.dateTo || body.dateFrom);

    // contrôles
    if (!body.fullName || !body.entity || !body.place)
      return res.status(400).json({ error: 'Champs requis manquants (nom, entité, lieu)' });
    if (!isEmail(body.applicantEmail))
      return res.status(400).json({ error: 'E-mail du demandeur invalide' });
    if (!body.dateFrom)
      return res.status(400).json({ error: 'Date de début manquante' });
    if (!/^\d{4}-\d{2}-\d{2}$/.test(body.dateFrom) || !/^\d{4}-\d{2}-\d{2}$/.test(body.dateTo))
      return res.status(400).json({ error: 'Format de date invalide (utiliser AAAA-MM-JJ)' });

    const startPeriod = (body.startPeriod || 'FULL').toUpperCase();
    const endPeriod   = (body.endPeriod   || 'FULL').toUpperCase();
    if (!['AM','PM','FULL'].includes(startPeriod))
      return res.status(400).json({ error: 'startPeriod doit être AM, PM ou FULL' });
    if (!['AM','PM','FULL'].includes(endPeriod))
      return res.status(400).json({ error: 'endPeriod doit être AM, PM ou FULL' });

    const type = (body.type || '21B').toUpperCase();
    if (!['21B','21C'].includes(type))
      return res.status(400).json({ error: 'type doit être 21B ou 21C' });

    if (!isEmail(body.managerEmail))
      return res.status(400).json({ error: "E-mail du N+1 invalide" });
    if (!isEmail(body.hrEmail))
      return res.status(400).json({ error: "E-mail du DDRH/RH invalide" });

    const id   = randomUUID();
    const days = computeDays(body.dateFrom, body.dateTo, startPeriod, endPeriod);

    const item = {
      id,
      full_name: body.fullName.trim(),
      applicant_email: body.applicantEmail,     // nouveau
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

      // champs décision (refus/annulation)
      decision_reason: null,
      decision_at: null
    };
    REQUESTS.unshift(item);
    return res.json({ id, days, status: 'pending' });
  } catch (e) {
    console.error(e);
    return res.status(400).json({ error: e.message || 'Invalid payload' });
  }
});

// ---------------- Lister (admin) ----------------
app.get('/api/requests', requireAuth, (req, res) => {
  const { status, entity, type } = req.query;
  let items = REQUESTS.slice();
  if (status) items = items.filter(r => r.status === status);
  if (entity) items = items.filter(r => r.entity === entity);
  if (type)   items = items.filter(r => r.type === type);
  return res.json({ items });
});

// ---------------- Export CSV (admin) ----------------
function csvEscape(v) {
  if (v === null || v === undefined) return "";
  const s = String(v);
  return /[",\n;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
function buildCSV(items) {
  const header = [
    "Prénom & Nom","E-mail Demandeur","Entité","Dates","Lieu","Article 21","Nb jours",
    "N+1","DDRH/RH","Statut","Créé le","Validé le","Motif décision","Date décision"
  ].join(";");
  const rows = items.map(r => {
    const dates =
      r.date_from === r.date_to
        ? toFR(r.date_from) + (r.start_period !== 'FULL' ? (r.start_period === 'AM' ? " (Matin)" : " (Après-midi)") : "")
        : `${toFR(r.date_from)} → ${toFR(r.date_to)}`
          + (r.start_period === 'PM' ? " (Début: Après-midi)" : "")
          + (r.end_period === 'AM' ? " (Fin: Matin)" : "");
    const created = r.created_at ? new Date(r.created_at).toLocaleString("fr-FR") : "";
    const validated = r.validated_at ? new Date(r.validated_at).toLocaleString("fr-FR") : "";
    const decisionAt = r.decision_at ? new Date(r.decision_at).toLocaleString("fr-FR") : "";
    const fields = [
      r.full_name, r.applicant_email || "", r.entity, dates, r.place, r.type, r.days,
      r.manager_email, r.hr_email, r.status, created, validated, r.decision_reason || "", decisionAt
    ].map(csvEscape);
    return fields.join(";");
  });
  return [header, ...rows].join("\n");
}
app.get('/api/requests/export.csv', requireAuth, (req, res) => {
  try {
    const csv = buildCSV(REQUESTS);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="detachements-export-complet.csv"');
    res.send(csv);
  } catch (e) {
    console.error('CSV export error:', e);
    res.status(500).json({ error: 'Export CSV failed' });
  }
});

// ---------------- Valider & envoyer (admin) ----------------
app.post('/api/requests/:id/validate', requireAuth, async (req, res) => {
  const { id } = req.params;
  const r = REQUESTS.find(x => x.id === id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  if (r.status === 'sent') return res.json({ ok: true, already: true });

  const datesFR = r.date_from === r.date_to
    ? toFR(r.date_from)
    : `${toFR(r.date_from)} au ${toFR(r.date_to)}`;
  const daysLabel = (r.days % 1 === 0.5 ? (Math.floor(r.days)+',5') : r.days) + ' jour' + (r.days > 1 ? 's' : '');

  const subject = `Détachement – ${r.full_name}`;
  const text = [
    'Bonjour,','',
    'Merci de bien vouloir noter le détachement de :',
    `${r.full_name}${r.entity ? ' – ' + r.entity : ''}`,'',
    `Le(s) : ${datesFR}`,
    `À : ${r.place}`,
    `En article 21 : ${r.type} – ${daysLabel}`,
    '(Hors délai de route)','',
    'Bonne fin de journée,','',
    'Sébastien DELGADO','Secrétaire Adjoint – CSEC SG',
    'sebastien.delgado@csec-sg.com','06 74 98 48 68',
  ].join('\n');

  const html = `
  <div style="font-family: Arial, Helvetica, sans-serif; font-size: 12pt; color: #000000; line-height: 1.5;">
    <p>Bonjour,</p>
    <p>Merci de bien vouloir noter le détachement de :<br />
      <span style="color:${VAR_COLOR};">${escapeHtml(r.full_name)}${r.entity ? ' – ' + escapeHtml(r.entity) : ''}</span>
    </p>
    <p>
      Le(s) : <span style="color:${VAR_COLOR};">${escapeHtml(datesFR)}</span><br />
      À : <span style="color:${VAR_COLOR};">${escapeHtml(r.place)}</span><br />
      En article 21 : <span style="color:${VAR_COLOR};">${escapeHtml(r.type)} – ${escapeHtml(daysLabel)}</span><br />
      <span>(Hors délai de route)</span>
    </p>
    <p>Bonne fin de journée,</p>
    <p>
      Sébastien DELGADO<br />
      Secrétaire Adjoint – CSEC SG<br />
      <a href="mailto:sebastien.delgado@csec-sg.com" style="color:#000000; text-decoration:none;">sebastien.delgado@csec-sg.com</a><br />
      06 74 98 48 68
    </p>
  </div>
  `;

  const from = {
    name: process.env.MAIL_FROM_NAME || 'CSEC SG – Détachements',
    address: process.env.MAIL_FROM || 'no-reply@example.com',
  };
  const to = [r.manager_email, r.hr_email].filter(Boolean).join(', ');
  const cc = ['reine.allaglo@csec-sg.com', 'chrystelle.agea@socgen.com'].join(', ');

  try {
    const info = await mailer.sendMail({ from, to, cc, subject, text, html });
    r.status = 'sent';
    r.validated_at = new Date().toISOString();
    return res.json({ ok: true, messageId: info && info.messageId ? info.messageId : 'sent' });
  } catch (e) {
    console.error('[MAIL ERROR]', e);
    return res.status(500).json({ error: 'Email send failed', detail: e.message });
  }
});

// ---------- E-mails décision (refus/annulation) ----------
function buildDecisionMail({ fullName, datesFR, place, type, daysLabel, reason, kind }) {
  const subject = (kind === 'refused' ? 'Refus' : 'Annulation') + ` – Détachement ${fullName}`;

  const text = [
    'Bonjour,','',
    (kind === 'refused' ? 'Votre demande de détachement a été refusée.' : 'Votre demande de détachement a été annulée.'),
    '',
    `Demandeur : ${fullName}`,
    `Le(s) : ${datesFR}`,
    `À : ${place}`,
    `Article 21 : ${type} – ${daysLabel}`,
    '',
    `Motif : ${reason || '—'}`,
    '',
    'Cordialement,','CSEC SG'
  ].join('\n');

  const html = `
  <div style="font-family: Arial, Helvetica, sans-serif; font-size: 12pt; color: #000000; line-height: 1.5;">
    <p>Bonjour,</p>
    <p>${kind === 'refused' ? 'Votre demande de détachement a été <strong>refusée</strong>.' : 'Votre demande de détachement a été <strong>annulée</strong>.'}</p>
    <p>
      Demandeur : <span style="color:${VAR_COLOR};">${escapeHtml(fullName)}</span><br/>
      Le(s) : <span style="color:${VAR_COLOR};">${escapeHtml(datesFR)}</span><br/>
      À : <span style="color:${VAR_COLOR};">${escapeHtml(place)}</span><br/>
      Article 21 : <span style="color:${VAR_COLOR};">${escapeHtml(type)} – ${escapeHtml(daysLabel)}</span>
    </p>
    <p>Motif : <span style="color:${VAR_COLOR};">${escapeHtml(reason || '—')}</span></p>
    <p>Cordialement,<br/>CSEC SG</p>
  </div>
  `;
  return { subject, text, html };
}

// ---------------- Refuser (admin) ----------------
app.post('/api/requests/:id/refuse', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body || {};
  const r = REQUESTS.find(x => x.id === id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  if (!r.applicant_email || !isEmail(r.applicant_email))
    return res.status(400).json({ error: "E-mail demandeur manquant ou invalide" });

  const datesFR = r.date_from === r.date_to ? toFR(r.date_from) : `${toFR(r.date_from)} au ${toFR(r.date_to)}`;
  const daysLabel = (r.days % 1 === 0.5 ? (Math.floor(r.days)+',5') : r.days) + ' jour' + (r.days > 1 ? 's' : '');
  const { subject, text, html } = buildDecisionMail({
    fullName: r.full_name, datesFR, place: r.place, type: r.type, daysLabel, reason, kind: 'refused'
  });

  try {
    await mailer.sendMail({
      from: { name: process.env.MAIL_FROM_NAME || 'CSEC SG – Détachements', address: process.env.MAIL_FROM || 'no-reply@example.com' },
      to: r.applicant_email,
      subject, text, html
    });
    r.status = 'refused';
    r.decision_reason = reason || null;
    r.decision_at = new Date().toISOString();
    return res.json({ ok: true });
  } catch (e) {
    console.error('[MAIL ERROR]', e);
    return res.status(500).json({ error: 'Email send failed', detail: e.message });
  }
});

// ---------------- Annuler (admin) ----------------
app.post('/api/requests/:id/cancel', requireAuth, async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body || {};
  const r = REQUESTS.find(x => x.id === id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  if (!r.applicant_email || !isEmail(r.applicant_email))
    return res.status(400).json({ error: "E-mail demandeur manquant ou invalide" });

  const datesFR = r.date_from === r.date_to ? toFR(r.date_from) : `${toFR(r.date_from)} au ${toFR(r.date_to)}`;
  const daysLabel = (r.days % 1 === 0.5 ? (Math.floor(r.days)+',5') : r.days) + ' jour' + (r.days > 1 ? 's' : '');
  const { subject, text, html } = buildDecisionMail({
    fullName: r.full_name, datesFR, place: r.place, type: r.type, daysLabel, reason, kind: 'cancelled'
  });

  try {
    await mailer.sendMail({
      from: { name: process.env.MAIL_FROM_NAME || 'CSEC SG – Détachements', address: process.env.MAIL_FROM || 'no-reply@example.com' },
      to: r.applicant_email,
      subject, text, html
    });
    r.status = 'cancelled';
    r.decision_reason = reason || null;
    r.decision_at = new Date().toISOString();
    return res.json({ ok: true });
  } catch (e) {
    console.error('[MAIL ERROR]', e);
    return res.status(500).json({ error: 'Email send failed', detail: e.message });
  }
});

// ---------------- Start ----------------
app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});


