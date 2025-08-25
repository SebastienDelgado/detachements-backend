// Simple backend for Détachements (demo) — Express + CORS
// Deploy on Render as a Web Service (Node 18+)

const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// --- CORS ---
const ALLOWED_ORIGINS = [
  'https://cgtsg-detachements-art21-csecsg.netlify.app',
  'http://localhost:5173',
  'http://localhost:3000',
  'http://localhost:8080',
];

app.use(cors({
  origin: function(origin, cb) {
    if (!origin) return cb(null, true); // allow curl / server-to-server
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(null, true); // <-- permissif pour simplifier les tests (peut être resserré)
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','Accept'],
  credentials: false,
  maxAge: 86400,
}));

app.use(express.json());

// --- Demo data store (in-memory) ---
let ID = 1;
const requests = []; // {id, full_name, applicant_email, entity, date_from, date_to, place, type, days, comment, manager_email, hr_email, status}

// --- Health ---
app.get('/api/health', (req, res) => res.json({ ok: true }));

// --- Auth (demo) ---
const DEMO_USER = { email: 'admin@csec-sg.com', password: 'Art21!' };
const DEMO_TOKEN = 'demo-admin-token';

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (email === DEMO_USER.email && password === DEMO_USER.password) {
    return res.json({ token: DEMO_TOKEN });
  }
  return res.status(401).json({ error: 'Identifiants invalides' });
});

function authRequired(req, res, next) {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (token !== DEMO_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// --- Create request ---
app.post('/api/requests', (req, res) => {
  const b = req.body || {};
  // Basic validation
  const required = ['fullName','applicantEmail','entity','dateFrom','dateTo','place','type','managerEmail','hrEmail','days'];
  for (const k of required) {
    if (!b[k]) return res.status(400).json({ error: `Champ manquant: ${k}` });
  }
  const rec = {
    id: ID++,
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
    created_at: new Date().toISOString(),
  };
  requests.push(rec);
  return res.json({ ok: true, id: rec.id });
});

// --- List requests by status ---
app.get('/api/requests', authRequired, (req, res) => {
  const status = (req.query.status || '').toLowerCase();
  const items = status ? requests.filter(r => r.status === status) : requests.slice();
  return res.json({ items });
});

// --- Transition helpers ---
function changeStatus(id, status, extra = {}) {
  const r = requests.find(x => String(x.id) === String(id));
  if (!r) return null;
  r.status = status;
  Object.assign(r, extra);
  return r;
}

app.post('/api/requests/:id/validate', authRequired, (req, res) => {
  const r = changeStatus(req.params.id, 'sent');
  if (!r) return res.status(404).json({ error: 'Not found' });
  return res.json({ ok: true });
});

app.post('/api/requests/:id/refuse', authRequired, (req, res) => {
  const reason = (req.body && req.body.reason) || '';
  const r = changeStatus(req.params.id, 'refused', { refuse_reason: reason });
  if (!r) return res.status(404).json({ error: 'Not found' });
  return res.json({ ok: true });
});

app.post('/api/requests/:id/cancel', authRequired, (req, res) => {
  const reason = (req.body && req.body.reason) || '';
  const r = changeStatus(req.params.id, 'cancelled', { cancel_reason: reason });
  if (!r) return res.status(404).json({ error: 'Not found' });
  return res.json({ ok: true });
});

// --- Start ---
app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
