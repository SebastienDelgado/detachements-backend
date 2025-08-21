const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// Middleware
app.use(cors({
  origin: (origin, cb) => {
    const allowed = (process.env.CORS_ORIGINS || '').split(',').map(o => o.trim());
    if (!origin || allowed.includes(origin)) cb(null, true);
    else cb(new Error('Not allowed by CORS'));
  }
}));
app.use(express.json());

// Routes
app.get('/', (req, res) => {
  res.type('html').send(`
    <h1>Détachements API</h1>
    <p>Service en ligne ✅</p>
    <p>Healthcheck: <a href="/api/health">/api/health</a></p>
  `);
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// Lancer le serveur
app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
});
function normalizeDate(input) {
  if (!input) return input;
  if (/^\d{4}-\d{2}-\d{2}$/.test(input)) return input; // déjà bon

  // Accepter DD/MM/YYYY
  const m = /^(\d{2})\/(\d{2})\/(\d{4})$/.exec(input);
  if (m) {
    const [_, dd, mm, yyyy] = m;
    return `${yyyy}-${mm}-${dd}`;
  }
  return input; // laisser tel quel si inconnu
}
app.post('/api/requests', async (req, res) => {
  try {
    // 🔧 normaliser les dates avant parse
    if (req.body) {
      req.body.dateFrom = normalizeDate(req.body.dateFrom);
      req.body.dateTo   = normalizeDate(req.body.dateTo);
    }

    const p = RequestSchema.parse(req.body);
    // ... le reste inchangé
