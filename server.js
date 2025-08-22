const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// Middleware CORS
app.use(cors({
  origin: (origin, cb) => {
    const allowed = (process.env.CORS_ORIGINS || '*').split(',').map(o => o.trim());
    if (!origin || allowed.includes(origin)) cb(null, true);
    else cb(new Error('Not allowed by CORS'));
  }
}));
app.use(express.json());

// Mailtrap (mode test)
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "sandbox.smtp.mailtrap.io",
  port: process.env.SMTP_PORT || 587,
  auth: {
    user: process.env.SMTP_USER || "YOUR_MAILTRAP_USER",
    pass: process.env.SMTP_PASS || "YOUR_MAILTRAP_PASS"
  }
});

// Helper – format FR
function formatDateFR(dateStr) {
  return new Date(dateStr).toLocaleDateString('fr-FR', {
    day: '2-digit', month: '2-digit', year: 'numeric'
  });
}

// Route santé
app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

// Refus / annulation
app.post('/api/notify-refusal', async (req, res) => {
  try {
    const { applicantEmail, fullName, reason, type } = req.body;
    if (!applicantEmail || !fullName || !reason || !type) {
      return res.status(400).json({ error: "Champs manquants" });
    }

    const subject = type === "refus"
      ? "Refus de votre demande de détachement"
      : "Annulation de votre demande de détachement";

    const html = `
      <div style="font-family: Arial, sans-serif; font-size: 12pt; color: #000;">
        <p>Bonjour <span style="color:#D71620;">${fullName}</span>,</p>
        <p>Votre demande de détachement a été 
          <strong style="color:#D71620;">${type === "refus" ? "refusée" : "annulée"}</strong>.
        </p>
        <p><u>Motif :</u> <span style="color:#D71620;">${reason}</span></p>
        <br/>
        <p>Cordialement,</p>
        <p><strong>Sébastien DELGADO - Secrétaire Adjoint CSEC SG</strong></p>
      </div>
    `;

    await transporter.sendMail({
      from: `"Sébastien DELGADO" <${process.env.MAIL_FROM || "test@example.com"}>`,
      to: applicantEmail,
      subject,
      html
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Erreur envoi refus/annulation:", err);
    res.status(500).json({ error: "Envoi email échoué" });
  }
});

// Lancement
app.listen(PORT, () => {
  console.log(`✅ API running on port ${PORT}`);
});
