// db.js — Connexion Postgres + création de schéma si nécessaire
const { Pool } = require('pg');
require('dotenv').config();

const cs = process.env.DATABASE_URL || "";
const needSSL = !/localhost|127\.0\.0\.1/.test(cs) && (process.env.DATABASE_SSL || "true") !== "false";

const pool = new Pool({
  connectionString: cs,
  ssl: needSSL ? { rejectUnauthorized: false } : false,
});

async function ensureSchema() {
  const sql = `
    create table if not exists requests (
      id uuid primary key,
      full_name text not null,
      applicant_email text not null,
      entity text not null,
      date_from date not null,
      date_to date not null,
      start_period text not null,
      end_period text not null,
      place text not null,
      type text not null, -- 21B | 21C | Pour Information
      manager_email text not null,
      hr_email text not null,
      comment text,
      days numeric not null default 1,
      status text not null, -- pending | sent | refused | cancelled
      created_at timestamptz default now(),
      validated_at timestamptz,
      decision_at timestamptz,
      decision_reason text
    );
    create index if not exists idx_requests_status on requests(status);
    create index if not exists idx_requests_created_at on requests(created_at desc);
  `;
  await pool.query(sql);
}

module.exports = { pool, ensureSchema };
