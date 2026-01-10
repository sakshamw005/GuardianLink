const db = require('../lib/db');

db.exec(`
CREATE TABLE IF NOT EXISTS rules (
  id TEXT PRIMARY KEY,
  type TEXT,
  selector TEXT,
  value TEXT,
  source TEXT,
  confidence REAL,
  expires_at TEXT,
  evidence TEXT,
  enabled INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS heuristics (
  id TEXT PRIMARY KEY,
  condition TEXT,
  weight INTEGER,
  confidence REAL,
  source TEXT,
  evidence TEXT,
  enabled INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS url_intelligence (
  url TEXT PRIMARY KEY,
  verdict TEXT,
  confidence REAL,
  source TEXT,
  first_seen TEXT,
  last_seen TEXT,
  metadata TEXT
);

CREATE TABLE IF NOT EXISTS vt_evidence (
  url TEXT,
  engines_flagged INTEGER,
  categories TEXT,
  country TEXT,
  asn TEXT,
  raw_response TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS heuristics (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,                 -- domain, path, keyword, pattern
  value TEXT NOT NULL,
  condition TEXT NOT NULL,            -- contains, equals, regex
  source TEXT NOT NULL,               -- virustotal, local
  confidence REAL DEFAULT 0.5,
  evidence TEXT,
  enabled INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);
console.log("✅ DB initialized");