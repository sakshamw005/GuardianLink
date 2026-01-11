const db = require('../lib/db');
const path = require('path');

const existing = db.prepare('SELECT COUNT(*) AS c FROM rules').get().c;
if (existing > 0) {
  console.log('ℹ️ Rules already exist, skipping import');
  process.exit(0);
}
// const db = require('../lib/db');

const raw = require(path.join(__dirname, '../data/rules.json'));
let rules;

if (Array.isArray(raw)) {
  rules = raw;
} else if (Array.isArray(raw.rules)) {
  rules = raw.rules;
} else if (Array.isArray(raw.entries)) {
  rules = raw.entries;
} else {
  console.error('❌ Could not find rules array in rules.json');
  process.exit(1);
}

const stmt = db.prepare(`
  INSERT OR REPLACE INTO rules
  (id, type, selector, value, source, confidence, expires_at, evidence)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

let count = 0;

for (const r of rules) {
  if (!r.id || !r.type || !r.selector || !r.value) {
    console.warn('⚠️ Skipping invalid rule:', r);
    continue;
  }

  stmt.run(
    r.id,
    r.type,
    r.selector,
    r.value,
    r.source || 'local',
    r.confidence ?? 1.0,
    r.expiresAt || null,
    JSON.stringify(r.evidence || {})
  );

  count++;
}

console.log(`✅ Imported ${count} rules into database`);