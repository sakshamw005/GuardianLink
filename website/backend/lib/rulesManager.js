const db = require('./db');

/* -------------------------------
   Helpers
-------------------------------- */

function normalizeHostname(urlOrDomain) {
  try {
    return new URL(urlOrDomain).hostname.toLowerCase();
  } catch {
    return (urlOrDomain || '').toLowerCase();
  }
}

/* -------------------------------
   Lifecycle
-------------------------------- */

// For DB-backed rules, load() is just a sanity check
function load() {
  try {
    db.prepare(`SELECT 1 FROM rules LIMIT 1`).get();
    return true;
  } catch (err) {
    console.error('rulesManager: DB not ready', err.message);
    throw err;
  }
}

/* -------------------------------
   Queries
-------------------------------- */

function isWhitelisted(urlOrDomain) {
  const host = normalizeHostname(urlOrDomain);

  return db.prepare(`
    SELECT *
    FROM rules
    WHERE enabled = 1
      AND type = 'whitelist'
      AND (
        (selector = 'domain' AND ? = value)
        OR (selector = 'domain' AND ? LIKE '%.' || value)
        OR (selector = 'ip' AND value = ?)
        OR (selector = 'url' AND value = ?)
      )
    LIMIT 1
  `).get(host, host, host, urlOrDomain);
}

function isBlacklisted(urlOrDomain) {
  const host = normalizeHostname(urlOrDomain);

  return db.prepare(`
    SELECT *
    FROM rules
    WHERE enabled = 1
      AND type = 'blacklist'
      AND (
        (selector = 'domain' AND ? = value)
        OR (selector = 'domain' AND ? LIKE '%.' || value)
        OR (selector = 'ip' AND value = ?)
        OR (selector = 'url' AND value = ?)
      )
    LIMIT 1
  `).get(host, host, host, urlOrDomain);
}

/* -------------------------------
   Mutations
-------------------------------- */

function addRule(rule) {
  if (!rule?.id) throw new Error('rule.id required');

  db.prepare(`
    INSERT OR IGNORE INTO rules
    (id, type, selector, value, source, confidence, expires_at, evidence, enabled)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
  `).run(
    rule.id,
    rule.type,
    rule.selector,
    rule.value,
    rule.source || 'local',
    rule.confidence ?? 1.0,
    rule.expiresAt || null,
    JSON.stringify(rule.evidence || {})
  );

  return rule;
}

function count() {
  return db.prepare(`SELECT COUNT(*) AS c FROM rules`).get().c;
}

function getAll() {
  return db.prepare(`SELECT * FROM rules`).all();
}

/* -------------------------------
   Exports
-------------------------------- */

module.exports = {
  load,
  isWhitelisted,
  isBlacklisted,
  addRule,
  count,
  getAll
};