const db = require('./db');

const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function canonicalizeUrl(rawUrl) {
  const u = new URL(rawUrl);
  u.hash = '';
  u.search = '';
  if ((u.protocol === 'https:' && u.port === '443') ||
      (u.protocol === 'http:' && u.port === '80')) {
    u.port = '';
  }
  if (u.pathname.endsWith('/') && u.pathname !== '/') {
    u.pathname = u.pathname.slice(0, -1);
  }
  return u.toString();
}


function getCachedScan(url) {
  const row = db.prepare(`
    SELECT verdict, confidence, last_seen, metadata
    FROM url_intelligence
    WHERE url = ?
  `).get(url);

  if (!row) return null;

  const ageMs = Date.now() - new Date(row.last_seen).getTime();
  if (ageMs > CACHE_TTL_MS) return null;

  return {
    verdict: row.verdict,
    confidence: row.confidence,
    metadata: JSON.parse(row.metadata || '{}'),
    ageMs
  };
}

function upsertScan(url, verdict, confidence, metadata = {}) {
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO url_intelligence
      (url, verdict, confidence, source, first_seen, last_seen, metadata)
    VALUES (?, ?, ?, 'guardianlink', ?, ?, ?)
    ON CONFLICT(url) DO UPDATE SET
      verdict = excluded.verdict,
      confidence = excluded.confidence,
      last_seen = excluded.last_seen,
      metadata = excluded.metadata
  `).run(
    url,
    verdict,
    confidence,
    now,
    now,
    JSON.stringify(metadata)
  );
}

module.exports = { getCachedScan, upsertScan , canonicalizeUrl };