const fs = require('fs');
const path = require('path');
const { extractSignals } = require('./signalExtractor');

const DATA_FILE =
  process.env.HEURISTICS_FILE ||
  path.join(__dirname, '..', 'data', 'heuristics.json');

fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });

let heuristics = { version: '1.0', description: '', rules: [] };

// ===== SCORING POLICY =====
const MAX_RULE_PENALTY = 3;      // max deduction per rule
const MAX_TOTAL_PENALTY = 20;   // cap heuristic phase damage
const MAX_SCORE = 25;
// =========================

function load() {
  try {
    heuristics = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    return heuristics;
  } catch {
    heuristics = { version: '1.0', description: '', rules: [] };
    fs.writeFileSync(DATA_FILE, JSON.stringify(heuristics, null, 2));
    return heuristics;
  }
}

function save() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(heuristics, null, 2));
}

function getAll() {
  return heuristics;
}

function evaluate(url, context = {}) {
  const signals = extractSignals(url, context);

  let matchedRules = [];
  let totalSuspicion = 0;

  // Prevent stacking from same family (domain, ssl, page, etc.)
  const firedFamilies = new Set();

  for (const rule of heuristics.rules || []) {
    const condition = rule.condition;
    if (!condition || typeof condition !== 'object') continue;

    let matched = true;

    for (const [key, expected] of Object.entries(condition)) {
      if (key.endsWith('_gt')) {
        const base = key.replace('_gt', '');
        if (!(signals[base] > expected)) { matched = false; break; }
        continue;
      }

      if (key.endsWith('_lt')) {
        const base = key.replace('_lt', '');
        if (!(signals[base] < expected)) { matched = false; break; }
        continue;
      }

      const actual = signals[key];
      if (actual === undefined) { matched = false; break; }

      if (Array.isArray(expected)) {
        if (!expected.includes(actual)) { matched = false; break; }
      } else {
        if (actual !== expected) { matched = false; break; }
      }
    }

    if (!matched) continue;

    // === FAMILY DEDUP ===
    const family = rule.id?.split(':')[0] || rule.id;
    if (firedFamilies.has(family)) continue;

    firedFamilies.add(family);
    matchedRules.push(rule);

    // === SAFE PENALTY ===
    const penalty = Math.min(rule.score || MAX_RULE_PENALTY, MAX_RULE_PENALTY);
    totalSuspicion += penalty;

    rule.lastSeenAt = new Date().toISOString();
    rule.confidence =
      typeof rule.confidence === 'number'
        ? Math.min(1, rule.confidence + 0.05)
        : 0.55;
  }

  totalSuspicion = Math.min(totalSuspicion, MAX_TOTAL_PENALTY);

  const score = Math.max(0, MAX_SCORE - totalSuspicion);

  let status = 'safe';
  if (totalSuspicion >= 15) status = 'danger';
  else if (totalSuspicion >= 7) status = 'warning';

  console.log('[Heuristics]', {
    signalKeys: Object.keys(signals),
    matched: matchedRules.map(r => r.id),
    suspicion: totalSuspicion,
    score,
    status
  });

  save();

  // ===============================
  // 🔥 ADDITIONS (NO REMOVALS)
  // ===============================

  const findings = matchedRules.map(rule => ({
    id: rule.id,
    category: rule.category,
    description: rule.description,
    scoreImpact: Math.min(rule.score || MAX_RULE_PENALTY, MAX_RULE_PENALTY),
    confidence: rule.confidence ?? 0.55
  }));

  return {
    // existing outputs
    matchedRules,
    totalSuspicion,
    score,
    maxScore: MAX_SCORE,
    status,

    // 🔥 NEW — what UI needs
    findings,                 // <-- frontend uses this
    hitCount: findings.length // <-- Heuristic Hits
  };
}

module.exports = { load, getAll, evaluate };