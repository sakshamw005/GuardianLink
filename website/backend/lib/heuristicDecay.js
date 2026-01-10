const fs = require('fs');
const path = require('path');

const HEURISTICS_FILE = path.join(__dirname, '..', 'data', 'heuristics.json');

function daysBetween(a, b) {
  return Math.floor((b - a) / (1000 * 60 * 60 * 24));
}

function applyHeuristicDecay() {
  let data;
  try {
    data = JSON.parse(fs.readFileSync(HEURISTICS_FILE, 'utf8'));
  } catch {
    return;
  }

  const now = Date.now();
  let changed = false;

  for (const rule of data.rules || []) {
    if (!rule.active) continue;
    if (!rule.confidenceDecayPerDay) continue;

    const last = new Date(rule.lastSeenAt || rule.createdAt).getTime();
    const days = daysBetween(last, now);
    if (days <= 0) continue;

    const decay = days * rule.confidenceDecayPerDay;
    const newConfidence = Math.max(0, rule.confidence - decay);

    rule.confidence = Number(newConfidence.toFixed(3));
    rule.lastSeenAt = new Date(now).toISOString();

    if (rule.confidence < rule.minConfidence) {
      rule.active = false;
      rule.expiresAt = new Date(now).toISOString();
      console.log(`🧠 Heuristic expired: ${rule.id}`);
    }

    changed = true;
  }

  if (changed) {
    fs.writeFileSync(HEURISTICS_FILE, JSON.stringify(data, null, 2), 'utf8');
  }
}

module.exports = { applyHeuristicDecay };
