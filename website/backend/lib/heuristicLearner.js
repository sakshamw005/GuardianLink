const fs = require('fs');
const path = require('path');

const HEURISTICS_FILE =
  process.env.HEURISTICS_FILE ||
  path.join(__dirname, '..', 'data', 'heuristics.json');

fs.mkdirSync(path.dirname(HEURISTICS_FILE), { recursive: true });
/* ------------------ helpers ------------------ */

function loadHeuristics() {
  try {
    const raw = fs.readFileSync(HEURISTICS_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return { version: '1.0', rules: [] };
  }
}

function saveHeuristics(data) {
  fs.writeFileSync(HEURISTICS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function ruleExists(rules, conditions) {
  return rules.some(r =>
    JSON.stringify(r.conditions) === JSON.stringify(conditions)
  );
}

function makeRuleId(conditions) {
  const key = Object.keys(conditions).sort().join('-');
  return `learned:vt:${key}`;
}

/* ------------------ main learner ------------------ */

function learnFromVirusTotal(url, context) {
  const { virusTotal, content, redirects } = context;

  // Hard gate: learn ONLY from high-confidence VT malicious
  if (!virusTotal || virusTotal.mandate !== 'malicious') return;

  const heuristics = loadHeuristics();

  const learnedConditions = {};

  /* -------- pattern extraction -------- */

  if (content?.findings) {
    if (content.findings.some(f => /JavaScript redirect/i.test(f))) {
      learnedConditions.js_redirect = true;
    }

    if (content.findings.some(f => /Meta refresh/i.test(f))) {
      learnedConditions.meta_refresh = true;
    }

    if (content.findings.some(f => /Password input/i.test(f))) {
      learnedConditions.password_field = true;
    }

    if (content.findings.some(f => /login|sign in/i.test(f))) {
      learnedConditions.login_form_detected = true;
    }

    if (content.findings.some(f => /obfuscated/i.test(f))) {
      learnedConditions.obfuscated_script = true;
    }
  }

  if (redirects?.redirectCount >= 3) {
    learnedConditions.redirect_chain_long = true;
  }

  // If nothing meaningful learned → stop
  if (Object.keys(learnedConditions).length < 2) return;

  // Prevent duplicate heuristic rules
  if (ruleExists(heuristics.rules, learnedConditions)) return;

  /* -------- rule creation -------- */

  const newRule = {
    id: makeRuleId(learnedConditions),
    description: `Learned from VT-malicious URL: ${url}`,
    conditions: learnedConditions,
    severity: 'high',
    scoreImpact: -30,
    confidence: 0.85,
    source: 'virustotal-learning',
    createdAt: new Date().toISOString(),
    expiresAt: null
  };

  heuristics.rules.push(newRule);
  saveHeuristics(heuristics);

  console.log('🧠 Heuristic learned:', newRule.id);
}

module.exports = { learnFromVirusTotal };