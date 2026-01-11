const fs = require('fs');
const path = require('path');

const DATA_FILE =
  process.env.HEURISTICS_FILE ||
  path.join(__dirname, '..', 'data', 'heuristics.json');

fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });

let heuristics = { version: '1.0', description: '', rules: [] };

function load() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    heuristics = JSON.parse(raw);
    return heuristics;
  } catch (err) {
    console.warn('heuristicsManager: could not load heuristics file, initializing empty rules', err.message);
    heuristics = { version: '1.0', description: '', rules: [] };
    try {
      fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
      fs.writeFileSync(DATA_FILE, JSON.stringify(heuristics, null, 2), 'utf8');
    } catch (e) {}
    return heuristics;
  }
}
function save() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(heuristics, null, 2), 'utf8');
}

function getAll() {
  return heuristics;
}

// simple levenshtein distance
function levenshtein(a = '', b = '') {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}
const CONDITION_HANDLERS = {
  url_uses_ip: ({ hostname }) => _isIp(hostname),

  url_length_gt: ({ url }, v) => (url || '').length > v,

  url_encoded: ({ url }) => (url || '').includes('%'),

  url_keywords_any: ({ hostname, pathAndQuery }, list) => {
    const combined = (hostname + ' ' + pathAndQuery).toLowerCase();
    return list.some(k => combined.includes(k.toLowerCase()));
  },

  subdomain_count_gt: ({ subdomainCount }, v) => subdomainCount > v,

  double_extension: ({ doubleExtension }) => doubleExtension,

  url_contains_at: ({ hasAtSymbol }) => hasAtSymbol,

  tld_in: ({ hostname }, list) =>
    list.includes(hostname.split('.').pop()),

  ssl_self_signed: ({ ssl }) =>
    ssl?.issuer?.toLowerCase().includes('self'),

  js_obfuscation_score_gt: ({ jsObfuscationScore }, v) =>
    jsObfuscationScore > v,

  redirect_count_gt: ({ redirects }, v) =>
    (redirects?.redirectCount ?? redirects?.redirects?.length ?? 0) > v,

  hosting_type: ({ hostingType }, v) =>
    hostingType === v,

  ip_age_days_lt: ({ ipAgeDays }, v) =>
  ipAgeDays != null && ipAgeDays < v,

};

function _isIp(hostname) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^\[[0-9a-f:]+\]$/.test(hostname);
}

function evaluate(url, context = {}) {
  const normalizedUrl = (() => {
    try {
      return url.startsWith('http') ? url : `https://${url}`;
    } catch {
      return url;
    }
  })();

  // context may include: ssl, content, abuseIPDB, redirects, securityHeaders, whois, and many derived flags
  const urlObj = (() => {
    try { return new URL(normalizedUrl); } catch { return null; }
  })();
  const hostname = urlObj ? urlObj.hostname : (url || '');
  const pathAndQuery = urlObj ? (urlObj.pathname + (urlObj.search || '')) : '';

  // helper derived values
  const parts = hostname.split('.').filter(Boolean);
  const subdomainCount = parts.length > 2 ? parts.length - 2 : 0;
  const doubleExtension = /\/[^\/]+\.[a-z0-9]{1,6}\.[a-z0-9]{1,6}(?:\?|$)/i.test(pathAndQuery);
  const hasAtSymbol = (url || '').includes('@');
  const content = context.content || {};
  const findings = content.findings || [];
  const contentHtml = (content.html || content.raw || '').toString();
  const lowerContent = contentHtml.toLowerCase();

  // simple JS obfuscation score (0..1)
  const obfMatches = (contentHtml.match(/eval\(|unescape\(|atob\(|btoa\(|%[0-9a-f]{2}/ig) || []).length;
  const jsObfuscationScore = Math.min(1, obfMatches / 5);

  const combinedText = (hostname + ' ' + pathAndQuery + ' ' + lowerContent).toLowerCase();

  const knownBrands = [
    'google','microsoft','facebook','apple','amazon','paypal','github','linkedin','icloud','office','spotify','netflix'
  ];

  let matchedRules = [];
  let totalSuspicion = 0;

  const contextValues = {
    url,
    hostname,
    pathAndQuery,
    subdomainCount,
    doubleExtension,
    hasAtSymbol,
    ssl: context.ssl,
    redirects: context.redirects,
    jsObfuscationScore,
    hostingType: context.hosting_type ?? context.hostingType,
    ipAgeDays: context.ip_age_days ?? context.ipAgeDays
  };

  for (const rule of heuristics.rules) {
    let ruleMatched = true;

    for (const [condKey, condValue] of Object.entries(rule.condition || {})) {
      const handler = CONDITION_HANDLERS[condKey];

      if (!handler || !handler(contextValues, condValue)) {
        ruleMatched = false;
        break;
      }
    }

    if (ruleMatched) {
      matchedRules.push(rule);
      totalSuspicion += rule.score;
      if (typeof rule.confidence === 'number') {
        rule.confidence = Math.min(1.0, rule.confidence + 0.05);
      } else {
        rule.confidence = 0.55; // initialize if missing
      }
      rule.lastSeenAt = new Date().toISOString();
    }
  }

  // Map suspicion points to a phase score (higher is better)
  const maxScore = 25;
  const cappedSuspicion = Math.min(totalSuspicion, maxScore);
  const score = Math.max(0, Math.round(maxScore - cappedSuspicion));

  let status = 'safe';
  if (cappedSuspicion >= 20) status = 'danger';
  else if (cappedSuspicion >= 10) status = 'warning';
  save();
  return {
    matchedRules,
    totalSuspicion,
    score,
    maxScore,
    status
  };
}

function validate() {
  const knownKeys = new Set(Object.keys(CONDITION_HANDLERS));
  const problems = [];
  const ids = new Set();
  (heuristics.rules || []).forEach((r, idx) => {
    if (!r.id) problems.push({ idx, problem: 'missing id' });
    if (r.id && ids.has(r.id)) problems.push({ idx, id: r.id, problem: 'duplicate id' });
    ids.add(r.id);
    const keys = Object.keys(r.condition || {});
    for (const k of keys) if (!knownKeys.has(k)) problems.push({ idx, id: r.id, problem: `unknown condition key: ${k}` });
  });

  return problems;
}

module.exports = { load, getAll, evaluate, validate };