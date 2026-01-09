const fs = require('fs');
const path = require('path');

const DATA_FILE = path.join(__dirname, '..', 'data', 'heuristics.json');

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

  let matched = [];
  let totalSuspicion = 0;

  for (const rule of heuristics.rules) {
    const c = rule.condition || {};
    let matchedRule = false;

    // URL based checks
    if (c.url_uses_ip) {
      if (_isIp(hostname)) matchedRule = true;
    }
    if (c.url_length_gt) {
      if ((url || '').length > c.url_length_gt) matchedRule = true;
    }
    if (c.url_encoded) {
      if ((url || '').includes('%')) matchedRule = true;
    }
    if (c.url_keywords_any) {
      const combined = (hostname + ' ' + pathAndQuery).toLowerCase();
      for (const kw of c.url_keywords_any) {
        if (combined.includes(kw.toLowerCase())) { matchedRule = true; break; }
      }
    }
    if (c.subdomain_count_gt != null) {
      if (subdomainCount > c.subdomain_count_gt) matchedRule = true;
    }
    if (c.double_extension) {
      if (doubleExtension) matchedRule = true;
    }
    if (c.url_contains_at) {
      if (hasAtSymbol) matchedRule = true;
    }

    // Domain checks
    if (c.domain_age_days_lt != null) {
      const whois = context.whois;
      if (whois && whois.createdDateTimestamp) {
        const ageDays = Math.floor((Date.now() - whois.createdDateTimestamp) / (1000 * 60 * 60 * 24));
        if (ageDays < c.domain_age_days_lt) matchedRule = true;
      }
    }
    if (c.tld_in) {
      const tld = hostname.split('.').pop();
      if (tld && c.tld_in.includes(tld.toLowerCase())) matchedRule = true;
    }
    if (c.ns_changed_recently) {
      const whois = context.whois || {};
      if ((whois.nameserverChangeDays != null && whois.nameserverChangeDays < c.ns_changed_recently) || whois.ns_changed === true) matchedRule = true;
    }
    if (c.dns_provider_in) {
      const provider = context.dnsProvider || context.whois?.dnsProvider;
      if (provider && c.dns_provider_in.includes(provider.toLowerCase())) matchedRule = true;
    }
    if (c.dga_score_gt != null) {
      const dga = context.dga_score ?? context.dgaScore;
      if (dga != null && dga > c.dga_score_gt) matchedRule = true;
    }

    // Brand checks
    if (c.brand_match) {
      const lowerHost = hostname.toLowerCase();
      for (const b of knownBrands) {
        if (lowerHost.includes(b)) { matchedRule = true; break; }
      }
    }
    if (c.brand_hyphenated) {
      const lowerHost = hostname.toLowerCase();
      for (const b of knownBrands) {
        if (lowerHost.includes(b + '-') || lowerHost.includes('-' + b) || lowerHost.endsWith(b + 's')) { matchedRule = true; break; }
      }
    }
    if (c.brand_typosquat) {
      const lowerHost = hostname.toLowerCase();
      for (const b of knownBrands) {
        const sld = (lowerHost.split('.').slice(0, -1).join('.')) || lowerHost.split('.')[0];
        if (levenshtein(sld, b) <= 1 && sld !== b) { matchedRule = true; break; }
      }
    }
    if (c.brand_login_mismatch) {
      const hasPassword = findings.some(f => /password/i.test(f));
      const lowerHost = hostname.toLowerCase();
      let brandPresent = false;
      for (const b of knownBrands) if (lowerHost.includes(b)) brandPresent = true;
      if (hasPassword && !brandPresent) matchedRule = true;
    }
    if (c.brand_hosting_mismatch) {
      const abuse = context.abuseIPDB || {};
      const isp = (abuse.isp || '').toLowerCase();
      const lowerHost = hostname.toLowerCase();
      let brandPresent = false;
      for (const b of knownBrands) if (lowerHost.includes(b)) brandPresent = true;
      if (brandPresent && /amazon|digitalocean|linode|cloudflare|google|azure|ovh|hetzner/i.test(isp)) matchedRule = true;
    }

    // Country / geo
    if (c.country_in) {
      const country = context.country;
      if (country && c.country_in.includes(country)) matchedRule = true;
    }
    if (c.language_country_mismatch) {
      if (context.language && context.country && context.languageCountry && context.languageCountry !== context.country) matchedRule = true;
      if (context.language && context.country && context.language.toLowerCase().includes('en') && context.country === 'cn') matchedRule = true; // fallback heuristic
    }

    // SSL checks
    if (c.https === false) {
      if (!urlObj || urlObj.protocol !== 'https:') matchedRule = true;
    }
    if (c.ssl_age_days_lt != null) {
      const ssl = context.ssl;
      if (ssl && ssl.validTo) {
        const validTo = new Date(ssl.validTo);
        const now = new Date();
        const diffDays = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        if (diffDays < c.ssl_age_days_lt) matchedRule = true;
      }
    }
    if (c.ssl_self_signed) {
      const ssl = context.ssl;
      if (ssl && ssl.issuer && ssl.issuer.toLowerCase().includes('self')) matchedRule = true;
    }

    // ASN / network
    if (c.asn_abuse_score_gt != null) {
      const abuse = context.abuseIPDB;
      if (abuse && abuse.abuseConfidenceScore != null) {
        if (abuse.abuseConfidenceScore > c.asn_abuse_score_gt) matchedRule = true;
      }
    }
    if (c.asn_bulletproof) {
      const abuse = context.abuseIPDB;
      if (abuse && abuse.isBulletproof) matchedRule = true; // set by upstream if detected
    }
    if (c.ip_age_days_lt != null) {
      const ipAge = context.ip_age_days ?? context.ipAgeDays;
      if (ipAge != null && ipAge < c.ip_age_days_lt) matchedRule = true;
    }
    if (c.domains_on_ip_gt != null) {
      const d = context.domains_on_ip ?? context.domainsOnIp;
      if (d != null && d > c.domains_on_ip_gt) matchedRule = true;
    }
    if (c.no_ptr_record) {
      if (context.no_ptr_record || context.noPtrRecord) matchedRule = true;
    }

    // Page behaviour & content
    if (c.login_form_detected) {
      const hasPasswordField = findings.some(f => /password input detected/i.test(f));
      const externalForm = findings.some(f => /External form submission/i.test(f));
      if (hasPasswordField && externalForm) matchedRule = true;
    }

    if (c.password_field && c.brand_match) {
      const hasPassword = findings.some(f => /password/i.test(f));
      let brandPresent = false;
      const lowerHost = hostname.toLowerCase();
      for (const b of knownBrands) if (lowerHost.includes(b)) brandPresent = true;
      if (hasPassword && brandPresent) matchedRule = true;
    }

    if (c.js_redirect) {
      if (findings.some(f => /window.location|document.location|location.href/.test(f))) matchedRule = true;
    }
    if (c.external_form_action) {
      if (findings.some(f => /External form submission to:/i.test(f))) matchedRule = true;
    }

    if (c.hidden_inputs) {
      if (findings.some(f => /hidden input/i.test(f))) matchedRule = true;
    }

    if (c.content_keywords_any) {
      for (const kw of c.content_keywords_any) {
        if (findings.some(f => f.toLowerCase().includes(kw.toLowerCase())) || combinedText.includes(kw.toLowerCase())) { matchedRule = true; break; }
      }
    }

    if (c.auto_download) {
      if (findings.some(f => /automatic download/i.test(f))) matchedRule = true;
    }

    if (c.js_obfuscation_score_gt != null) {
      if (jsObfuscationScore > c.js_obfuscation_score_gt) matchedRule = true;
    }

    if (c.content_keywords_any) {
      for (const kw of c.content_keywords_any) {
        if (combinedText.includes(kw.toLowerCase())) { matchedRule = true; break; }
      }
    }

    if (c.download_type_in) {
      const dtypes = context.download_type_in ?? context.downloadTypes;
      if (Array.isArray(dtypes) && dtypes.length) {
        for (const dt of dtypes) if (combinedText.includes('.' + dt.toLowerCase())) { matchedRule = true; break; }
      }
    }

    if (c.script_dropper) {
      if ((/createObjectURL|msSaveOrOpenBlob|navigator\.msSaveBlob|appendChild\(.*iframe/i.test(contentHtml)) || findings.some(f => /script dropper|dropper/i.test(f)) ) matchedRule = true;
    }

    if (c.fake_captcha_detected) {
      if (context.fake_captcha_detected || findings.some(f => /captcha/i.test(f))) matchedRule = true;
    }

    // redirect checks (many derived fields might be provided in context by the caller)
    const redirects = context.redirects || {};
    const redirectList = redirects.redirects || [];
    if (c.redirect_count_gt != null) {
      const rc = redirects.redirectCount ?? redirectList.length;
      if (rc > c.redirect_count_gt) matchedRule = true;
    }
    if (c.redirect_via_shortener) {
      if (context.redirect_via_shortener) matchedRule = true;
    }
    if (c.redirect_to_ip) {
      if (context.redirect_to_ip) matchedRule = true;
    }
    if (c.redirect_cross_tld) {
      if (context.redirect_cross_tld) matchedRule = true;
    }
    if (c.redirect_country_mismatch) {
      if (redirectList.some(r => r.country && context.country && r.country !== context.country)) matchedRule = true;
    }
    if (c.meta_refresh) {
      if (context.meta_refresh || findings.some(f => /meta refresh/i.test(f))) matchedRule = true;
    }
    // detect redirect loop
    if (c.redirect_loop) {
      const seen = new Set();
      for (const r of redirectList) {
        if (seen.has(r.to)) { matchedRule = true; break; }
        seen.add(r.to);
      }
    }
    if (c.delayed_redirect) {
      if (context.delayed_redirect || findings.some(f => /delayed redirect|delay/i.test(f))) matchedRule = true;
    }
    if (c.https_to_http_redirect) {
      for (const r of redirectList) {
        try {
          const fromProto = new URL(r.from).protocol;
          const toProto = new URL(r.to).protocol;
          if (fromProto === 'https:' && toProto === 'http:') { matchedRule = true; break; }
        } catch {}
      }
    }

    // misc network checks
    if (c.ua_cloaking) if (context.ua_cloaking) matchedRule = true;
    if (c.geo_cloaking) if (context.geo_cloaking) matchedRule = true;
    if (c.anti_debugging) if (context.anti_debugging) matchedRule = true;
    if (c.delayed_payload) if (context.delayed_payload) matchedRule = true;
    if (c.fast_flux) if (context.fast_flux) matchedRule = true;
    if (c.ip_rotation_rate_gt != null) {
      const rate = context.ip_rotation_rate ?? context.ip_rotation_rate_gt_value ?? context.ipRotationRate;
      if (rate != null && rate > c.ip_rotation_rate_gt) matchedRule = true;
    }

    if (c.hosting_type) {
      const hosting = context.hosting_type ?? context.hostingType;
      if (hosting && hosting === c.hosting_type) matchedRule = true;
    }

    if (c.mx_missing) if (context.mx_missing || context.mxMissing) matchedRule = true;
    if (c.suspicious_txt) if (context.suspicious_txt || context.suspiciousTxt) matchedRule = true;

    if (c.brand_html_fingerprint_match) {
      if (context.brand_html_fingerprint_match) matchedRule = true;
    }

    if (c.homoglyph_domain) {
      if (/[^ -]/.test(hostname)) matchedRule = true;
    }

    if (c.brand_keyword_count_gt != null) {
      let count = 0;
      const comb = (hostname + ' ' + pathAndQuery).toLowerCase();
      for (const b of knownBrands) {
        const re = new RegExp(b, 'g');
        count += ((comb.match(re) || []).length);
      }
      if (count > c.brand_keyword_count_gt) matchedRule = true;
    }

    // brand/credential combos
    if (c.password_field && c.external_form_action) {
      const hasPassword = findings.some(f => /password/i.test(f));
      const external = findings.some(f => /External form submission/i.test(f));
      if (hasPassword && external) matchedRule = true;
    }

    if (matchedRule) {
      matched.push({ id: rule.id, score: rule.score || 0, description: rule.description });
      totalSuspicion += rule.score || 0;
    }
  }

  // Map suspicion points to a phase score (higher is better)
  const maxScore = 25;
  const cappedSuspicion = Math.min(totalSuspicion, maxScore);
  const score = Math.max(0, Math.round(maxScore - cappedSuspicion));

  let status = 'safe';
  if (cappedSuspicion >= 20) status = 'danger';
  else if (cappedSuspicion >= 10) status = 'warning';
  console.log("HEURISTICS DEBUG:", {
    totalSuspicion,
    matched
  });

  return {
    matched,
    totalSuspicion,
    score,
    maxScore,
    status
  };
}

function validate() {
  const knownKeys = new Set([
    'url_uses_ip','url_length_gt','url_encoded','url_keywords_any','subdomain_count_gt','double_extension','url_contains_at',
    'domain_age_days_lt','tld_in','ns_changed_recently','dns_provider_in','dga_score_gt',
    'brand_match','brand_hyphenated','brand_typosquat','brand_hosting_mismatch','brand_login_mismatch','brand_keyword_count_gt','brand_html_fingerprint_match','homoglyph_domain',
    'https','ssl_age_days_lt','ssl_self_signed','ssl_domain_mismatch',
    'asn_abuse_score_gt','asn_bulletproof','ip_age_days_lt','domains_on_ip_gt','no_ptr_record','ip_rotation_rate_gt','fast_flux',
    'login_form_detected','password_field','js_redirect','external_form_action','hidden_inputs','content_keywords_any','auto_download','js_obfuscation_score_gt','fake_captcha_detected','download_type_in','script_dropper','double_extension',
    'redirect_count_gt','redirect_via_shortener','redirect_to_ip','redirect_cross_tld','redirect_country_mismatch','meta_refresh','redirect_loop','delayed_redirect','https_to_http_redirect',
    'country_in','language_country_mismatch','hosting_type','ua_cloaking','geo_cloaking','anti_debugging','delayed_payload','mx_missing','suspicious_txt','cdn_serving_login'
  ]);

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

