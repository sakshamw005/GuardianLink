require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const rulesManager = require('./lib/rulesManager');
const crypto = require('crypto');
const scansStore = new Map(); // scanId -> { id, userId, url, status, scan_result, created_at }
const extensionSessions = new Map(); // extensionToken -> { sessionId, deviceInfo, createdAt }
const heuristicsManager = require('./lib/heuristicsManager');

const app = express();
const PORT = process.env.PORT || 3001;


// ========== MIDDLEWARE ==========
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:5173",
  "http://localhost:5174",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:3001",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:5174"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true
}));
// Capture raw body while validating initial JSON character to avoid consuming the stream twice
app.use(express.json({
  verify: (req, res, buf) => {
    try { req.rawBody = buf.toString(); } catch (e) { req.rawBody = null; }
    const trimmed = (req.rawBody || '').trimLeft();
    if (trimmed && !trimmed.startsWith('{') && !trimmed.startsWith('[')) {
      const err = new Error('Request body is not valid JSON (unexpected leading character)');
      err.type = 'entity.parse.failed';
      throw err;
    }
  }
}));

// Better JSON parse error responses (body-parser errors are surfaced here)
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    console.warn('Invalid JSON body received:', err.message);
    // Log raw body for debugging (avoid logging sensitive data in production)
    console.warn('Raw body preview:', (req && req.rawBody) ? req.rawBody.slice(0, 1000) : '<<none>>');
    return res.status(400).json({
      error: 'INVALID_JSON',
      message: 'Request body is not valid JSON',
      details: err.message
    });
  }
  next(err);
});

// Load rules (whitelist / blacklist) into memory
try {
  rulesManager.load();
  console.log(`Rules loaded: ${rulesManager.count()} entries`);
} catch (err) {
  console.error('Failed to load rules:', err);
}

// Load heuristic rules
try {
  heuristicsManager.load();
  console.log(`Heuristics loaded: ${heuristicsManager.getAll().rules.length} rules`);
} catch (err) {
  console.error('Failed to load heuristics:', err);
}

// Rate limiting middleware
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: process.env.RATE_LIMIT || 100,
  message: 'Too many requests'
});
app.use('/api/', limiter);

// Extension token verification (in-memory)
function verifyExtensionToken(req, res, next) {
  const token = req.headers['x-extension-token'];
  if (!token) return res.status(401).json({ error: 'No extension token' });
  const session = extensionSessions.get(token);
  if (!session) return res.status(401).json({ error: 'Invalid extension token' });
  req.session = session;
  next();
}

// Authentication removed (no DB/JWT or user registration in this build)
// Health check (detailed version appears later in the file) -- previously used DB; removed duplicate.

// ========== EXTENSION ENDPOINTS ==========

// Register extension session (public endpoint)
app.post('/api/extension/register', (req, res) => {
  const extensionToken = crypto.randomUUID();
  const sessionId = crypto.randomUUID();
  const { deviceInfo } = req.body;
  
  // Store in-memory (no DB)
  extensionSessions.set(extensionToken, {
    sessionId,
    deviceInfo: deviceInfo || null,
    createdAt: new Date().toISOString()
  });

  res.json({
    extensionToken,
    sessionId,
    message: 'Extension registered successfully'
  });
});

// Verify extension is connected (returns session info)
app.get('/api/extension/verify', verifyExtensionToken, (req, res) => {
  const session = req.session;
  res.json({
    authenticated: true,
    sessionId: session.sessionId,
    deviceInfo: session.deviceInfo
  });
});

// ========== SCANNING ENDPOINTS ==========

// VirusTotal URL scan
async function scanWithVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  
  if (!apiKey) {
    console.warn('⚠️ VirusTotal API key not configured');
    return { 
      error: 'API key not configured', 
      score: 0, 
      maxScore: 25,
      status: 'warning',
      available: false 
    };
  }
  
  try {
    // First, submit the URL for scanning
    const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(url)}`
    });
    
    const submitData = await submitResponse.json();
    
    // Check for API key errors
    if (submitData.error) {
      const errorMsg = submitData.error.message || JSON.stringify(submitData.error);
      if (errorMsg.includes('API key') || errorMsg.includes('Invalid') || errorMsg.includes('Unauthorized')) {
        console.error('❌ VirusTotal API key error:', errorMsg);
        return { 
          error: 'Invalid or expired API key', 
          score: 0, 
          maxScore: 25,
          status: 'warning',
          available: false 
        };
      }
      console.error('VirusTotal submit error:', submitData.error);
      return { error: submitData.error.message, score: 0, maxScore: 25 };
    }
    
    // Get the analysis ID
    const analysisId = submitData.data?.id;
    
    if (!analysisId) {
      return { error: 'No analysis ID returned', score: 0, maxScore: 25 };
    }
    
    let analysisData;
    let attempts = 0;

    while (true) {
      const res = await fetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        { headers: { 'x-apikey': apiKey } }
      );

      analysisData = await res.json();
      const status = analysisData?.data?.attributes?.status;

      if (status === 'completed') break;

      await new Promise(r => setTimeout(r, 3000));
      attempts++;
    }

    if (!analysisData || analysisData.data?.attributes?.status !== 'completed') {
      return {
        error: 'VirusTotal analysis timeout',
        score: 0,
        maxScore: 25,
        status: 'danger'
      };
    }
    
    const attributes = analysisData.data?.attributes || {};
    const stats = attributes.stats || {};
    const results = attributes.results || {};

    const isMaliciousByAnyAV = Object.values(results).some(
      engine => engine.category === 'malicious'
    );

    if (isMaliciousByAnyAV) {
      return {
        malicious: stats.malicious || 1,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
        total:
          (stats.malicious || 0) +
          (stats.suspicious || 0) +
          (stats.harmless || 0) +
          (stats.undetected || 0),
        score: 0,
        maxScore: 25,
        status: 'danger',
        mandate: 'malicious'
      };
    }

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const total = malicious + suspicious + harmless + undetected;
    
    // Calculate score (higher is better)
    let score = 25;
    if (malicious > 0) {
      score = Math.max(0, 25 - (malicious * 5));
    } else if (suspicious > 0) {
      score = Math.max(10, 25 - (suspicious * 3));
    }
    
    return {
      malicious,
      suspicious,
      harmless,
      undetected,
      total,
      score,
      maxScore: 25,
      status: malicious > 0 ? 'danger' : suspicious > 0 ? 'warning' : 'safe'
    };
  } catch (error) {
    console.error('VirusTotal error:', error);
    return { error: error.message, score: 0, maxScore: 25 };
  }
}

// AbuseIPDB check (for domain IP)
async function checkWithAbuseIPDB(domain) {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  
  if (!apiKey) {
    console.warn('⚠️ AbuseIPDB API key not configured');
    return { 
      error: 'API key not configured', 
      score: 15, 
      maxScore: 15,
      status: 'warning',
      available: false 
    };
  }
  
  try {
    // First resolve domain to IP using DNS lookup
    const dns = require('dns').promises;
    let ip;
    
    try {
      const hostname = new URL(domain.startsWith('http') ? domain : `https://${domain}`).hostname;
      const addresses = await dns.lookup(hostname);
      ip = addresses.address;
    } catch (dnsError) {
      console.error('DNS lookup error:', dnsError);
      return { error: 'Could not resolve domain', score: 15, maxScore: 15, status: 'warning' };
    }
    
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      }
    });
    
    const data = await response.json();
    
    if (data.errors) {
      const errorMsg = data.errors[0]?.detail || JSON.stringify(data.errors);
      if (errorMsg.includes('API key') || errorMsg.includes('Invalid') || errorMsg.includes('Unauthorized')) {
        console.error('❌ AbuseIPDB API key error:', errorMsg);
        return { 
          error: 'Invalid or expired API key', 
          score: 15, 
          maxScore: 15,
          status: 'warning',
          available: false 
        };
      }
      console.error('AbuseIPDB error:', data.errors);
      return { error: errorMsg, score: 0, maxScore: 15 };
    }
    
    const abuseScore = data.data?.abuseConfidenceScore || 0;
    const totalReports = data.data?.totalReports || 0;
    
    // Calculate our score (higher is better, so invert abuse score)
    let score = Math.round(15 * (1 - abuseScore / 100));
    
    return {
      ip,
      abuseConfidenceScore: abuseScore,
      totalReports,
      countryCode: data.data?.countryCode,
      isp: data.data?.isp,
      score,
      maxScore: 15,
      status: abuseScore > 50 ? 'danger' : abuseScore > 20 ? 'warning' : 'safe'
    };
  } catch (error) {
    console.error('AbuseIPDB error:', error);
    return { error: error.message, score: 0, maxScore: 15 };
  }
}

// SSL Certificate check
async function checkSSL(url) {
  try {
    const https = require('https');
    const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
    
    if (urlObj.protocol !== 'https:') {
      return { 
        valid: false, 
        error: 'Not using HTTPS', 
        score: 0, 
        maxScore: 15,
        status: 'danger'
      };
    }
    
    return new Promise((resolve) => {
      const req = https.request({
        hostname: urlObj.hostname,
        port: 443,
        method: 'HEAD',
        timeout: 10000
      }, (res) => {
        const cert = res.socket.getPeerCertificate();
        
        if (!cert || Object.keys(cert).length === 0) {
          resolve({ 
            valid: false, 
            error: 'No certificate found', 
            score: 0, 
            maxScore: 15,
            status: 'danger'
          });
          return;
        }
        
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = new Date();
        const isValid = now >= validFrom && now <= validTo;
        const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        
        let score = 15;
        let status = 'safe';
        
        if (!isValid) {
          score = 0;
          status = 'danger';
        } else if (daysUntilExpiry < 30) {
          score = 10;
          status = 'warning';
        }
        
        resolve({
          valid: isValid,
          issuer: cert.issuer?.O || 'Unknown',
          validFrom: validFrom.toISOString(),
          validTo: validTo.toISOString(),
          daysUntilExpiry,
          score,
          maxScore: 15,
          status
        });
      });
      
      req.on('error', (error) => {
        resolve({ 
          valid: false, 
          error: error.message, 
          score: 0, 
          maxScore: 15,
          status: 'danger'
        });
      });
      
      req.on('timeout', () => {
        req.destroy();
        resolve({ 
          valid: false, 
          error: 'Connection timeout', 
          score: 5, 
          maxScore: 15,
          status: 'warning'
        });
      });
      
      req.end();
    });
  } catch (error) {
    return { 
      valid: false, 
      error: error.message, 
      score: 0, 
      maxScore: 15,
      status: 'danger'
    };
  }
}

// Domain age check using WHOIS-like heuristics
async function checkDomainAge(url) {
  try {
    const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
    const domain = urlObj.hostname;

    // If hostname is an IP literal, treat as highly suspicious
    const isIp = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain) || /^\[[0-9a-f:]+\]$/.test(domain);
    if (isIp) {
      return {
        domain,
        score: 0,
        maxScore: 10,
        status: 'danger',
        warnings: ['Hostname is an IP address literal - suspicious']
      };
    }

    // We'll use a simple heuristic based on domain characteristics
    // In production, you'd want to use a WHOIS API
    const suspiciousPatterns = [
      /\d{4,}/, // Long numbers
      /-{2,}/, // Multiple hyphens
      /[a-z]{20,}/, // Very long words
      /\.(tk|ml|ga|cf|gq)$/i, // Free TLD domains often used for phishing
    ];

    let score = 10;
    let status = 'safe';
    const warnings = [];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(domain)) {
        score -= 3;
        warnings.push(`Suspicious pattern detected: ${pattern.source}`);
      }
    }

    // If WHOIS data available via fetchWhois elsewhere, prefer that
    // The caller may pass a whois object into heuristicsManager for domain-age checks.

    if (score < 7) status = 'warning';
    if (score < 4) status = 'danger';

    return {
      domain,
      score: Math.max(0, score),
      maxScore: 10,
      status,
      warnings
    };
  } catch (error) {
    return { error: error.message, score: 5, maxScore: 10, status: 'warning' };
  }
}

// WHOIS lookup (optional -- requires WHOIS_API_KEY in .env)
async function fetchWhois(url) {
  const apiKey = process.env.WHOIS_API_KEY;

  if (!apiKey) {
    return {
      available: false,
      score: 0,
      maxScore: 10,
      status: 'warning',
      reason: 'WHOIS API key not configured'
    };
  }

  try {
    const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
    const domain = urlObj.hostname;

    const whoisUrl = `https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=${encodeURIComponent(domain)}&apiKey=${apiKey}&outputFormat=JSON`;

    const res = await fetch(whoisUrl);
    const data = await res.json();

    const parsed = data.WhoisRecord || {};
    const parsedDates = parsed.registryDataParsed || parsed.registryData || {};
    const created = parsedDates.createdDateNormalized || parsed.createdDate || null;

    let createdTs = null;
    if (created) {
      const d = new Date(created);
      if (!isNaN(d)) createdTs = d.getTime();
    }

    return {
      available: true,
      domain,
      createdDate: created,
      score: createdTs ? 10 : 5,
      maxScore: 10,
      status: createdTs ? 'safe' : 'warning'
    };

  } catch (error) {
    console.error('WHOIS error:', error.message);
    return {
      available: false,
      score: 0,
      maxScore: 10,
      status: 'warning',
      reason: 'WHOIS lookup failed or timed out'
    };
  }
}

// Content analysis
async function analyzeContent(url) {
  try {
    const response = await fetch(url.startsWith('http') ? url : `https://${url}`, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; GuardianLink/1.0; Security Scanner)'
      }
    });

    const html = await response.text();
    const lowerHtml = html.toLowerCase();

    let score = 15;
    let status = 'safe';
    const findings = [];

    // Expanded phishing indicators
    const phishingKeywords = [
      'verify your account',
      'confirm your identity',
      'suspended account',
      'unusual activity',
      'update payment',
      'click here immediately',
      'login',
      'sign in',
      'username',
      'password',
      'bank',
      'urgent',
      'FIR',
      'legal action',
      'limited time',
      'security alert',
      'account locked'
    ];

    for (const keyword of phishingKeywords) {
      if (lowerHtml.includes(keyword)) {
        score -= 3;
        findings.push(`Suspicious phrase: "${keyword}"`);
      }
    }

    // Detect explicit password inputs
    if (/<input[^>]*type=["']?password["']?/i.test(html)) {
      score -= 5;
      findings.push('Password input detected');
    }

    // Detect meta refresh redirect
    if (/<meta[^>]*http-equiv=["']?refresh["']?/i.test(html)) {
      score -= 3;
      findings.push('Meta refresh redirect detected');
    }

    // Detect JS redirects
    if (/(window\.location|document\.location|location\.href|location.replace|location.assign)/i.test(html)) {
      score -= 3;
      findings.push('JavaScript redirect detected');
    }

    // Detect obfuscated script patterns (simple heuristics)
    if (/(eval\(|unescape\(|atob\(|btoa\()/.test(html) || /%[0-9a-f]{2}/i.test(html)) {
      score -= 2;
      findings.push('Potential obfuscated content detected');
    }

    // Check for hidden forms (improved)
    if (/<input[^>]*type=["']?hidden["']?/i.test(html) && /password/i.test(html)) {
      score -= 4;
      findings.push('Hidden password-related field detected');
    }

    // Check for external form submissions (keeps prior behaviour)
    const formMatch = html.match(/<form[^>]*action=["']([^"']+)["']/gi);
    if (formMatch) {
      const urlHost = new URL(url.startsWith('http') ? url : `https://${url}`).hostname;
      for (const form of formMatch) {
        const actionMatch = form.match(/action=["']([^"']+)["']/i);
        if (actionMatch && actionMatch[1].startsWith('http')) {
          try {
            const formHost = new URL(actionMatch[1]).hostname;
            if (formHost !== urlHost) {
              score -= 4;
              findings.push(`External form submission to: ${formHost}`);
            }
          } catch {}
        }
      }
    }

    if (score < 10) status = 'warning';
    if (score < 5) status = 'danger';

    return {
      score: Math.max(0, score),
      maxScore: 15,
      status,
      findings
    };
  } catch (error) {
    return { error: error.message, score: 10, maxScore: 15, status: 'warning' };
  }
}
// Redirect chain analysis
async function analyzeRedirects(url) {
  try {
    const redirects = [];
    let currentUrl = url.startsWith('http') ? url : `https://${url}`;
    let maxRedirects = 10;

    while (maxRedirects > 0) {
      const response = await fetch(currentUrl, {
        redirect: 'manual',
        timeout: 5000
      });

      const location = response.headers.get('location');
      if (location && (response.status >= 300 && response.status < 400)) {
        redirects.push({
          from: currentUrl,
          to: location,
          status: response.status
        });
        currentUrl = location.startsWith('http') ? location : new URL(location, currentUrl).href;
        maxRedirects--;
      } else {
        break;
      }
    }

    let score = 10;
    let status = 'safe';

    if (redirects.length > 3) {
      score -= 3;
      status = 'warning';
    }

    if (redirects.length > 5) {
      score -= 4;
      status = 'danger';
    }

    // Check for suspicious redirect destinations and IP destinations
    for (const redirect of redirects) {
      try {
        const toHost = new URL(redirect.to).hostname;
        if (toHost.includes('bit.ly') || toHost.includes('tinyurl') || toHost.includes('t.co')) {
          score -= 2;
          redirect.suspicious = 'known shortener';
        }
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(toHost) || /^\[[0-9a-f:]+\]$/.test(toHost)) {
          score -= 3;
          redirect.suspicious = 'redirects to IP host';
        }
      } catch {}
    }

    // Fetch final destination content to detect meta/JS redirects not using Location header
    try {
      const finalResp = await fetch(currentUrl, { timeout: 8000, redirect: 'follow' });
      const finalHtml = await finalResp.text();
      if (/<meta[^>]*http-equiv=["']?refresh["']?/i.test(finalHtml)) {
        score -= 3;
      }
      if (/(window\.location|document\.location|location\.href|location.replace|location.assign)/i.test(finalHtml)) {
        score -= 3;
      }
    } catch (e) {
      // ignore final content issues
    }

    if (score < 7) status = 'warning';
    if (score < 4) status = 'danger';

    return {
      redirectCount: redirects.length,
      redirects,
      score: Math.max(0, score),
      maxScore: 10,
      status
    };
  } catch (error) {
    return { error: error.message, score: 5, maxScore: 10, status: 'warning' };
  }
}

// Headers security check
async function checkSecurityHeaders(url) {
  try {
    const response = await fetch(url.startsWith('http') ? url : `https://${url}`, {
      timeout: 10000
    });
    
    const headers = response.headers;
    let score = 0;
    const maxScore = 10;
    const findings = [];
    
    const securityHeaders = {
      'strict-transport-security': 2,
      'x-content-type-options': 1,
      'x-frame-options': 1,
      'x-xss-protection': 1,
      'content-security-policy': 3,
      'referrer-policy': 1,
      'permissions-policy': 1
    };
    
    for (const [header, points] of Object.entries(securityHeaders)) {
      if (headers.get(header)) {
        score += points;
        findings.push(`✓ ${header}`);
      } else {
        findings.push(`✗ Missing ${header}`);
      }
    }
    
    score = Math.min(score, maxScore);
    let status = 'safe';
    if (score < 7) status = 'warning';
    if (score < 4) status = 'danger';
    
    return {
      score,
      maxScore,
      status,
      findings
    };
  } catch (error) {
    return { error: error.message, score: 0, maxScore: 10, status: 'warning' };
  }
}

// Main scan endpoint
app.post('/api/scan', async (req, res) => {
  const { url, source } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  // Phase 0: Domain existence check
  const dns = require('dns').promises;
  let hostname;

  // Validate URL and extract hostname
  try {
    hostname = new URL(url.startsWith('http') ? url : `https://${url}`).hostname;
  } catch (err) {
    return res.status(400).json({ error: 'Invalid URL', message: 'Provided URL is not a valid URL' });
  }

  // Quick DNS resolution check (A/AAAA) to avoid wasting API calls
  let dnsResolved = true;
  let preflightWhois = null;
  try {
    await dns.lookup(hostname);
  } catch (err) {
    dnsResolved = false;
    console.warn(`DNS lookup failed for ${hostname}; attempting WHOIS lookup to verify registration...`);
    try {
      preflightWhois = await fetchWhois(url);
    } catch (whoisErr) {
      console.warn('WHOIS lookup failed during DNS fallback:', whoisErr && whoisErr.message ? whoisErr.message : whoisErr);
      preflightWhois = null;
    }
    const whoisConfirms = preflightWhois && preflightWhois.available && preflightWhois.createdDate;
    if (!whoisConfirms) {
      return res.status(404).json({
        error: 'DNS_PROBE_POSSIBLE',
        message: "This site can’t be reached",
        details: `${hostname}'s DNS address could not be found. WHOIS lookup did not confirm registration.`,
        uiHint: 'DNS_NOT_FOUND',
        whois: preflightWhois,
        overallStatus: 'danger'
      });
    }

    console.log(`WHOIS indicates ${hostname} is registered; proceeding with a limited scan (DNS unresolved).`);
  }

  // Phase 1: Whitelist check (fast)
  const whitelistMatch = rulesManager.isWhitelisted(url);

  if (whitelistMatch) {
    console.log(`Whitelist hit for ${url} (source: ${whitelistMatch.source || 'local'}) - skipping checks`);
    const results = {
      url,
      timestamp: new Date().toISOString(),
      phases: {
        whitelist: { name: 'Whitelist Check', score: 100, maxScore: 100, status: 'safe', reason: 'Whitelisted domain', evidence: whitelistMatch }
      },
      totalScore: 100,
      maxTotalScore: 100,
      percentage: 100,
      overallStatus: 'safe'
    };
    return res.json(results);
  }

  // Phase 2: Local blacklist (fast)
  const blacklistMatch = rulesManager.isBlacklisted(url);
  if (blacklistMatch) {
    console.log(`Local blacklist hit for ${url} (source: ${blacklistMatch.source || 'local'}) - blocked`);
    const results = {
      url,
      timestamp: new Date().toISOString(),
      phases: {
        localBlacklist: { name: 'Local Blacklist', score: 0, maxScore: 100, status: 'danger', reason: 'Blacklisted', evidence: blacklistMatch }
      },
      totalScore: 0,
      maxTotalScore: 100,
      percentage: 0,
      overallStatus: 'danger'
    };
    return res.json(results);
  }
  
  const scanId = crypto.randomUUID();
  
  console.log(`\n🔍 Scan ${scanId} started for: ${url} (from ${source || 'website'})`);
  
  // Store scan as pending (in-memory)
  scansStore.set(scanId, {
    id: scanId,
    userId: null,
    url,
    status: 'pending',
    created_at: new Date().toISOString(),
    source: source || 'website'
  });
  
  const results = {
    scanId,
    url,
    timestamp: new Date().toISOString(),
    phases: {},
    source: source || 'website'
  };
  
try {
    // If DNS resolved, run full checks in parallel; otherwise run a conservative set and mark skipped phases
    let virusTotal, abuseIPDB, ssl, domainAge, content, redirects, securityHeaders, whois;
    if (dnsResolved) {
      [
        virusTotal,
        abuseIPDB,
        ssl,
        domainAge,
        content,
        redirects,
        securityHeaders,
        whois
      ] = await Promise.all([
        scanWithVirusTotal(url),
        checkWithAbuseIPDB(url),
        checkSSL(url),
        checkDomainAge(url),
        analyzeContent(url),
        analyzeRedirects(url),
        checkSecurityHeaders(url),
        fetchWhois(url)
      ]);

      results.phases = {
        virusTotal: { name: 'VirusTotal Analysis', ...virusTotal },
        abuseIPDB: { name: 'AbuseIPDB Check', ...abuseIPDB },
        ssl: { name: 'SSL Certificate', ...ssl },
        domainAge: { name: 'Domain Analysis', ...domainAge },
        content: { name: 'Content Analysis', ...content },
        redirects: { name: 'Redirect Analysis', ...redirects },
        securityHeaders: { name: 'Security Headers', ...securityHeaders },
        whois: { name: 'WHOIS Lookup', ...whois }
      };
    } else {
      // DNS failed but WHOIS confirmed registration (preflightWhois). Do a limited scan to save API calls.
      whois = preflightWhois;
      [virusTotal, domainAge] = await Promise.all([
        scanWithVirusTotal(url),
        checkDomainAge(url)
      ]);

      abuseIPDB = { error: 'SKIPPED_DNS', score: 15, maxScore: 15, status: 'warning', reason: 'Skipped because DNS lookup failed' };
      ssl = { error: 'SKIPPED_DNS', score: 0, maxScore: 15, status: 'danger', reason: 'Skipped because DNS lookup failed' };
      content = { error: 'SKIPPED_DNS', score: 10, maxScore: 15, status: 'warning', findings: ['Content fetch skipped due to DNS lookup failure'] };
      redirects = { redirectCount: 0, redirects: [], score: 10, maxScore: 10, status: 'warning', reason: 'Skipped because DNS lookup failed' };
      securityHeaders = { error: 'SKIPPED_DNS', score: 0, maxScore: 10, status: 'warning', findings: ['Skipped because DNS lookup failed'] };

      results.phases = {
        virusTotal: { name: 'VirusTotal Analysis', ...virusTotal },
        abuseIPDB: { name: 'AbuseIPDB Check', ...abuseIPDB },
        ssl: { name: 'SSL Certificate', ...ssl },
        domainAge: { name: 'Domain Analysis', ...domainAge },
        content: { name: 'Content Analysis', ...content },
        redirects: { name: 'Redirect Analysis', ...redirects },
        securityHeaders: { name: 'Security Headers', ...securityHeaders },
        whois: { name: 'WHOIS Lookup', ...whois }
      };

      results.skippedPhases = ['abuseIPDB', 'ssl', 'content', 'redirects', 'securityHeaders'];
    }
  // Evaluate heuristics against the gathered context
  const domain = (() => {
    try { return new URL(url.startsWith('http') ? url : `https://${url}`).hostname; }
    catch { return url; }
  })();

  const heuristicContext = {
    domain,
    ssl,
    content,
    whois,
    redirects,
    securityHeaders,
    abuseIPDB,

    country: abuseIPDB?.countryCode?.toLowerCase(),
    asn_abuse_score: abuseIPDB?.abuseConfidenceScore,
    asn_bulletproof: abuseIPDB?.isBulletproof === true,
    

    redirect_count: redirects?.redirectCount ?? 0,
    redirect_to_ip: (redirects?.redirects || []).some(r => {
      try {
        return /^\d{1,3}(\.\d{1,3}){3}$/.test(new URL(r.to).hostname);
      } catch {
        return false;
      }
    }),
    redirect_via_shortener: (redirects?.redirects || []).some(r =>
      /bit\.ly|tinyurl|t\.co|goo\.gl/i.test(r.to)
    ),
    redirect_cross_tld: (redirects?.redirects || []).some(r => {
      try {
        return new URL(r.from).hostname.split('.').pop() !==
              new URL(r.to).hostname.split('.').pop();
      } catch {
        return false;
      }
    }),

    password_field: (content?.findings || []).some(f =>
      /password input/i.test(f)
    ),
    hidden_inputs: (content?.findings || []).some(f =>
      /hidden input/i.test(f)
    ),
    external_form_action: (content?.findings || []).some(f =>
      /External form submission/i.test(f)
    ),
    js_redirect: (content?.findings || []).some(f =>
      /JavaScript redirect/i.test(f)
    ),
    meta_refresh: (content?.findings || []).some(f =>
      /Meta refresh/i.test(f)
    ),
    login_form_detected: (content?.findings || []).some(f =>
      /login|sign in/i.test(f)
    ),

    auto_download: (content?.findings || []).some(f =>
      /automatic download/i.test(f)
    ) ,
    domain: (() => { try { return new URL(url).hostname; } catch { return url; } })() 
  };

  const heuristicsResult = heuristicsManager.evaluate(url, heuristicContext);

  results.phases.heuristics = { name: 'Heuristic Rules', ...heuristicsResult };
  
    // Calculate total score
    let totalScore = 0;
    let maxTotalScore = 0;
    
    for (const phase of Object.values(results.phases)) {
      totalScore += phase.score || 0;
      maxTotalScore += phase.maxScore || 0;
    }
    
    results.totalScore = totalScore;
    results.maxTotalScore = maxTotalScore;
    results.percentage = Math.round((totalScore / maxTotalScore) * 100);
    
    if (results.phases.virusTotal?.mandate === 'malicious') {
      results.overallStatus = 'danger';
      results.percentage = Math.min(results.percentage, 20);

      results.securityDecision = {
        action: 'BLOCK',
        reason: 'VirusTotal flagged malicious by at least one antivirus engine',
        confidence: 'HIGH'
      };
    }
    else{
    // Determine overall status
      if (results.percentage >= 80) {
        results.overallStatus = 'safe';
      } else if (results.percentage >= 50) {
        results.overallStatus = 'warning';
      } else {
        results.overallStatus = 'danger';
      }
    }
    
    // Store completed scan
    const entry = scansStore.get(scanId) || {};
    entry.status = 'completed';
    entry.scan_result = results;
    entry.completed_at = new Date().toISOString();
    scansStore.set(scanId, entry);
    
    console.log(`✅ Scan complete. Score: ${results.percentage}% (${results.overallStatus})`);
    
    res.json(results);
  } catch (error) {
    console.error('Scan error:', error);
    const entry = scansStore.get(scanId) || {};
    entry.status = 'failed';
    entry.failed_at = new Date().toISOString();
    scansStore.set(scanId, entry);
    res.status(500).json({ error: 'Scan failed', scanId });
  }
});

// Public scan history (in-memory)
app.get('/api/scans', (req, res) => {
  const limit = Number(req.query.limit || 50);
  const scans = Array.from(scansStore.values())
    .sort((a,b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, limit)
    .map(s => ({ id: s.id, url: s.url, status: s.status, created_at: s.created_at, scan_result: s.scan_result || null }));
  res.json(scans);
});

// Get specific scan details (public)
app.get('/api/scans/:scanId', (req, res) => {
  const { scanId } = req.params;
  const row = scansStore.get(scanId);
  if (!row) return res.status(404).json({ error: 'Scan not found' });
  res.json({ ...row, scan_result: row.scan_result || null });
});

// Real-time scan endpoint (from extension)
app.post('/api/scan/realtime', verifyExtensionToken, async (req, res) => {
  const { url, source } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  // Validate URL and DNS before doing any work
  const dns = require('dns').promises;
  let hostname;
  try {
    hostname = new URL(url.startsWith('http') ? url : `https://${url}`).hostname;
  } catch (err) {
    return res.status(400).json({ error: 'Invalid URL', message: 'Provided URL is not a valid URL' });
  }

  try {
    await dns.lookup(hostname);
  } catch (err) {
    return res.status(404).json({
      error: 'DNS_PROBE_POSSIBLE',
      message: "This site can’t be reached",
      details: `${hostname}'s DNS address could not be found. Diagnosing the problem.`,
      uiHint: 'DNS_NOT_FOUND',
      overallStatus: 'danger'
    });
  }

  const scanId = crypto.randomUUID();
  
  console.log(`\n🔍 Extension scan ${scanId} for: ${url}`);
  
  // Store extension scan (in-memory)
  scansStore.set(scanId, {
    id: scanId,
    userId: null,
    url,
    status: 'pending',
    created_at: new Date().toISOString(),
    source: 'extension'
  });
  
  const results = {
    scanId,
    url,
    timestamp: new Date().toISOString(),
    source: 'extension'
  };
  
  try {
    // Quick analysis for extension (with timeouts)
    const timeout = (promise, ms) => Promise.race([
      promise,
      new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), ms))
    ]);
    
    const [virusTotal, abuseIPDB] = await Promise.allSettled([
      timeout(scanWithVirusTotal(url), 3000),
      timeout(checkWithAbuseIPDB(url), 3000)
    ]);
    
    results.virusTotal = virusTotal.status === 'fulfilled' ? virusTotal.value : { error: 'Timeout' };
    results.abuseIPDB = abuseIPDB.status === 'fulfilled' ? abuseIPDB.value : { error: 'Timeout' };
    
    if (results.virusTotal.malicious > 0) riskScore -= 25;
    if (results.virusTotal.suspicious > 0) riskScore -= 10;
    if (results.abuseIPDB.abuseConfidenceScore > 50) riskScore -= 15;
    
    results.riskScore = Math.max(0, Math.min(100, riskScore));
    results.verdict = riskScore < 30 ? 'BLOCK' : riskScore < 60 ? 'WARN' : 'ALLOW';
    
    // Store result
    const entry = scansStore.get(scanId) || {};
    entry.status = 'completed';
    entry.scan_result = results;
    entry.completed_at = new Date().toISOString();
    scansStore.set(scanId, entry);
    
    res.json(results);
  } catch (error) {
    console.error('Extension scan error:', error);
    const entry = scansStore.get(scanId) || {};
    entry.status = 'failed';
    entry.failed_at = new Date().toISOString();
    scansStore.set(scanId, entry);
    res.status(500).json({ error: 'Scan failed', scanId, verdict: 'ALLOW' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    hasVirusTotalKey: !!process.env.VIRUSTOTAL_API_KEY,
    hasAbuseIPDBKey: !!process.env.ABUSEIPDB_API_KEY,
    hasWhoisKey: !!process.env.WHOIS_API_KEY,
    rulesCount: rulesManager.count(),
    heuristicsCount: (heuristicsManager.getAll().rules || []).length
  });
});

// Rules management endpoints (basic)
app.get('/api/rules', (req, res) => {
  res.json({ status: 'ok', rules: rulesManager.getAll() });
});

// Heuristics listing for review
app.get('/api/heuristics', (req, res) => {
  res.json({ status: 'ok', heuristics: heuristicsManager.getAll() });
});

// Heuristics validation (checks for duplicates / unknown condition keys)
app.get('/api/heuristics/validate', (req, res) => {
  try {
    const problems = heuristicsManager.validate();
    res.json({ status: 'ok', problems });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

app.post('/api/rules/reload', (req, res) => {
  try {
    rulesManager.load();
    res.json({ status: 'ok', count: rulesManager.count() });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

// Global error handler — return JSON instead of HTML so clients always get machine-readable errors
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err && (err.stack || err));
  if (res.headersSent) return next(err);
  const status = err && err.status ? err.status : 500;
  res.status(status).json({
    error: err && err.code ? err.code : 'INTERNAL_SERVER_ERROR',
    message: err && err.message ? err.message : 'An internal server error occurred'
  });
});

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🛡️  Guardian Link Backend Server v2.0                   ║
║                                                           ║
║   Server running on: http://localhost:${PORT}               ║
║                                                           ║
║   Endpoints:                                              ║
║   - (auth endpoints removed)                          ║
║   - POST /api/extension/register     - Register extension ║
║   - GET  /api/extension/verify       - Verify connection  ║
║   - POST /api/scan                   - Scan URL (website) ║
║   - POST /api/scan/realtime          - Scan (extension)   ║
║   - GET  /api/scans                  - Get scan history   ║
║   - GET  /api/health                 - Check status       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
  `);
  
  console.log('API Keys configured:');
  console.log(`  VirusTotal: ${process.env.VIRUSTOTAL_API_KEY ? '✓' : '✗'}`);
  console.log(`  AbuseIPDB:  ${process.env.ABUSEIPDB_API_KEY ? '✓' : '✗'}`);
  console.log(`  WHOIS:      ${process.env.WHOIS_API_KEY ? '✓' : '✗'}`);
});
