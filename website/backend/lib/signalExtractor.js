function extractSignals(url, context = {}) {
  let urlObj;
  try {
    urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
  } catch {
    urlObj = null;
  }

  const hostname = urlObj?.hostname || '';
  const path = urlObj?.pathname || '';
  const query = urlObj?.search || '';

  const isIp =
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) ||
    /^\[[0-9a-f:]+\]$/.test(hostname);

  const contentFindings = context.content?.findings || [];

  const domainAgeDays = context.whois?.createdDate
    ? Math.floor(
        (Date.now() - new Date(context.whois.createdDate)) / 86400000
      )
    : null;

  const signals = {
    /* ======================
       URL
       ====================== */
    url_length: url.length,
    url_encoded: url.includes('%'),
    url_contains_at: url.includes('@'),
    url_uses_ip: isIp,

    /* ======================
       Domain
       ====================== */
    hostname,
    tld: hostname.split('.').pop(),
    subdomain_count:
      hostname.split('.').length > 2
        ? hostname.split('.').length - 2
        : 0,
    domain_age_days: domainAgeDays,

    /* ======================
       SSL
       ====================== */
    https: url.startsWith('https'),
    ssl_self_signed: context.ssl?.issuer
      ?.toLowerCase()
      ?.includes('self'),

    /* ======================
       Content / Behavior
       ====================== */
    login_form_detected: contentFindings.some(f =>
      /login|sign in/i.test(f)
    ),
    password_field: contentFindings.some(f =>
      /password/i.test(f)
    ),
    hidden_inputs: contentFindings.some(f =>
      /hidden/i.test(f)
    ),
    js_redirect: contentFindings.some(f =>
      /javascript redirect|window\.location|location\.href/i.test(f)
    ),

    /* ======================
       Redirects
       ====================== */
    redirect_count: context.redirects?.redirectCount ?? 0,

    /* ======================
       Network / Geo
       ====================== */
    asn_abuse_score: context.abuseIPDB?.abuseConfidenceScore ?? null,
    country: context.abuseIPDB?.countryCode?.toLowerCase() ?? null
  };

  return signals;
}

module.exports = { extractSignals };