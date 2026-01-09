const fetch = require('node-fetch');

async function test(url) {
  console.log('Testing:', url);
  try {
    const res = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0 (GuardianLink test)' } });
    const html = await res.text();
    const formMatch = html.match(/<form[^>]*action=["']([^"']+)["']/gi);
    const urlHostRaw = new URL(url.startsWith('http') ? url : `https://${url}`).hostname;
    const normalize = h => (h || '').toString().toLowerCase().replace(/^www\./, '');
    const urlHost = normalize(urlHostRaw);

    const findings = [];
    if (formMatch) {
      for (const form of formMatch) {
        const actionMatch = form.match(/action=["']([^"']+)["']/i);
        if (actionMatch) {
          try {
            const formHostRaw = new URL(actionMatch[1], url).hostname;
            const formHost = normalize(formHostRaw);
            if (formHost && formHost !== urlHost) {
              findings.push(`External form submission to: ${formHost}`);
            }
          } catch (e) {}
        }
      }
    }

    console.log('url host:', urlHostRaw, '=> normalized:', urlHost);
    console.log('Findings:', findings.length ? findings : 'none');
  } catch (err) {
    console.error('Fetch error:', err.message);
  }
}

const url = process.argv[2] || 'https://www.jecrcuniversity.edu.in';
void test(url).then(() => process.exit(0));
