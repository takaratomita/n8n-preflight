// Detection rules. Kept as plain data so they are easy to read, extend and test.
// Every regular expression uses bounded quantifiers or starts with a literal, so the
// scan stays roughly linear on large or hostile input (see the ReDoS test).

export const RULES = {
  'hardcoded-secret': { severity: 'error', summary: 'A value that looks like a real API key, token or private key.' },
  'secret-field': { severity: 'error', summary: 'A field named like a secret (api key, token, password, Authorization, Cookie...) holds a literal value.' },
  'credential-reference': { severity: 'warning', summary: 'Node references a credential ID/name from your own n8n instance.' },
  'pinned-data': { severity: 'warning', summary: 'Workflow contains pinned execution data (often real customer data).' },
  'static-data': { severity: 'warning', summary: 'Workflow contains saved static data (state from your own runs).' },
  'instance-id': { severity: 'warning', summary: 'meta.instanceId identifies your n8n instance.' },
  'internal-host': { severity: 'warning', summary: 'URL points to localhost, a private IP range or an internal hostname.' },
  'n8n-instance-url': { severity: 'warning', summary: 'URL points to a specific n8n instance (webhook/form URL or *.app.n8n.cloud).' },
  'email-address': { severity: 'warning', summary: 'A real-looking email address (not example.com / .test / .invalid).' },
  'too-deep': { severity: 'error', summary: 'Nesting is deeper than the scanner follows (200 levels); that part was not checked.' },
  'no-sticky-note': { severity: 'warning', template: true, summary: 'No sticky note. n8n template reviewers expect sticky notes that explain the workflow.' },
  'missing-workflow-name': { severity: 'warning', template: true, summary: 'Workflow has no name.' },
  'disabled-node': { severity: 'warning', template: true, summary: 'Disabled node left in the workflow.' },
};

const QUERY_SECRET_NAMES = 'api[_-]?key|apikey|access[_-]?token|auth[_-]?token|token|secret|client[_-]?secret|password|passwd|key|sig|signature';

// Token patterns. Each entry: label, regex (global), optional `redact(match)` and optional
// `secret(match)` (the part that is checked against placeholder words; default: whole match).
// All repetition is bounded so that failing matches cannot backtrack across the whole input.
// The PEM pattern only matches the BEGIN line; sanitize removes the whole block procedurally.
export const PEM_BEGIN_RE = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----/g;
export const TOKEN_PATTERNS = [
  { label: 'PEM private key', re: PEM_BEGIN_RE, pem: true },
  { label: 'Anthropic API key', re: /(?<!(?<!\\)[A-Za-z0-9_.-])sk-ant-[A-Za-z0-9_-]{20,512}/g },
  { label: 'OpenAI-style API key', re: /(?<!(?<!\\)[A-Za-z0-9_.-])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,512}/g },
  { label: 'Stripe secret key', re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,256}/g },
  { label: 'Slack token', re: /(?<!(?<!\\)[A-Za-z0-9_.-])xox[abposr]-[A-Za-z0-9-]{10,256}/g },
  { label: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{1,256}/g },
  { label: 'Discord webhook URL', re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{1,30}\/[A-Za-z0-9_-]{1,256}/g },
  // No \b: in https://api.telegram.org/bot<TOKEN>/ the token follows the letters "bot".
  { label: 'Telegram bot token', re: /(?<![0-9])\d{8,10}:AA[A-Za-z0-9_-]{30,128}/g },
  { label: 'GitHub token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,256}|github_pat_[A-Za-z0-9_]{22,256})/g },
  { label: 'AWS access key ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { label: 'Google API key', re: /(?<!(?<!\\)[A-Za-z0-9_.-])AIza[0-9A-Za-z_-]{30,128}/g },
  { label: 'SendGrid API key', re: /(?<!(?<!\\)[A-Za-z0-9_.-])SG\.[A-Za-z0-9_-]{16,128}\.[A-Za-z0-9_-]{16,128}/g },
  { label: 'Hugging Face token', re: /(?<!(?<!\\)[A-Za-z0-9_.-])hf_[A-Za-z0-9]{30,128}/g },
  { label: 'Notion integration token', re: /\b(?:secret_[A-Za-z0-9]{40,128}|ntn_[A-Za-z0-9]{40,128})/g },
  { label: 'Airtable personal access token', re: /\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b/g },
  { label: 'JSON Web Token', re: /(?<!(?<!\\)[A-Za-z0-9_.-])eyJ[A-Za-z0-9_-]{10,4096}\.eyJ[A-Za-z0-9_-]{10,8192}\.[A-Za-z0-9_-]{10,4096}/g },
  { label: 'Bearer token', re: /\bBearer\s{1,10}[A-Za-z0-9._~+/-]{16,4096}={0,3}/g, redact: () => 'Bearer REPLACE_ME' },
  {
    label: 'Credentials embedded in URL',
    re: /\b[a-z][a-z0-9+.-]{0,20}:\/\/[^/\s:@'"`?#{}]{1,64}:[^/\s@'"`?#{}]{1,128}@/gi,
    redact: (m) => m.replace(/:\/\/.*@$/, '://REPLACE_ME@'),
    secret: (m) => m.slice(m.lastIndexOf(':') + 1, -1),
    placeholder: (s) => isPlainPlaceholder(s),
  },
  {
    label: 'Secret in URL query string',
    re: new RegExp(`[?&;](?:${QUERY_SECRET_NAMES})=[^&#\\s'"\`{}<>]{6,256}`, 'gi'),
    redact: (m) => m.replace(/=.*$/, '=REPLACE_ME'),
    secret: (m) => m.slice(m.indexOf('=') + 1),
    placeholder: (s) => isPlainPlaceholder(s),
  },
];

// For passwords and query values, which are free text: only obvious placeholders count
// ("MyExamplePass1" is a real password; "YOUR_API_KEY_HERE" is not).
function isPlainPlaceholder(s) {
  return isPlaceholder(s) || /^(?:your|%3C|<|\[)|x{4,}|replace[-_]?me|change[-_]?me|^(?:pass(?:word)?|pwd|secret|token|\*+)$/i.test(s);
}

// Matches that are documentation examples or obvious placeholders, not real keys.
// Only the secret part of a match is checked (see TOKEN_PATTERNS[].secret).
export function isPlaceholderToken(secretPart) {
  return /example|your[-_]|replace[-_]?me|placeholder|dummy|redacted|x{6,}/i.test(secretPart);
}

// Normalised (lowercase, alphanumerics only) field names that indicate a secret:
// a name ending with one of SUFFIXES, or containing one of STRONG anywhere — unless the
// name ends like a description of the secret (passwordField, apiKeyName, privateKeyPath...).
const SECRET_NAME_SUFFIXES = ['apikey', 'secret', 'token', 'password', 'passwd', 'passphrase', 'authorization', 'cookie'];
const SECRET_NAME_STRONG = ['apikey', 'apisecret', 'secretkey', 'privatekey', 'accesskey', 'clientsecret', 'password', 'passwd', 'passphrase', 'authorization'];
const DESCRIPTOR_SUFFIXES = ['label', 'name', 'path', 'field', 'type', 'url', 'uri', 'id', 'age', 'length', 'policy', 'less', 'hint', 'placeholder', 'required', 'enabled', 'mode', 'format', 'expiry', 'expires'];

export function isSecretName(name) {
  if (typeof name !== 'string') return false;
  const n = name.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!n) return false;
  if (SECRET_NAME_SUFFIXES.some((s) => n.endsWith(s))) return true;
  if (DESCRIPTOR_SUFFIXES.some((s) => n.endsWith(s))) return false;
  return SECRET_NAME_STRONG.some((s) => n.includes(s));
}

export function isExpression(value) {
  return typeof value === 'string' && value.startsWith('=');
}

// Whole-value placeholder patterns (anchored: "Todo123!secret" is NOT a placeholder).
const PLACEHOLDER_RES = [
  /^\{\{[\s\S]*\}\}$/,
  // <paste token here>, [your key] — only when the inside is plain words, not "<s3cretPw!>".
  /^<[A-Za-z][A-Za-z _-]*>$/,
  /^\[[A-Za-z][A-Za-z _-]*\]$/,
  // YOUR_API_KEY, enter-your-token — every part after the first word must be letters only.
  /^(?:your|enter|insert|paste|put)(?:[\s_-][A-Za-z]+)+$/i,
  /^(?:replace[\s_-]?me|change[\s_-]?me|placeholder|redacted|todo|tbd|dummy|example|none|null|undefined)$/i,
  /^placeholder[\s_-]/i,
  /^(?:x{3,}|\*{3,}|\.{3,}|-+)$/i,
  /^(?:credentials?|cred)[-_\s]?id$/i,
];

export function isPlaceholder(value) {
  const v = String(value).trim();
  if (!v) return true;
  return PLACEHOLDER_RES.some((re) => re.test(v));
}

// --- hosts -------------------------------------------------------------------

const URL_RE = /\b[a-z][a-z0-9+.-]{0,20}:\/\/([^/\s?#'"`<>\\]{1,255})/gi;

export function urlHosts(text) {
  if (!text.includes('://')) return [];
  const out = [];
  for (const m of text.matchAll(URL_RE)) {
    let host = m[1];
    host = host.slice(host.lastIndexOf('@') + 1);
    let numericPort = false;
    if (host.startsWith('[')) host = host.slice(1, host.indexOf(']') > 0 ? host.indexOf(']') : undefined);
    else {
      const [h, port] = host.split(':');
      numericPort = /^\d{1,5}$/.test(port ?? '');
      host = h;
    }
    host = host.replace(/[.,;)]+$/, '').toLowerCase();
    if (host && !host.includes('{')) {
      out.push({ host, numericPort, url: m[0], rest: text.slice(m.index + m[0].length, m.index + m[0].length + 300) });
    }
  }
  return out;
}

export function isExampleDomain(host) {
  return (
    /(?:^|\.)example\.(?:com|org|net)$/.test(host) ||
    /\.(?:test|example|invalid|localhost)$/.test(host) ||
    /^(?:example|test|invalid)$/.test(host)
  );
}

/**
 * Parse an IPv4 host the way URL parsers and inet_aton do: 1–4 parts, each decimal,
 * 0x-hex or 0-octal ("127.1", "2130706433", "0x7f.0.0.1"). Returns a 32-bit number or null.
 */
export function parseIPv4(host) {
  const parts = host.split('.');
  if (parts.length < 1 || parts.length > 4 || parts.some((p) => p === '')) return null;
  const nums = [];
  for (const p of parts) {
    let n;
    if (/^0x[0-9a-f]{1,8}$/i.test(p)) n = parseInt(p.slice(2), 16);
    else if (/^0[0-7]{1,11}$/.test(p)) n = parseInt(p, 8);
    else if (/^(?:0|[1-9]\d{0,9})$/.test(p)) n = Number(p);
    else return null;
    nums.push(n);
  }
  const last = nums.pop();
  if (nums.some((n) => n > 255) || last >= 256 ** (4 - nums.length)) return null;
  return nums.reduce((acc, n, i) => acc + n * 256 ** (3 - i), 0) + last;
}

const GENERIC_HOST_WORDS = new Set(['host', 'hostname', 'domain', 'server', 'your-domain', 'yourdomain', 'my-host', 'myhost', 'site', 'url']);

export function isInternalHost(host, numericPort = false) {
  if (isExampleDomain(host)) return false;
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host === '::1' || host === '0.0.0.0') return true;
  if (/\.(?:local|internal|lan|intranet|corp|home\.arpa)$/.test(host)) return true;
  if (host.includes(':')) {
    // IPv6: loopback, unique local fc00::/7, link-local fe80::/10, IPv4-mapped private addresses.
    if (/^(?:0{0,4}:){2,7}0{0,3}1$/.test(host) || host === '::1') return true;
    if (/^f[cd][0-9a-f]{0,2}:/.test(host) || /^fe[89ab][0-9a-f]?:/.test(host)) return true;
    const mapped = host.match(/^::ffff:([\d.]+)$/);
    if (mapped) return isInternalHost(mapped[1]);
    // WHATWG URL normalises [::ffff:127.0.0.1] to [::ffff:7f00:1].
    const hex = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hex) {
      const n = parseInt(hex[1], 16) * 65536 + parseInt(hex[2], 16);
      return isInternalHost([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'));
    }
    return false;
  }
  const ip = parseIPv4(host);
  if (ip !== null) {
    const a = Math.floor(ip / 2 ** 24);
    const b = Math.floor(ip / 2 ** 16) % 256;
    return (
      a === 0 || a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)
    );
  }
  // Single-label names with a port (docker-compose services like "postgres:5432") never resolve
  // publicly. Without a port they are usually prose ("https://host/..."), so they are not reported.
  return numericPort && /^[a-z0-9-]+$/.test(host) && !/^\d+$/.test(host) && !GENERIC_HOST_WORDS.has(host);
}

export function isN8nInstanceUrl(host, rest) {
  if (isExampleDomain(host)) return false;
  if (host.endsWith('.app.n8n.cloud')) return true;
  if (/^\/(?:webhook-test|webhook-waiting|form-test|form-waiting)\/[^\s'"`]/.test(rest)) return true;
  return host.includes('n8n') && /^\/(?:webhook|form)\/[^\s'"`]/.test(rest);
}

// --- emails ------------------------------------------------------------------

const EMAIL_RE = /[A-Za-z0-9._%+-]{1,64}@((?:[A-Za-z0-9-]{1,63}\.){1,10}[A-Za-z]{2,24})\b/g;
const FILE_EXT_TLDS = new Set(['png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'avif', 'ico', 'js', 'css', 'json', 'pdf']);

export function realEmails(text) {
  if (!text.includes('@')) return [];
  const out = [];
  for (const m of text.matchAll(EMAIL_RE)) {
    const domain = m[1].toLowerCase();
    const tld = domain.slice(domain.lastIndexOf('.') + 1);
    if (!isExampleDomain(domain) && !FILE_EXT_TLDS.has(tld)) out.push(m[0]);
  }
  return out;
}
