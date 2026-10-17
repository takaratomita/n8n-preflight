import { TOKEN_PATTERNS, PEM_BEGIN_RE, isPlaceholderToken } from './rules.js';
import { joinPath, isLiteralSecret, parseJsonString, childSecretKey, pairSecretName, MAX_DEPTH } from './scan.js';

export const REPLACEMENT = 'REPLACE_ME';

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Remove whole PEM private key blocks (BEGIN ... END, or to the end of the text). Linear. */
function redactPem(text) {
  let out = '';
  let pos = 0;
  PEM_BEGIN_RE.lastIndex = 0;
  for (let m = PEM_BEGIN_RE.exec(text); m; m = PEM_BEGIN_RE.exec(text)) {
    if (m.index < pos) continue;
    const endMarker = text.indexOf('PRIVATE KEY-----', m.index + m[0].length);
    const end = endMarker < 0 ? text.length : endMarker + 'PRIVATE KEY-----'.length;
    out += text.slice(pos, m.index) + REPLACEMENT;
    pos = end;
    PEM_BEGIN_RE.lastIndex = end;
  }
  return out + text.slice(pos);
}

function redactTokens(text) {
  let out = text.includes('PRIVATE KEY-----') ? redactPem(text) : text;
  for (const p of TOKEN_PATTERNS) {
    if (p.pem) continue;
    p.re.lastIndex = 0;
    out = out.replace(p.re, (m) => (isPlaceholderToken(p.secret ? p.secret(m) : m) ? m : p.redact ? p.redact(m) : REPLACEMENT));
  }
  return out;
}

/**
 * Return a cleaned deep copy of a workflow plus a list of what changed.
 * - removes pinData, staticData, sharing info, meta.instanceId and node credential references
 * - replaces literal values of secret-named fields with REPLACE_ME (also inside JSON strings,
 *   which are edited in place so the rest of their text stays byte-for-byte the same)
 * - replaces token-looking substrings with REPLACE_ME (surrounding text is kept)
 * Emails and URLs are only reported by the scanner; they are not rewritten.
 * The `changes` list contains paths and actions only, never values.
 */
export function sanitizeWorkflow(input) {
  const wf = structuredClone(input);
  const changes = [];

  for (const key of ['pinData', 'staticData']) {
    const v = wf[key];
    if (key in wf && v !== null && v !== undefined && !(typeof v === 'object' && Object.keys(v).length === 0)) {
      delete wf[key];
      changes.push({ path: key, action: 'removed' });
    }
  }
  if ('shared' in wf) {
    delete wf.shared;
    changes.push({ path: 'shared', action: 'removed' });
  }
  if (wf.meta && typeof wf.meta === 'object' && 'instanceId' in wf.meta) {
    delete wf.meta.instanceId;
    changes.push({ path: 'meta.instanceId', action: 'removed' });
  }
  const stripCredentials = (nodes, base) => {
    (Array.isArray(nodes) ? nodes : []).forEach((node, i) => {
      if (node && typeof node === 'object' && 'credentials' in node) {
        delete node.credentials;
        changes.push({ path: joinPath(joinPath(base, i), 'credentials'), action: 'removed (re-select credentials after import)' });
      }
    });
  };
  stripCredentials(wf.nodes, 'nodes');
  if (wf.activeVersion && typeof wf.activeVersion === 'object') stripCredentials(wf.activeVersion.nodes, 'activeVersion.nodes');

  // Inside a parsed JSON string: collect the literal secret values (with their property key)
  // instead of rewriting the object, so the original text can be edited in place.
  const collectJsonSecrets = (value, secretKey, key, out, depth) => {
    if (depth > MAX_DEPTH) return;
    if ((typeof value === 'string' || typeof value === 'number') && secretKey && isLiteralSecret(value)) {
      out.push({ key, value });
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((v) => collectJsonSecrets(v, secretKey, key, out, depth + 1));
    } else if (value && typeof value === 'object') {
      const pairSecret = pairSecretName(value);
      for (const [k, v] of Object.entries(value)) {
        collectJsonSecrets(v, k === 'value' && pairSecret ? pairSecret : childSecretKey(secretKey, k), k, out, depth + 1);
      }
    }
  };

  const cleanJsonString = (text, parsed, path, secretKey) => {
    const secrets = [];
    collectJsonSecrets(parsed, secretKey, null, secrets, 0);
    let out = text;
    let reserialized = false;
    const done = new Set();
    for (const { key, value } of secrets) {
      const id = JSON.stringify([key, typeof value, value]);
      if (done.has(id)) continue; // the 'g' replace below already handled every occurrence
      done.add(id);
      if (typeof value === 'number' && key === null) {
        reserialized = true; // a bare number cannot be located safely in the text
        continue;
      }
      // Exact literal only: a number matches its own digits (not any number), a string its JSON form.
      const literal = typeof value === 'number' ? `${escapeRe(String(value))}(?![\\d.eE])` : escapeRe(JSON.stringify(value));
      const re = key === null ? new RegExp(literal, 'g') : new RegExp(`(${escapeRe(JSON.stringify(key))}\\s*:\\s*)${literal}`, 'g');
      const next = out.replace(re, (...m) => (key === null ? `"${REPLACEMENT}"` : `${m[1]}"${REPLACEMENT}"`));
      if (next === out) reserialized = true; // written with different escaping / precision; handled below
      out = next;
    }
    out = redactTokens(out);
    if (reserialized) {
      if (out.trim().startsWith('=')) {
        // Expression-mode JSON cannot be re-serialized without losing the {{ }} expressions.
        changes.push({ path, action: 'NOT cleaned: secret inside an expression JSON string could not be located; edit it by hand' });
      } else {
        // Rare fallback: rewrite through JSON (formatting and number precision may change).
        const obj = parseJsonString(out);
        if (obj !== undefined) {
          cleanParsed(obj, secretKey, 0);
          out = JSON.stringify(obj, null, text.includes('\n') ? 2 : 0);
          changes.push({ path, action: 'JSON string re-serialized (formatting may differ)' });
        }
      }
    }
    if (out !== text) changes.push({ path, action: 'secret value(s) replaced inside JSON string' });
    return out;
  };

  const cleanParsed = (value, secretKey, depth) => {
    if (depth > MAX_DEPTH || !value || typeof value !== 'object') return;
    const pairSecret = Array.isArray(value) ? null : pairSecretName(value);
    for (const k of Object.keys(value)) {
      const sk = Array.isArray(value) ? secretKey : k === 'value' && pairSecret ? pairSecret : childSecretKey(secretKey, k);
      const v = value[k];
      if ((typeof v === 'string' || typeof v === 'number') && sk && isLiteralSecret(v)) value[k] = REPLACEMENT;
      else if (typeof v === 'string') value[k] = redactTokens(v);
      else cleanParsed(v, sk, depth + 1);
    }
  };

  // Returns the cleaned value (same reference when unchanged).
  const clean = (value, path, secretKey, depth) => {
    if (depth > MAX_DEPTH) return value; // left as is; the scanner reports "too-deep"
    if (typeof value === 'number') {
      if (secretKey && isLiteralSecret(value)) {
        changes.push({ path, action: 'secret value replaced' });
        return REPLACEMENT;
      }
      return value;
    }
    if (typeof value === 'string') {
      const parsed = parseJsonString(value);
      if (parsed !== undefined) return cleanJsonString(value, parsed, path, secretKey);
      if (secretKey && isLiteralSecret(value)) {
        changes.push({ path, action: 'secret value replaced' });
        return REPLACEMENT;
      }
      const redacted = redactTokens(value);
      if (redacted !== value) changes.push({ path, action: 'token replaced' });
      return redacted;
    }
    if (Array.isArray(value)) {
      value.forEach((v, i) => {
        value[i] = clean(v, joinPath(path, i), secretKey, depth + 1);
      });
      return value;
    }
    if (!value || typeof value !== 'object') return value;
    const pairSecret = pairSecretName(value);
    for (const k of Object.keys(value)) {
      const sk = k === 'value' && pairSecret ? pairSecret : childSecretKey(secretKey, k);
      value[k] = clean(value[k], joinPath(path, k), sk, depth + 1);
    }
    return value;
  };

  for (const k of Object.keys(wf)) {
    wf[k] = clean(wf[k], k, childSecretKey(null, k), 0);
  }

  return { workflow: wf, changes };
}
