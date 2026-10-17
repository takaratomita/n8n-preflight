import {
  RULES,
  TOKEN_PATTERNS,
  isPlaceholderToken,
  isSecretName,
  isExpression,
  isPlaceholder,
  urlHosts,
  isInternalHost,
  isN8nInstanceUrl,
  realEmails,
} from './rules.js';

const IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const MAX_JSON_STRING = 1_000_000;
// Keys under a secret-named object that describe it rather than hold the secret.
const STRUCTURAL_KEYS = new Set(['type', 'name', 'mode', 'id', '__rl', 'cachedResultName', 'cachedResultUrl', 'description', 'label', 'enabled']);

export function joinPath(base, key) {
  if (typeof key === 'number') return `${base}[${key}]`;
  if (IDENT_RE.test(key)) return base ? `${base}.${key}` : key;
  return `${base}[${JSON.stringify(key)}]`;
}

export function maskValue(value) {
  const s = String(value);
  if (s.length < 8) return '***';
  return `${s.slice(0, 4)}… (${s.length} chars)`;
}

export function isWorkflow(obj) {
  return Boolean(obj) && typeof obj === 'object' && !Array.isArray(obj) && Array.isArray(obj.nodes);
}

/**
 * Accepts a parsed JSON document and returns the list of workflows in it,
 * or null if it does not look like n8n workflow JSON.
 * Supported shapes: a workflow object, an array of workflows, or an n8n API
 * response of the form { data: [workflow, ...] }.
 */
export function extractWorkflows(doc) {
  if (Array.isArray(doc)) {
    return doc.length > 0 && doc.every(isWorkflow) ? doc : null;
  }
  if (isWorkflow(doc)) return [doc];
  if (doc && typeof doc === 'object' && Array.isArray(doc.data)) return extractWorkflows(doc.data);
  return null;
}

export const MAX_DEPTH = 200;
// Stands in for an n8n {{ expression }} while parsing expression-mode JSON (see parseJsonString).
export const EXPR_SENTINEL = '__N8N_EXPRESSION__';

/** First real (non-placeholder) token found in a string, or null. */
export function findToken(text) {
  for (const p of TOKEN_PATTERNS) {
    p.re.lastIndex = 0;
    for (const m of text.matchAll(p.re)) {
      const secretPart = p.secret ? p.secret(m[0]) : m[0];
      if (secretPart.includes(EXPR_SENTINEL)) continue;
      const placeholder = p.placeholder ? p.placeholder(secretPart) : isPlaceholderToken(secretPart);
      if (!placeholder) return { label: p.label, match: m[0] };
    }
  }
  return null;
}

/** True when a literal value in a secret-named field should be reported. */
export function isLiteralSecret(value) {
  if (typeof value === 'number') return Number.isFinite(value) && String(Math.abs(value)).length >= 6;
  return typeof value === 'string' && !isExpression(value) && !value.includes(EXPR_SENTINEL) && !isPlaceholder(value);
}

/**
 * Replace each {{ ... }} with a JSON-safe sentinel: inside a JSON string it becomes
 * EXPR_SENTINEL, outside it becomes "EXPR_SENTINEL" (a string value). Linear scan.
 */
function neutralizeExpressions(text) {
  let out = '';
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '{' && text[i + 1] === '{') {
      const end = text.indexOf('}}', i + 2);
      if (end < 0) return null;
      out += inString ? EXPR_SENTINEL : `"${EXPR_SENTINEL}"`;
      i = end + 1;
      continue;
    }
    if (inString && c === '\\') {
      out += c + (text[i + 1] ?? '');
      i += 1;
      continue;
    }
    if (c === '"') inString = !inString;
    out += c;
  }
  return out;
}

/**
 * Parse a string that holds a JSON object/array (e.g. jsonBody, jsonHeaders), else undefined.
 * Expression-mode values ("={ \"a\": \"{{ $json.x }}\" }") are parsed too, with every
 * {{ }} replaced by EXPR_SENTINEL so that it is never mistaken for a literal secret.
 */
export function parseJsonString(value) {
  let t = value.trim();
  if (t.startsWith('=')) {
    t = t.slice(1).trim();
    if (t.includes('{{')) t = neutralizeExpressions(t);
    if (t === null) return undefined;
  }
  if (t.length < 2 || t.length > MAX_JSON_STRING || !((t[0] === '{' && t.at(-1) === '}') || (t[0] === '[' && t.at(-1) === ']'))) return undefined;
  try {
    const parsed = JSON.parse(t);
    return parsed && typeof parsed === 'object' ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/** Secret-name context for a child property. */
export function childSecretKey(parentSecretKey, key) {
  if (isSecretName(key)) return key;
  return parentSecretKey && !STRUCTURAL_KEYS.has(key) ? parentSecretKey : null;
}

/** Secret name carried by an n8n {name, value} pair, if any. */
export function pairSecretName(obj) {
  return typeof obj.name === 'string' && isSecretName(obj.name) && 'value' in obj ? obj.name : null;
}

function finding(rule, message, path, extra = {}) {
  return { rule, severity: RULES[rule].severity, message, path, ...extra };
}

/**
 * Scan one workflow object. Returns a list of findings:
 *   { rule, severity, message, path, node?, evidence? }
 * Secret values are never included in full; `evidence` is masked.
 */
export function scanWorkflow(wf, options = {}) {
  const ignore = new Set(options.ignore ?? []);
  const findings = [];
  const add = (f) => {
    if (!ignore.has(f.rule)) findings.push(f);
  };

  const visitString = (value, path, ctx) => {
    const parsed = parseJsonString(value);
    if (parsed !== undefined) {
      walk(parsed, `${path}(json)`, ctx);
      return;
    }
    const token = findToken(value);
    if (token) {
      const bearer = /^Bearer\s+/.exec(token.match);
      const evidence = bearer ? `Bearer ${maskValue(token.match.slice(bearer[0].length))}` : maskValue(token.match);
      add(finding('hardcoded-secret', `Possible ${token.label}`, path, { ...ctx.where, evidence }));
    } else if (ctx.secretKey && isLiteralSecret(value)) {
      add(finding('secret-field', `"${ctx.secretKey}" has a literal value; use an n8n credential or an expression instead`, path, {
        ...ctx.where,
        evidence: `(${value.length} chars)`,
      }));
    }
    if (ctx.inPinData) return;
    const seen = new Set();
    for (const { host, numericPort, url, rest } of urlHosts(value)) {
      if (seen.has(url)) continue;
      seen.add(url);
      if (isInternalHost(host, numericPort)) {
        add(finding('internal-host', `URL points to an internal host (${host})`, path, ctx.where));
      } else if (isN8nInstanceUrl(host, rest)) {
        add(finding('n8n-instance-url', `URL points to a specific n8n instance (${host})`, path, ctx.where));
      }
    }
    const emails = realEmails(value);
    if (emails.length) {
      add(finding('email-address', `Real-looking email address (${maskValue(emails[0])})`, path, ctx.where));
    }
  };

  let tooDeep = false;
  const walk = (value, path, ctx) => {
    const depth = (ctx.depth ?? 0) + 1;
    if (depth > MAX_DEPTH) {
      if (!tooDeep) add(finding('too-deep', `Nesting deeper than ${MAX_DEPTH} levels was not checked`, path, ctx.where));
      tooDeep = true;
      return;
    }
    ctx = { ...ctx, depth };
    if (typeof value === 'string') {
      visitString(value, path, ctx);
      return;
    }
    if (typeof value === 'number') {
      if (ctx.secretKey && isLiteralSecret(value)) {
        add(finding('secret-field', `"${ctx.secretKey}" has a literal value; use an n8n credential or an expression instead`, path, {
          ...ctx.where,
          evidence: `(${String(value).length} digits)`,
        }));
      }
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((v, i) => walk(v, joinPath(path, i), ctx));
      return;
    }
    if (!value || typeof value !== 'object') return;
    // n8n "name/value" pairs: HTTP headers, query/body parameters, Set node assignments.
    const pairSecret = pairSecretName(value);
    for (const [k, v] of Object.entries(value)) {
      const secretKey = k === 'value' && pairSecret ? pairSecret : childSecretKey(ctx.secretKey, k);
      walk(v, joinPath(path, k), { ...ctx, secretKey });
    }
  };

  const checkCredentials = (nodes, base) => {
    nodes.forEach((node, i) => {
      if (!node || typeof node !== 'object' || !node.credentials || typeof node.credentials !== 'object') return;
      const where = typeof node.name === 'string' ? { node: node.name } : {};
      for (const [type, ref] of Object.entries(node.credentials)) {
        const id = ref && typeof ref === 'object' ? ref.id : ref;
        const realId = (typeof id === 'string' || typeof id === 'number') && !isPlaceholder(String(id));
        if (realId) {
          add(finding('credential-reference', `Credential "${type}" references an ID from your instance`, joinPath(joinPath(joinPath(base, i), 'credentials'), type), where));
        }
      }
    });
  };

  const nodes = Array.isArray(wf.nodes) ? wf.nodes : [];
  checkCredentials(nodes, 'nodes');
  if (wf.activeVersion && Array.isArray(wf.activeVersion.nodes)) checkCredentials(wf.activeVersion.nodes, 'activeVersion.nodes');

  nodes.forEach((node, i) => {
    if (!node || typeof node !== 'object') return;
    const nodePath = joinPath('nodes', i);
    const where = typeof node.name === 'string' ? { node: node.name } : {};
    for (const [k, v] of Object.entries(node)) {
      if (k === 'credentials') continue;
      walk(v, joinPath(nodePath, k), { where, secretKey: isSecretName(k) ? k : null });
    }
    if (options.template && node.disabled === true) {
      add(finding('disabled-node', 'Disabled node left in the workflow', nodePath, where));
    }
  });

  for (const [k, v] of Object.entries(wf)) {
    if (k === 'nodes') continue;
    if (k === 'pinData') {
      if (v && typeof v === 'object' && Object.keys(v).length > 0) {
        add(finding('pinned-data', 'Pinned data is exported with the workflow; remove it before sharing', 'pinData'));
      }
      walk(v, 'pinData', { where: {}, secretKey: null, inPinData: true });
      continue;
    }
    if (k === 'staticData') {
      const has = v && (typeof v === 'string' ? v.trim() !== '' && v.trim() !== '{}' : typeof v === 'object' && Object.keys(v).length > 0);
      if (has) add(finding('static-data', 'Saved static data (state from your runs) is exported; remove it before sharing', 'staticData'));
      walk(v, 'staticData', { where: {}, secretKey: null, inPinData: true });
      continue;
    }
    if (k === 'activeVersion' && v && typeof v === 'object') {
      const { nodes: avNodes, ...rest } = v;
      (Array.isArray(avNodes) ? avNodes : []).forEach((n, i) => {
        if (!n || typeof n !== 'object') return;
        const where = typeof n.name === 'string' ? { node: n.name } : {};
        const { credentials, ...body } = n;
        walk(body, joinPath('activeVersion.nodes', i), { where, secretKey: null });
      });
      walk(rest, 'activeVersion', { where: {}, secretKey: null });
      continue;
    }
    if (k === 'meta' && v && typeof v === 'object' && v.instanceId) {
      add(finding('instance-id', 'meta.instanceId identifies your n8n instance', 'meta.instanceId'));
      const { instanceId, ...rest } = v;
      walk(rest, 'meta', { where: {}, secretKey: null });
      continue;
    }
    walk(v, k, { where: {}, secretKey: isSecretName(k) ? k : null });
  }

  if (options.template) {
    if (typeof wf.name !== 'string' || wf.name.trim() === '') {
      add(finding('missing-workflow-name', 'Workflow has no name', 'name'));
    }
    if (!nodes.some((n) => n && n.type === 'n8n-nodes-base.stickyNote')) {
      add(finding('no-sticky-note', 'No sticky note explains the workflow (expected by n8n template reviewers)', 'nodes'));
    }
  }

  // Errors first; otherwise keep document order (Array.prototype.sort is stable).
  return findings.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'error' ? -1 : 1));
}
