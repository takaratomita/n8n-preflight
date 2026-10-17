import { readFileSync, writeFileSync, statSync, readdirSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';

import { scanWorkflow, extractWorkflows } from './scan.js';
import { sanitizeWorkflow } from './sanitize.js';
import { RULES } from './rules.js';

export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

export const USAGE = `Usage: n8n-preflight [options] <file-or-directory ...>

Scan exported n8n workflow JSON for things you should not share:
API keys and tokens, secret fields with literal values, credential IDs,
pinned data, your instance ID, internal URLs and real email addresses.

Options:
  --json              Print findings as JSON
  --strict            Exit with code 1 on warnings too (default: errors only)
  --template          Also run n8n template checks (sticky notes, name, disabled nodes)
  --ignore <rule>     Skip a rule (repeatable, or comma separated)
  --sanitize <out>    Write a cleaned copy of a single input file to <out>
  -h, --help          Show this help
  -v, --version       Show version

Exit codes: 0 = nothing at the failing level, 1 = findings (even if some inputs
could not be read), 2 = usage or read error, or no workflow JSON found.

Rules:
${Object.entries(RULES)
  .map(([id, r]) => `  ${id.padEnd(22)} ${r.severity.padEnd(8)} ${r.template ? '(--template) ' : ''}${r.summary}`)
  .join('\n')}`;

const SKIP_DIRS = new Set(['node_modules', '.git']);

function collectJsonFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) out.push(...collectJsonFiles(p));
    } else if (entry.name.toLowerCase().endsWith('.json')) {
      // Regular files, and symlinks that point at files (symlinked directories are not followed).
      let isFile = entry.isFile();
      if (!isFile && entry.isSymbolicLink()) {
        try {
          isFile = statSync(p).isFile();
        } catch {
          isFile = false;
        }
      }
      if (isFile) out.push(p);
    }
  }
  return out;
}

function parseArgs(argv) {
  const opts = { json: false, strict: false, template: false, ignore: [], sanitize: null, inputs: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') {
      opts.inputs.push(...argv.slice(i + 1));
      break;
    }
    if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '-v' || a === '--version') opts.version = true;
    else if (a === '--json') opts.json = true;
    else if (a === '--strict') opts.strict = true;
    else if (a === '--template') opts.template = true;
    else if (a === '--ignore' || a === '--sanitize') {
      const v = argv[++i];
      if (v === undefined) return { error: `${a} needs a value` };
      if (a === '--ignore') opts.ignore.push(...v.split(',').map((s) => s.trim()).filter(Boolean));
      else opts.sanitize = v;
    } else if (a.startsWith('-') && a !== '-') return { error: `Unknown option: ${a}` };
    else opts.inputs.push(a);
  }
  const unknown = opts.ignore.filter((r) => !RULES[r]);
  if (unknown.length) return { error: `Unknown rule for --ignore: ${unknown.join(', ')}` };
  return opts;
}

function loadDoc(file) {
  return JSON.parse(readFileSync(file, 'utf8'));
}

function display(file) {
  const rel = relative(process.cwd(), file);
  return rel && !rel.startsWith('..') ? rel : file;
}

function formatFinding(f) {
  const where = [f.workflow ? `workflow "${f.workflow}"` : null, f.node ? `node "${f.node}"` : null].filter(Boolean).join(', ');
  const ev = f.evidence ? `  [${f.evidence}]` : '';
  return `  ${f.severity.padEnd(8)} ${f.rule.padEnd(21)} ${f.message}\n           at ${where ? `${where} → ` : ''}${f.path}${ev}`;
}

function scanDoc(workflows, opts) {
  const multi = workflows.length > 1;
  const findings = [];
  for (const wf of workflows) {
    for (const f of scanWorkflow(wf, { template: opts.template, ignore: opts.ignore })) {
      findings.push(multi ? { workflow: wf.name ?? '(unnamed)', ...f } : f);
    }
  }
  return findings;
}

function runSanitize(opts, io) {
  if (opts.inputs.length !== 1) {
    io.stderr('--sanitize takes exactly one input file');
    return 2;
  }
  const input = resolve(opts.inputs[0]);
  const out = resolve(opts.sanitize);
  if (isSameFile(input, out)) {
    io.stderr('--sanitize output must be a different file than the input');
    return 2;
  }
  let doc;
  try {
    if (!statSync(input).isFile()) throw new Error('not a file');
    doc = loadDoc(input);
  } catch (e) {
    io.stderr(`${display(input)}: cannot read JSON (${e.message})`);
    return 2;
  }
  const workflows = extractWorkflows(doc);
  if (!workflows) {
    io.stderr(`${display(input)}: does not look like n8n workflow JSON`);
    return 2;
  }
  const cleaned = [];
  const changes = [];
  try {
    for (const wf of workflows) {
      const r = sanitizeWorkflow(wf);
      cleaned.push(r.workflow);
      changes.push(...r.changes);
    }
  } catch (e) {
    io.stderr(`${display(input)}: cannot sanitize (${e && e.message ? e.message : e}); nothing was written`);
    return 2;
  }
  let outDoc = cleaned[0];
  if (Array.isArray(doc)) outDoc = cleaned;
  else if (!Array.isArray(doc.nodes)) outDoc = { ...doc, data: cleaned };
  try {
    writeFileSync(out, JSON.stringify(outDoc, null, 2) + '\n');
  } catch (e) {
    io.stderr(`${display(out)}: cannot write (${e.code ?? e.message})`);
    return 2;
  }

  io.stdout(`Wrote ${display(out)} (${changes.length} change${changes.length === 1 ? '' : 's'})`);
  for (const c of changes) io.stdout(`  ${c.path}: ${c.action}`);
  const remaining = scanDoc(cleaned, opts);
  const errors = remaining.filter((f) => f.severity === 'error').length;
  const warnings = remaining.length - errors;
  if (remaining.length) {
    io.stdout(`\nStill needs a manual look (${errors} error${errors === 1 ? '' : 's'}, ${warnings} warning${warnings === 1 ? '' : 's'}):`);
    for (const f of remaining) io.stdout(formatFinding(f));
  }
  return errors > 0 || (opts.strict && warnings > 0) ? 1 : 0;
}

/**
 * Run the CLI. `io` = { stdout(line), stderr(line) }. Returns the exit code.
 */
export function run(argv, io) {
  const opts = parseArgs(argv);
  if (opts.error) {
    io.stderr(`${opts.error}\n\n${USAGE}`);
    return 2;
  }
  if (opts.help) {
    io.stdout(USAGE);
    return 0;
  }
  if (opts.version) {
    io.stdout(VERSION);
    return 0;
  }
  if (opts.inputs.length === 0) {
    io.stderr(USAGE);
    return 2;
  }
  if (opts.sanitize) return runSanitize(opts, io);

  let usageError = false;
  const targets = [];
  for (const input of opts.inputs) {
    let st;
    try {
      st = statSync(input);
    } catch {
      io.stderr(`${input}: no such file or directory`);
      usageError = true;
      continue;
    }
    if (st.isDirectory()) targets.push(...collectJsonFiles(input).map((file) => ({ file, fromDir: true })));
    else targets.push({ file: input, fromDir: false });
  }

  const results = [];
  let skipped = 0;
  for (const { file, fromDir } of targets) {
    let doc;
    try {
      doc = loadDoc(file);
    } catch (e) {
      io.stderr(`${display(file)}: invalid JSON (${e.message})`);
      usageError = true;
      continue;
    }
    const workflows = extractWorkflows(doc);
    if (!workflows) {
      if (fromDir) {
        skipped += 1;
        continue;
      }
      io.stderr(`${display(file)}: does not look like n8n workflow JSON (expected an object with a "nodes" array)`);
      usageError = true;
      continue;
    }
    results.push({ file: display(file), workflows: workflows.length, findings: scanDoc(workflows, opts) });
  }

  const all = results.flatMap((r) => r.findings);
  const errors = all.filter((f) => f.severity === 'error').length;
  const warnings = all.length - errors;
  const summary = { files: results.length, skipped, errors, warnings };

  if (opts.json) {
    io.stdout(JSON.stringify({ version: VERSION, summary, files: results }, null, 2));
  } else {
    for (const r of results) {
      if (!r.findings.length) continue;
      io.stdout(r.file);
      for (const f of r.findings) io.stdout(formatFinding(f));
      io.stdout('');
    }
    const scanned = `${results.length} file${results.length === 1 ? '' : 's'} scanned${skipped ? `, ${skipped} non-workflow JSON skipped` : ''}`;
    if (all.length === 0) io.stdout(`No problems found (${scanned}).`);
    else io.stdout(`${errors} error${errors === 1 ? '' : 's'}, ${warnings} warning${warnings === 1 ? '' : 's'} (${scanned}).`);
  }

  if (errors > 0 || (opts.strict && warnings > 0)) return 1;
  if (usageError) return 2;
  if (results.length === 0) {
    io.stderr('No n8n workflow JSON found in the given paths.');
    return 2;
  }
  return 0;
}

/** True when both paths name the same existing file (symlinks, case-insensitive file systems). */
function isSameFile(a, b) {
  if (a === b) return true;
  try {
    const sa = statSync(a);
    const sb = statSync(b);
    return sa.dev === sb.dev && sa.ino === sb.ino;
  } catch {
    return false;
  }
}
