import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { run } from '../src/cli.js';
import { FAKE, node, workflow } from './helpers.js';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'n8n-preflight.js');
let dir;

function io() {
  const out = [];
  const err = [];
  return { out, err, stdout: (s) => out.push(s), stderr: (s) => err.push(s) };
}

before(() => {
  dir = mkdtempSync(join(tmpdir(), 'n8n-preflight-'));
  writeFileSync(join(dir, 'clean.json'), JSON.stringify(workflow([node({ parameters: { url: 'https://api.example.com' } })])));
  writeFileSync(
    join(dir, 'leaky.json'),
    JSON.stringify(workflow([node({ name: 'Leaky', parameters: { jsCode: `const k = "${FAKE.github}"` } })])),
  );
  writeFileSync(join(dir, 'warn.json'), JSON.stringify(workflow([node({ credentials: { a: { id: '1', name: 'x' } } })])));
  writeFileSync(join(dir, 'broken.json'), '{ not json');
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'not-a-workflow' }));
  mkdirSync(join(dir, 'nested'));
  writeFileSync(join(dir, 'nested', 'also-clean.json'), JSON.stringify(workflow([node()])));
});

after(() => rmSync(dir, { recursive: true, force: true }));

test('exit 0 for a clean file', () => {
  const s = io();
  assert.equal(run([join(dir, 'clean.json')], s), 0);
  assert.match(s.out.join('\n'), /No problems found/);
});

test('exit 1 and masked output for a leaky file', () => {
  const s = io();
  assert.equal(run([join(dir, 'leaky.json')], s), 1);
  const text = s.out.join('\n');
  assert.match(text, /hardcoded-secret/);
  assert.match(text, /Leaky/);
  assert.ok(!text.includes(FAKE.github));
});

test('warnings exit 0 unless --strict', () => {
  assert.equal(run([join(dir, 'warn.json')], io()), 0);
  assert.equal(run(['--strict', join(dir, 'warn.json')], io()), 1);
});

test('--json prints machine readable findings', () => {
  const s = io();
  assert.equal(run(['--json', join(dir, 'leaky.json')], s), 1);
  const parsed = JSON.parse(s.out.join(''));
  assert.equal(parsed.summary.errors, 1);
  assert.equal(parsed.files[0].findings[0].rule, 'hardcoded-secret');
  assert.ok(!s.out.join('').includes(FAKE.github));
});

test('invalid JSON is a usage error (exit 2)', () => {
  const s = io();
  assert.equal(run([join(dir, 'broken.json')], s), 2);
  assert.match(s.err.join('\n'), /broken\.json/);
});

test('an explicitly passed non-workflow JSON file is exit 2', () => {
  assert.equal(run([join(dir, 'package.json')], io()), 2);
});

test('directories are scanned recursively and non-workflow JSON is skipped', () => {
  const s = io();
  const sub = mkdtempSync(join(tmpdir(), 'n8n-preflight-dir-'));
  writeFileSync(join(sub, 'package.json'), '{"name":"x"}');
  mkdirSync(join(sub, 'deep'));
  writeFileSync(join(sub, 'deep', 'wf.json'), JSON.stringify(workflow([node({ parameters: { jsCode: FAKE.aws } })])));
  assert.equal(run([sub], s), 1);
  assert.match(s.out.join('\n'), /wf\.json/);
  rmSync(sub, { recursive: true, force: true });
});

test('no arguments prints usage and exits 2', () => {
  const s = io();
  assert.equal(run([], s), 2);
  assert.match(s.err.join('\n'), /Usage/);
});

test('--help exits 0', () => {
  const s = io();
  assert.equal(run(['--help'], s), 0);
  assert.match(s.out.join('\n'), /Usage/);
});

test('unknown option exits 2', () => {
  assert.equal(run(['--nope', join(dir, 'clean.json')], io()), 2);
});

test('--sanitize writes a cleaned copy that passes', () => {
  const outFile = join(dir, 'leaky.clean.json');
  const s = io();
  assert.equal(run(['--sanitize', outFile, join(dir, 'leaky.json')], s), 0);
  const cleaned = readFileSync(outFile, 'utf8');
  assert.ok(!cleaned.includes(FAKE.github));
  assert.equal(run([outFile], io()), 0);
});

test('--sanitize refuses to overwrite the input file', () => {
  const p = join(dir, 'leaky.json');
  assert.equal(run(['--sanitize', p, p], io()), 2);
});

test('--sanitize requires exactly one input file', () => {
  assert.equal(run(['--sanitize', join(dir, 'x.json'), join(dir, 'clean.json'), join(dir, 'warn.json')], io()), 2);
});

test('--ignore drops a rule', () => {
  assert.equal(run(['--strict', '--ignore', 'credential-reference', join(dir, 'warn.json')], io()), 0);
});

test('findings win over an unreadable file (exit 1, error still reported)', () => {
  const s = io();
  assert.equal(run([join(dir, 'leaky.json'), join(dir, 'broken.json')], s), 1);
  assert.match(s.err.join('\n'), /broken\.json/);
});

test('a directory without workflow JSON is exit 2', () => {
  const empty = mkdtempSync(join(tmpdir(), 'n8n-preflight-empty-'));
  const s = io();
  assert.equal(run([empty], s), 2);
  assert.match(s.err.join('\n'), /no n8n workflow JSON/i);
  rmSync(empty, { recursive: true, force: true });
});

test('--sanitize into a missing directory is exit 2 without a stack trace', () => {
  const s = io();
  assert.equal(run(['--sanitize', join(dir, 'nope', 'out.json'), join(dir, 'leaky.json')], s), 2);
  assert.match(s.err.join('\n'), /cannot write/);
});

test('--sanitize refuses an output that is the same file under another name', () => {
  const p = join(dir, 'leaky.json');
  const alias = join(dir, 'alias.json');
  symlinkSync(p, alias);
  assert.equal(run(['--sanitize', alias, p], io()), 2);
});

test('symlinked workflow files inside a directory are scanned', () => {
  const d = mkdtempSync(join(tmpdir(), 'n8n-preflight-link-'));
  symlinkSync(join(dir, 'leaky.json'), join(d, 'linked.json'));
  assert.equal(run([d], io()), 1);
  rmSync(d, { recursive: true, force: true });
});

test('--sanitize on absurdly deep input fails cleanly with exit 2', () => {
  const deep = join(dir, 'deep.json');
  writeFileSync(deep, `{"name":"w","nodes":[{"name":"n","type":"t","parameters":${'{"x":'.repeat(20000)}1${'}'.repeat(20000)}}]}`);
  const s = io();
  assert.equal(run(['--sanitize', join(dir, 'deep.clean.json'), deep], s), 2);
  assert.match(s.err.join('\n'), /cannot sanitize/);
});

test('the bin script runs end to end', () => {
  const r = spawnSync(process.execPath, [BIN, join(dir, 'leaky.json')], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /hardcoded-secret/);
  const v = spawnSync(process.execPath, [BIN, '--version'], { encoding: 'utf8' });
  assert.equal(v.status, 0);
  assert.match(v.stdout.trim(), /^\d+\.\d+\.\d+$/);
});
