import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { renderDemoSvg, DEMO_COMMAND } from '../scripts/render-demo.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = join(ROOT, 'bin', 'n8n-preflight.js');
const EXAMPLES = join(ROOT, 'examples');
const README = readFileSync(join(ROOT, 'README.md'), 'utf8');
// The workflows repo vendors this directory with a stub README; the README checks do not apply there.
const hasRealReadme = !README.includes('(vendored)');

function realOutput() {
  const r = spawnSync(process.execPath, [BIN, 'leaky-workflow.json'], { cwd: EXAMPLES, encoding: 'utf8' });
  assert.equal(r.status, 1, 'the leaky example must produce findings (exit 1)');
  return r.stdout.replace(/\n$/, '');
}

test('renderDemoSvg escapes markup, colours levels and shows the command', () => {
  const svg = renderDemoSvg('$ n8n-preflight a<b>&c.json', 'a<b>&c.json\n  error    rule  "x" <y>\n  warning  rule  z\n           at node "N" → p');
  assert.match(svg, /^<svg /);
  assert.ok(svg.includes('a&lt;b&gt;&amp;c.json'));
  assert.ok(!svg.includes('<y>'));
  assert.match(svg, /class="err"[^>]*>error/);
  assert.match(svg, /class="warn"[^>]*>warning/);
  assert.match(svg, /class="dim"[^>]*>\s*at node/);
  assert.match(svg, /<title[ >]/);
});

test('docs/demo.svg is exactly what the real CLI prints for the example (no drift)', () => {
  const file = join(ROOT, 'docs', 'demo.svg');
  assert.ok(existsSync(file), 'docs/demo.svg is missing; run: node scripts/render-demo.mjs');
  assert.equal(readFileSync(file, 'utf8'), renderDemoSvg(DEMO_COMMAND, realOutput()), 'docs/demo.svg is stale; regenerate with: node scripts/render-demo.mjs');
});

test('README first screen: runnable command near the top, demo image, output block equals real output', { skip: !hasRealReadme }, () => {
  const lines = README.split('\n');
  const firstRun = lines.findIndex((l) => /^\s*npx github:/.test(l)) + 1;
  assert.ok(firstRun > 0 && firstRun <= 15, `first runnable npx line is at README line ${firstRun}, expected within 15`);
  const firstCurl = lines.findIndex((l) => /curl .*leaky-workflow\.json/.test(l)) + 1;
  assert.ok(firstCurl > 0 && firstCurl < firstRun, 'the example file must be fetched before it is scanned');
  const image = lines.findIndex((l) => l.includes('](docs/demo.svg)')) + 1;
  assert.ok(image > 0 && image <= 20, `demo image is at README line ${image}, expected within 20`);
  assert.ok(README.includes(realOutput()), 'the sample output in README differs from the real CLI output');
});
