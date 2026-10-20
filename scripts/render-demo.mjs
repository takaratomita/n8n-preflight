#!/usr/bin/env node
// Render docs/demo.svg: a terminal-style picture of the real CLI output for examples/leaky-workflow.json.
// The README embeds this image. test/demo.test.js fails when the committed SVG no longer matches the CLI.
//
// Usage (from the n8n-preflight directory):
//   node scripts/render-demo.mjs
import { spawnSync } from 'node:child_process';
import { mkdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

export const DEMO_COMMAND = '$ npx github:takaratomita/n8n-preflight leaky-workflow.json';

const CHAR_W = 7.9;
const LINE_H = 19;
const PAD = 18;
const FONT = 13;

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function classify(line) {
  if (/^ {2}error /.test(line)) return 'err';
  if (/^ {2}warning /.test(line)) return 'warn';
  if (/^ {11}at /.test(line)) return 'dim';
  if (/^\d+ errors?, /.test(line) || /^0 errors/.test(line)) return 'sum';
  return 'file';
}

export function renderDemoSvg(commandLine, outputText) {
  const rows = [{ text: commandLine, cls: 'cmd' }, { text: '', cls: 'file' }, ...outputText.split('\n').map((text) => ({ text, cls: classify(text) }))];
  const longest = Math.max(...rows.map((r) => [...r.text].length));
  const width = Math.ceil(PAD * 2 + longest * CHAR_W);
  const height = PAD * 2 + rows.length * LINE_H;
  const body = rows
    .map((r, i) => {
      const y = PAD + (i + 1) * LINE_H - 5;
      if (r.cls === 'err' || r.cls === 'warn') {
        const level = r.cls === 'err' ? 'error' : 'warning';
        const rest = r.text.slice(2 + level.length);
        return `<text x="${PAD}" y="${y}" xml:space="preserve">  <tspan class="${r.cls}">${level}</tspan>${esc(rest)}</text>`;
      }
      return `<text x="${PAD}" y="${y}" class="${r.cls}" xml:space="preserve">${esc(r.text)}</text>`;
    })
    .join('\n');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="t">
<title id="t">n8n-preflight scanning an example n8n workflow: 2 errors and 5 warnings</title>
<style>
text{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:${FONT}px;fill:#d4d4d4;white-space:pre}
.cmd{fill:#9cdcfe;font-weight:bold}.file{fill:#ffffff;font-weight:bold}.err{fill:#f48771;font-weight:bold}.warn{fill:#e5c07b;font-weight:bold}.dim{fill:#8b949e}.sum{fill:#ffffff;font-weight:bold}
</style>
<rect width="${width}" height="${height}" rx="8" fill="#1e1e1e"/>
${body}
</svg>
`;
}

export function runDemo(root = ROOT) {
  const r = spawnSync(process.execPath, [join(root, 'bin', 'n8n-preflight.js'), 'leaky-workflow.json'], { cwd: join(root, 'examples'), encoding: 'utf8' });
  if (r.status !== 1) throw new Error(`expected exit 1 from the leaky example, got ${r.status}: ${r.stderr}`);
  return renderDemoSvg(DEMO_COMMAND, r.stdout.replace(/\n$/, ''));
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const out = join(ROOT, 'docs', 'demo.svg');
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, runDemo());
  console.log(`wrote ${out}`);
}
