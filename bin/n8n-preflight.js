#!/usr/bin/env node
import { run } from '../src/cli.js';

try {
  process.exitCode = run(process.argv.slice(2), {
    stdout: (line) => process.stdout.write(`${line}\n`),
    stderr: (line) => process.stderr.write(`${line}\n`),
  });
} catch (e) {
  process.stderr.write(`n8n-preflight: unexpected error: ${e && e.message ? e.message : e}\n`);
  process.exitCode = 2;
}
