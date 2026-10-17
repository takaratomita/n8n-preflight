import { test } from 'node:test';
import assert from 'node:assert/strict';

import { scanWorkflow, extractWorkflows, maskValue } from '../src/scan.js';
import { FAKE, node, workflow, rules } from './helpers.js';

test('a clean workflow has no findings', () => {
  const wf = workflow([
    node({
      parameters: {
        url: 'https://api.example.com/items',
        sendHeaders: true,
        headerParameters: { parameters: [{ name: 'Accept', value: 'application/json' }] },
      },
    }),
  ]);
  assert.deepEqual(scanWorkflow(wf), []);
});

test('detects every built-in token pattern anywhere in parameters', () => {
  for (const [kind, value] of Object.entries(FAKE)) {
    const wf = workflow([node({ parameters: { jsCode: `const x = "${value}";` } })]);
    const found = scanWorkflow(wf);
    assert.ok(
      found.some((f) => f.rule === 'hardcoded-secret' && f.severity === 'error'),
      `expected ${kind} to be detected`,
    );
  }
});

test('finding output never contains the full secret value', () => {
  const wf = workflow([node({ parameters: { jsCode: `const k = "${FAKE.openai}";` } })]);
  const [f] = scanWorkflow(wf);
  assert.ok(f, 'expected a finding');
  assert.ok(!JSON.stringify(f).includes(FAKE.openai));
  assert.match(f.evidence, /^sk-p/);
});

test('reports node name and JSON path of the finding', () => {
  const wf = workflow([
    node({ name: 'Call API', parameters: { headerParameters: { parameters: [{ name: 'X-Api-Key', value: 'live-key-998877' }] } } }),
  ]);
  const [f] = scanWorkflow(wf);
  assert.equal(f.rule, 'secret-field');
  assert.equal(f.node, 'Call API');
  assert.equal(f.path, 'nodes[0].parameters.headerParameters.parameters[0].value');
});

test('secret-looking field names with literal values are errors', () => {
  const wf = workflow([node({ parameters: { options: { apiKey: 'abc123secretvalue' }, password: 'hunter22' } })]);
  const found = scanWorkflow(wf);
  assert.deepEqual(rules(found).sort(), ['secret-field', 'secret-field']);
});

test('Set node assignments named like secrets are detected', () => {
  const wf = workflow([
    node({
      type: 'n8n-nodes-base.set',
      parameters: { assignments: { assignments: [{ id: 'a', name: 'openai_token', value: 'plain-text-token-1', type: 'string' }] } },
    }),
  ]);
  assert.deepEqual(rules(scanWorkflow(wf)), ['secret-field']);
});

test('expressions and placeholders in secret fields are not flagged', () => {
  const wf = workflow([
    node({
      parameters: {
        headerParameters: {
          parameters: [
            { name: 'Authorization', value: '={{ $env.API_TOKEN }}' },
            { name: 'X-Api-Key', value: 'YOUR_API_KEY' },
            { name: 'token', value: '<paste token here>' },
            { name: 'password', value: '' },
            { name: 'secret', value: 'REPLACE_ME' },
          ],
        },
      },
    }),
  ]);
  assert.deepEqual(scanWorkflow(wf), []);
});

test('n8n structural keys that merely contain "token" are not flagged', () => {
  const wf = workflow([node({ parameters: { maxTokens: 512, tokenType: 'bearer', authentication: 'genericCredentialType' } })]);
  assert.deepEqual(scanWorkflow(wf), []);
});

test('credential references are warnings', () => {
  const wf = workflow([node({ credentials: { gmailOAuth2: { id: 'aB3dE5', name: "Jane's Gmail" } } })]);
  const found = scanWorkflow(wf);
  assert.deepEqual(rules(found), ['credential-reference']);
  assert.equal(found[0].severity, 'warning');
});

test('placeholder credential IDs are not reported', () => {
  const wf = workflow([
    node({ credentials: { smtp: { id: 'PLACEHOLDER_SMTP', name: 'SMTP account' } } }),
    node({ credentials: { openAiApi: { id: 'credential-id', name: 'OpenAi account' } } }),
    node({ credentials: { slackApi: { id: '', name: 'Slack' } } }),
  ]);
  assert.deepEqual(scanWorkflow(wf), []);
});

test('pinned data and instance id are warnings', () => {
  const wf = workflow([node()], { pinData: { 'Node X': [{ json: { a: 1 } }] }, meta: { instanceId: 'f'.repeat(64) } });
  assert.deepEqual(rules(scanWorkflow(wf)).sort(), ['instance-id', 'pinned-data']);
});

test('empty pinData is fine', () => {
  assert.deepEqual(scanWorkflow(workflow([node()], { pinData: {} })), []);
});

test('internal hosts are warnings', () => {
  for (const url of [
    'http://localhost:5678/x',
    'http://127.0.0.1/x',
    'http://192.168.1.20/x',
    'http://10.0.0.3/x',
    'http://172.20.1.1/x',
    'http://nas.local/x',
    'http://host.docker.internal:8080',
  ]) {
    const found = scanWorkflow(workflow([node({ parameters: { url } })]));
    assert.deepEqual(rules(found), ['internal-host'], url);
  }
});

test('public hosts that only look similar are not internal', () => {
  for (const url of ['http://172.32.0.1/x', 'https://localhost-tools.dev/x', 'https://api.example.com/v10.0.0.1']) {
    assert.deepEqual(scanWorkflow(workflow([node({ parameters: { url } })])), [], url);
  }
});

test('your own n8n instance URLs are warnings', () => {
  for (const url of ['https://acme.app.n8n.cloud/webhook/abc', 'https://n8n.acme.io/webhook/123', 'https://auto.acme.io/webhook-test/123']) {
    assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { url } })]))), ['n8n-instance-url'], url);
  }
});

test('real-looking email addresses are warnings, reserved example domains are not', () => {
  const bad = scanWorkflow(workflow([node({ parameters: { toEmail: 'jane.doe@acme-widgets.com' } })]));
  assert.deepEqual(rules(bad), ['email-address']);
  const ok = scanWorkflow(
    workflow([node({ parameters: { a: 'you@example.com', b: 'ops@mail.example.org', c: 'x@foo.test', d: 'n@shop.invalid' } })]),
  );
  assert.deepEqual(ok, []);
});

test('sticky note text is scanned too', () => {
  const wf = workflow([
    node({ type: 'n8n-nodes-base.stickyNote', parameters: { content: `my key is ${FAKE.stripe}` } }),
  ]);
  assert.deepEqual(rules(scanWorkflow(wf)), ['hardcoded-secret']);
});

test('JSON-encoded header strings are scanned', () => {
  const wf = workflow([node({ parameters: { jsonHeaders: JSON.stringify({ Authorization: FAKE.bearer }) } })]);
  assert.ok(rules(scanWorkflow(wf)).includes('hardcoded-secret'));
});

test('template checks run only when requested', () => {
  const wf = { nodes: [node({ disabled: true })], connections: {} };
  assert.deepEqual(scanWorkflow(wf), []);
  const found = scanWorkflow(wf, { template: true });
  assert.deepEqual(rules(found).sort(), ['disabled-node', 'missing-workflow-name', 'no-sticky-note']);
});

test('ignore option drops rules', () => {
  const wf = workflow([node({ credentials: { x: { id: '1', name: 'n' } } })]);
  assert.deepEqual(scanWorkflow(wf, { ignore: ['credential-reference'] }), []);
});

test('one value matching several patterns yields one hardcoded-secret finding', () => {
  const wf = workflow([node({ parameters: { jsCode: `fetch(u, {headers: {Authorization: "Bearer ${FAKE.jwt}"}})` } })]);
  assert.equal(scanWorkflow(wf).filter((f) => f.rule === 'hardcoded-secret').length, 1);
});

// ---- review round 1 regressions ------------------------------------------------

test('large pathological strings are scanned in linear-ish time (no ReDoS)', () => {
  for (const s of ['a.'.repeat(1e5), 'a-'.repeat(1e5), 'a:'.repeat(1e5), 'a@'.repeat(5e4)]) {
    const t = Date.now();
    scanWorkflow(workflow([node({ parameters: { x: s } })]));
    assert.ok(Date.now() - t < 2000, `took ${Date.now() - t}ms`);
  }
});

test('Telegram bot tokens inside api.telegram.org URLs are detected', () => {
  const url = `https://api.telegram.org/bot${FAKE.telegram}/sendMessage`;
  assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { url } })]))), ['hardcoded-secret']);
});

test('real secrets that merely contain placeholder words are still reported', () => {
  for (const password of ['Todo123!secret', 'myExampleCorpPw!9', 'replace-this-later-8f7a']) {
    assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { password } })]))), ['secret-field'], password);
  }
});

test('secrets in URL query strings are detected', () => {
  const url = 'https://api.weather.example.net/v1?city=x&api_key=abcd1234efgh5678';
  assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { url } })]))), ['hardcoded-secret']);
  const expr = 'https://api.example.net/v1?api_key={{ $env.KEY }}';
  assert.deepEqual(scanWorkflow(workflow([node({ parameters: { url: expr } })])), []);
});

test('secret-named keys inside JSON-encoded strings are detected', () => {
  const wf = workflow([node({ parameters: { jsonBody: '{"api_key":"realsecretvalue123","city":"x"}' } })]);
  const found = scanWorkflow(wf);
  assert.deepEqual(rules(found), ['secret-field']);
  assert.match(found[0].path, /jsonBody/);
});

test('secret names propagate into arrays and nested value objects', () => {
  assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { token: ['realtoken12345'] } })]))), ['secret-field']);
  assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { token: { value: 'realtoken12345' } } })]))), ['secret-field']);
  assert.deepEqual(scanWorkflow(workflow([node({ parameters: { token: { type: 'bearer', mode: 'list' } } })])), []);
});

test('numeric secrets are detected', () => {
  assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { password: 12345678 } })]))), ['secret-field']);
});

test('header names that contain api-key or cookie are secret names', () => {
  for (const name of ['x-api-key-header', 'Cookie', 'X-Client-Secret-V2']) {
    const wf = workflow([node({ parameters: { headerParameters: { parameters: [{ name, value: 'session=abc123def456' }] } } })]);
    assert.deepEqual(rules(scanWorkflow(wf)), ['secret-field'], name);
  }
});

test('secret-field evidence shows only the length', () => {
  const [f] = scanWorkflow(workflow([node({ parameters: { password: 'abcd1234xyz' } })]));
  assert.equal(f.evidence, '(11 chars)');
});

test('documented example keys and placeholder tokens are not errors', () => {
  for (const v of ['Bearer your-api-key-goes-here', 'sk-your-openai-key-goes-here-1234', 'AKIAIOSFODNN7EXAMPLE']) {
    assert.deepEqual(scanWorkflow(workflow([node({ parameters: { x: v } })])), [], v);
  }
});

test('ports, expressions and file names are not mistaken for credentials or emails', () => {
  for (const v of [
    'https://api.partner.com:8443?owner=a@example.com',
    '=https://u:{{$env.PW}}@h.example.com/x',
    'logo image@2x.png',
  ]) {
    assert.deepEqual(scanWorkflow(workflow([node({ parameters: { x: v } })])), [], v);
  }
});

test('third-party webhook paths are not reported as n8n instance URLs', () => {
  assert.deepEqual(scanWorkflow(workflow([node({ parameters: { url: 'https://api.partner.com/webhook/abc' } })])), []);
});

test('internal hosts with expression ports, CGNAT and single-label hosts are warnings', () => {
  for (const url of ['http://localhost:{{$env.PORT}}/x', 'http://100.64.1.2/x', 'http://postgres:5432/db']) {
    assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { url } })]))), ['internal-host'], url);
  }
});

test('generic single-label hosts in comments are not internal hosts', () => {
  for (const v of ['// e.g. https://host:port/path', 'see https://server/x', 'https://host:8080/x']) {
    assert.deepEqual(scanWorkflow(workflow([node({ parameters: { jsCode: v } })])), [], v);
  }
});

test('non-empty staticData is a warning', () => {
  const wf = workflow([node()], { staticData: { global: { seen: ['a'] } } });
  assert.deepEqual(rules(scanWorkflow(wf)), ['static-data']);
  assert.deepEqual(scanWorkflow(workflow([node()], { staticData: null })), []);
});

// ---- review round 2 regressions ------------------------------------------------

test('PEM headers and dash-separated JWT prefixes do not cause quadratic scans', () => {
  const pem = ['-----BEGIN ', 'PRIVATE KEY----- a'].join('');
  for (const s of [pem.repeat(50000), 'eyJ-'.repeat(2e5), 'SG.a-'.repeat(1e5), 'sk-a.'.repeat(1e5)]) {
    const t = Date.now();
    scanWorkflow(workflow([node({ parameters: { x: s } })]));
    assert.ok(Date.now() - t < 2000, `took ${Date.now() - t}ms for ${s.slice(0, 12)}…`);
  }
});

test('expression-mode JSON bodies and headers are scanned', () => {
  const body = '={\n "apiKey": "realsecretvalue123",\n "name": "{{ $json.name }}",\n "n": {{ $json.count }}\n}';
  assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { jsonBody: body } })]))), ['secret-field']);
  const headers = '={"X-Api-Key":"abcdef123456"}';
  assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { jsonHeaders: headers } })]))), ['secret-field']);
  const exprOnly = '={"Authorization":"Bearer {{ $env.TOKEN }}"}';
  assert.deepEqual(scanWorkflow(workflow([node({ parameters: { jsonHeaders: exprOnly } })])), []);
});

test('names that describe a secret are not secret names; real variants are', () => {
  for (const name of ['passwordless', 'maxPasswordAge', 'passwordField', 'passwordLabel', 'passwordResetUrl', 'clientSecretLabel', 'privateKeyPath', 'apiKeyName', 'sessionId', 'tokenType', 'maxTokens']) {
    assert.deepEqual(scanWorkflow(workflow([node({ parameters: { [name]: 'some-literal-value' } })])), [], name);
  }
  for (const name of ['passphrase', 'authorizationHeader', 'X-Auth-Token', 'stripeSecretKey']) {
    assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { [name]: 'some-literal-value' } })]))), ['secret-field'], name);
  }
});

test('bracketed or "enter-" values with secret-like content are not placeholders', () => {
  for (const v of ['<s3cretPw!>', '[abcdef123456]', 'Enter-4kd93jd02x']) {
    assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { password: v } })]))), ['secret-field'], v);
  }
});

test('placeholder words only exempt the secret part of URL credentials and query strings', () => {
  for (const url of ['https://api.example.net/v1?password=MyExamplePass1', 'https://user:Example123@db.example.net/x']) {
    assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { url } })]))), ['hardcoded-secret'], url);
  }
  assert.deepEqual(scanWorkflow(workflow([node({ parameters: { url: 'https://api.example.net/v1?api_key=YOUR_API_KEY_HERE' } })])), []);
});

test('IPv6 private ranges and unusual IPv4 spellings are internal hosts', () => {
  for (const url of ['http://[fd00::1]/', 'http://[fe80::1]/', 'http://127.1/', 'http://2130706433/', 'http://0x7f.0.0.1/', 'http://[::ffff:10.0.0.1]/', 'http://[::ffff:7f00:1]/']) {
    assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: { url } })]))), ['internal-host'], url);
  }
  for (const url of ['http://[2001:db8::1]/', 'http://8.8.8.8/', 'http://1.2/']) {
    assert.deepEqual(scanWorkflow(workflow([node({ parameters: { url } })])), [], url);
  }
});

test('keys right after an escaped newline in code are detected', () => {
  const jsCode = `const msg = "header\\n${FAKE.anthropic}";`;
  assert.deepEqual(rules(scanWorkflow(workflow([node({ type: 'n8n-nodes-base.code', parameters: { jsCode } })]))), ['hardcoded-secret']);
});

test('very deep nesting is reported instead of crashing', () => {
  const deep = '['.repeat(100000) + ']'.repeat(100000);
  const found = scanWorkflow(workflow([node({ parameters: { jsonBody: deep } })]));
  assert.ok(found.every((f) => f.rule === 'too-deep'));
  let obj = {};
  const root = obj;
  for (let i = 0; i < 500; i++) obj = obj.x = {};
  assert.deepEqual(rules(scanWorkflow(workflow([node({ parameters: root })]))), ['too-deep']);
});

test('extractWorkflows accepts a workflow, an array, and an API {data: []} wrapper', () => {
  const wf = workflow([node()]);
  assert.equal(extractWorkflows(wf).length, 1);
  assert.equal(extractWorkflows([wf, wf]).length, 2);
  assert.equal(extractWorkflows({ data: [wf] }).length, 1);
  assert.equal(extractWorkflows({ foo: 1 }), null);
  assert.equal(extractWorkflows([{ foo: 1 }]), null);
  assert.equal(extractWorkflows(null), null);
});

test('maskValue keeps a short prefix only', () => {
  assert.equal(maskValue('abc'), '***');
  assert.equal(maskValue('abcdefghijkl'), 'abcd… (12 chars)');
});
