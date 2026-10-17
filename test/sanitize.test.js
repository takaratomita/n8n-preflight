import { test } from 'node:test';
import assert from 'node:assert/strict';

import { sanitizeWorkflow } from '../src/sanitize.js';
import { scanWorkflow } from '../src/scan.js';
import { FAKE, node, workflow } from './helpers.js';

function leaky() {
  return workflow(
    [
      node({
        name: 'Call API',
        parameters: {
          url: 'https://api.example.com/x',
          headerParameters: { parameters: [{ name: 'Authorization', value: FAKE.bearer }] },
          jsCode: `const k = "${FAKE.openai}"; // keep this comment`,
          options: { apiKey: 'plain-secret-123' },
        },
        credentials: { httpHeaderAuth: { id: 'Zx9', name: 'My header auth' } },
      }),
    ],
    { pinData: { 'Call API': [{ json: { email: 'jane@acme-widgets.com' } }] }, meta: { instanceId: 'abc', templateCredsSetupCompleted: true }, shared: [{ role: 'owner' }] },
  );
}

test('sanitize removes errors-level leaks and instance specific data', () => {
  const { workflow: out, changes } = sanitizeWorkflow(leaky());
  const remaining = scanWorkflow(out).filter((f) => f.severity === 'error');
  assert.deepEqual(remaining, []);
  assert.equal(out.pinData, undefined);
  assert.equal(out.shared, undefined);
  assert.equal(out.meta.instanceId, undefined);
  assert.equal(out.meta.templateCredsSetupCompleted, true);
  assert.equal(out.nodes[0].credentials, undefined);
  assert.ok(changes.length >= 5);
});

test('sanitize keeps surrounding text and structure intact', () => {
  const { workflow: out } = sanitizeWorkflow(leaky());
  const p = out.nodes[0].parameters;
  assert.equal(p.url, 'https://api.example.com/x');
  assert.equal(p.jsCode, 'const k = "REPLACE_ME"; // keep this comment');
  assert.equal(p.headerParameters.parameters[0].name, 'Authorization');
  assert.equal(p.headerParameters.parameters[0].value, 'REPLACE_ME');
  assert.equal(p.options.apiKey, 'REPLACE_ME');
  assert.equal(out.nodes[0].name, 'Call API');
});

test('sanitize does not mutate its input', () => {
  const input = leaky();
  const before = JSON.stringify(input);
  sanitizeWorkflow(input);
  assert.equal(JSON.stringify(input), before);
});

test('sanitizing a clean workflow changes nothing', () => {
  const clean = workflow([node({ parameters: { url: 'https://api.example.com' } })]);
  const { workflow: out, changes } = sanitizeWorkflow(clean);
  assert.deepEqual(out, clean);
  assert.deepEqual(changes, []);
});

test('sanitize handles JSON strings, query strings, staticData and activeVersion nodes', () => {
  const wf = workflow(
    [
      node({
        parameters: {
          jsonBody: '{"api_key":"realsecretvalue123","city":"x"}',
          url: 'https://api.example.net/v1?city=x&api_key=abcd1234efgh5678',
        },
      }),
    ],
    { staticData: { global: { seen: [1] } }, activeVersion: { nodes: [node({ credentials: { a: { id: 'Zx1', name: 'n' } } })] } },
  );
  const { workflow: out } = sanitizeWorkflow(wf);
  assert.deepEqual(scanWorkflow(out), []);
  assert.deepEqual(JSON.parse(out.nodes[0].parameters.jsonBody), { api_key: 'REPLACE_ME', city: 'x' });
  assert.equal(out.nodes[0].parameters.url, 'https://api.example.net/v1?city=x&api_key=REPLACE_ME');
  assert.equal(out.staticData, undefined);
  assert.equal(out.activeVersion.nodes[0].credentials, undefined);
});

test('JSON strings are edited in place: formatting, big numbers and escapes survive', () => {
  const jsonBody = '{\n\t"id": 12345678901234567890,\n\t"ratio": 1.0,\n\t"name": "caf\\u00e9",\n\t"api_key": "realsecretvalue123"\n}';
  const { workflow: out } = sanitizeWorkflow(workflow([node({ parameters: { jsonBody } })]));
  assert.equal(out.nodes[0].parameters.jsonBody, jsonBody.replace('"realsecretvalue123"', '"REPLACE_ME"'));
});

test('the same secret twice is replaced in place without re-serializing', () => {
  const body = '{\n "a": {"password":"hunter2hunter2", "big": 12345678901234567890},\n "b": {"password":"hunter2hunter2"}\n}';
  const { workflow: out, changes } = sanitizeWorkflow(workflow([node({ parameters: { body } })]));
  assert.equal(out.nodes[0].parameters.body, body.replaceAll('"hunter2hunter2"', '"REPLACE_ME"'));
  assert.ok(!changes.some((c) => /re-serialized/.test(c.action)));
});

test('a numeric secret only replaces that number, never other numbers', () => {
  const body = '{"password": 12345678, "count": 3, "nested": {"n": 12345678}}';
  const { workflow: out } = sanitizeWorkflow(workflow([node({ parameters: { body } })]));
  assert.equal(out.nodes[0].parameters.body, '{"password": "REPLACE_ME", "count": 3, "nested": {"n": 12345678}}');
  const arr = sanitizeWorkflow(workflow([node({ parameters: { apiKeys: '[123456789, 1, 2, {"x":5}]' } })])).workflow;
  assert.deepEqual(JSON.parse(arr.nodes[0].parameters.apiKeys), ['REPLACE_ME', 1, 2, { x: 5 }]);
});

test('an expression JSON secret that cannot be located is reported as not cleaned', () => {
  const body = '={ "password": "p\\u0061ssword123", "n": "{{ $json.n }}" }';
  const { changes } = sanitizeWorkflow(workflow([node({ parameters: { body } })]));
  assert.ok(changes.some((c) => /NOT cleaned/.test(c.action)));
});

test('expression-mode JSON keeps its expressions and loses the secret', () => {
  const jsonBody = '={\n "apiKey": "realsecretvalue123",\n "name": "{{ $json.name }}",\n "n": {{ $json.count }}\n}';
  const { workflow: out } = sanitizeWorkflow(workflow([node({ parameters: { jsonBody } })]));
  assert.equal(out.nodes[0].parameters.jsonBody, jsonBody.replace('"realsecretvalue123"', '"REPLACE_ME"'));
  assert.deepEqual(scanWorkflow(out), []);
});

test('PEM blocks are removed entirely, with or without an END line', () => {
  const begin = ['-----BEGIN ', 'PRIVATE KEY-----'].join('');
  const end = ['-----END ', 'PRIVATE KEY-----'].join('');
  const { workflow: out } = sanitizeWorkflow(
    workflow([node({ parameters: { a: `key:\n${begin}\nMIIabc\n${end}\nafter`, b: `${begin}\nMIIabc-truncated` } })]),
  );
  assert.equal(out.nodes[0].parameters.a, 'key:\nREPLACE_ME\nafter');
  assert.equal(out.nodes[0].parameters.b, 'REPLACE_ME');
});

test('changes list never includes secret values', () => {
  const { changes } = sanitizeWorkflow(leaky());
  const text = JSON.stringify(changes);
  assert.ok(!text.includes(FAKE.openai));
  assert.ok(!text.includes('plain-secret-123'));
});
