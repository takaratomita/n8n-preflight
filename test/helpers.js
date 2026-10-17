// Test helpers.
// Fake secrets are assembled at runtime with string concatenation so that the
// repository itself never contains a literal that looks like a real credential
// (keeps GitHub push protection and other secret scanners quiet).

const j = (...parts) => parts.join('');

export const FAKE = {
  openai: j('sk-', 'proj-', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4'),
  anthropic: j('sk-', 'ant-', 'api03-', 'abcdefghijklmnopqrstuvwx'),
  stripe: j('sk', '_live_', 'abcdefghijklmnop1234'),
  slackToken: j('xo', 'xb-', '1234567890-abcdefghij'),
  slackWebhook: j('https://hooks.', 'slack.com/services/', 'T000/B000/abcdEFGHijkl'),
  discordWebhook: j('https://discord.com/api/', 'webhooks/', '123456789/abcDEF_ghi-jkl'),
  telegram: j('123456789', ':AA', 'abcdefghijklmnopqrstuvwxyz0123456'),
  github: j('gh', 'p_', 'abcdefghijklmnopqrstuvwxyz0123456789'),
  aws: j('AK', 'IA', 'ABCDEFGHIJKLMNOP'),
  google: j('AI', 'za', 'Sy', 'abcdefghijklmnopqrstuvwxyz0123456'),
  jwt: j('ey', 'JhbGciOiJIUzI1NiJ9', '.', 'ey', 'JzdWIiOiIxMjM0NTY3ODkwIn0', '.', 'abcdefghijklmnopqrstuv'),
  pem: j('-----BEGIN ', 'PRIVATE KEY-----\nMIIabc\n-----END ', 'PRIVATE KEY-----'),
  bearer: j('Bearer ', 'abcdefghijklmnopqrstuvwxyz012345'),
  urlCreds: j('https://admin', ':hunter2', '@db.example.org/api'),
};

let seq = 0;

export function node(overrides = {}) {
  seq += 1;
  return {
    id: `node-${seq}`,
    name: overrides.name ?? `Node ${seq}`,
    type: 'n8n-nodes-base.httpRequest',
    typeVersion: 4.2,
    position: [0, 0],
    parameters: {},
    ...overrides,
  };
}

export function workflow(nodes = [], extra = {}) {
  return { name: 'Test workflow', nodes, connections: {}, ...extra };
}

export function rules(findings) {
  return findings.map((f) => f.rule);
}
