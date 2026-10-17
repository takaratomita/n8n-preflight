# n8n-preflight

**Scan n8n workflow JSON for leaked API keys, credential IDs, pinned data and private URLs — before you share, publish or sell it.**

Exported n8n workflows are easy to share and easy to leak from. A "quick test" HTTP Request node with a pasted `Authorization` header, a pinned run full of customer emails, the `instanceId` of your server, a webhook URL that points at your own instance — all of it ends up in the JSON you paste into a forum, a GitHub repo or a template marketplace.

`n8n-preflight` is a small, zero-dependency CLI that reads that JSON and tells you what to remove. It can also write a cleaned copy.

```text
$ n8n-preflight examples/leaky-workflow.json
examples/leaky-workflow.json
  error    secret-field          "api_key" has a literal value; use an n8n credential or an expression instead
           at node "Get forecast" → nodes[1].parameters.queryParameters.parameters[1].value  [(21 chars)]
  error    hardcoded-secret      Possible Bearer token
           at node "Get forecast" → nodes[1].parameters.headerParameters.parameters[0].value  [Bearer 0123… (32 chars)]
  warning  credential-reference  Credential "slackApi" references an ID from your instance
           at node "Post to Slack" → nodes[3].credentials.slackApi
  warning  internal-host         URL points to an internal host (192.168.1.40)
           at node "Home sensor" → nodes[2].parameters.url
  warning  email-address         Real-looking email address (jane… (25 chars))
           at node "Post to Slack" → nodes[3].parameters.text
  warning  pinned-data           Pinned data is exported with the workflow; remove it before sharing
           at pinData
  warning  instance-id           meta.instanceId identifies your n8n instance
           at meta.instanceId

2 errors, 5 warnings (1 file scanned).
```

Secrets are never printed in full. Recognized tokens show their first 4 characters (usually the public prefix such as `sk-p` or `Bearer`) and the length; values of secret-named fields show only the length. The output itself is safe to paste into an issue or a CI log.

## Install / run

Requires Node.js 18 or newer. No dependencies.

```bash
# run without installing
npx github:takaratomita/n8n-preflight my-workflow.json

# or clone and run
git clone https://github.com/takaratomita/n8n-preflight.git
node n8n-preflight/bin/n8n-preflight.js my-workflow.json
```

## Usage

```text
n8n-preflight [options] <file-or-directory ...>

  --json              Print findings as JSON
  --strict            Exit with code 1 on warnings too (default: errors only)
  --template          Also run n8n template checks (sticky notes, name, disabled nodes)
  --ignore <rule>     Skip a rule (repeatable, or comma separated)
  --sanitize <out>    Write a cleaned copy of a single input file to <out>
  -h, --help          Show help
  -v, --version       Show version
```

- Directories are scanned recursively for `*.json` (`node_modules` and `.git` are skipped). JSON files that are not n8n workflows are skipped when they come from a directory, and rejected when you pass them by name.
- Accepted shapes: a single exported workflow, an array of workflows (`n8n export:workflow --all`), or an n8n API response (`{ "data": [...] }`).
- JSON strings inside parameters (for example `jsonBody` or `jsonHeaders`) are parsed and scanned like normal fields.
- Exit codes: `0` nothing at the failing level, `1` findings (also when some other input could not be read), `2` usage / read / parse error or no workflow JSON found.

### Clean a workflow before sharing

```bash
n8n-preflight --sanitize shareable.json my-workflow.json
```

This writes a copy where:

- `pinData`, `staticData`, `shared` and `meta.instanceId` are removed
- node `credentials` references are removed (whoever imports it selects their own)
- literal values in secret-named fields (`api_key`, `token`, `password`, `Authorization`, …) become `REPLACE_ME`
- token-looking substrings inside code or text become `REPLACE_ME`, and the surrounding text is kept

Emails and internal URLs are only reported, never rewritten — they often need a human decision. The original file is never modified.

### Use it in CI

```yaml
# .github/workflows/n8n-preflight.yml
name: n8n-preflight
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx github:takaratomita/n8n-preflight --strict workflows/
```

## What it checks

| Rule | Level | What it means |
|---|---|---|
| `hardcoded-secret` | error | A value that looks like a real key: OpenAI, Anthropic, Stripe, Slack (tokens and webhook URLs), Discord webhooks, Telegram bots (also inside `api.telegram.org/bot…` URLs), GitHub, AWS, Google, SendGrid, Hugging Face, Notion, Airtable, JWTs, PEM private keys, `Bearer …` headers, `user:password@` in URLs, `?api_key=…`-style query strings. Documentation examples (`…EXAMPLE`, `your-api-key`) are ignored |
| `secret-field` | error | A field or header/query/Set-node entry named like a secret (`apiKey`, `x-api-key`, `token`, `password`, `Authorization`, `Cookie`, `client_secret`, …) holds a literal value, including numbers and values nested under that name. Expressions (`={{ $env.TOKEN }}`) and obvious placeholders (`YOUR_API_KEY`, `<token>`, `REPLACE_ME`) are fine |
| `credential-reference` | warning | A node references a credential ID from your instance (IDs like `PLACEHOLDER_*` are ignored) |
| `pinned-data` | warning | Pinned execution data is included — often real customer data |
| `static-data` | warning | Saved static data (state from your own runs) is included |
| `instance-id` | warning | `meta.instanceId` identifies your n8n instance |
| `internal-host` | warning | URL to `localhost`, private / CGNAT / link-local IPv4 (also spelled `127.1`, `2130706433`, `0x7f.0.0.1`), IPv6 `fc00::/7` and `fe80::/10`, `*.local`, `*.internal`, `host.docker.internal`, docker-compose style `service:port`, … A single-label host *without* a port (`http://myserver/`) is not reported, because that is usually prose such as `https://host/path` |
| `too-deep` | error | Nesting deeper than 200 levels; that part was not checked |
| `n8n-instance-url` | warning | URL to a specific n8n instance (`*.app.n8n.cloud`, `/webhook-test/…`, or `/webhook/…` and `/form/…` on a host named like n8n) |
| `email-address` | warning | A real-looking email (anything except `example.com/.org/.net`, `.test`, `.invalid`, `.example`) |
| `no-sticky-note` | warning (`--template`) | No sticky note. n8n's template reviewers expect sticky notes that explain the workflow |
| `missing-workflow-name` | warning (`--template`) | Workflow has no name |
| `disabled-node` | warning (`--template`) | A disabled node was left in |

## Limits

This is a pattern scanner, not a guarantee. It will not find a secret that has no recognizable shape and sits in a field with an innocent name, and it does not follow values that are built at runtime. Keep secrets in n8n credentials, and treat a clean result as "nothing obvious", not "safe". If you already shared a key, rotate it — removing it from the JSON does not un-leak it.

## Development

```bash
npm test   # node --test, no dependencies
```

## Free workflows

Free workflows that already pass `n8n-preflight --template --strict`: https://github.com/takaratomita/n8n-free-workflows

## License

MIT
