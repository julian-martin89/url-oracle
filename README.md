# url-oracle — URL Trust Oracle

A pay-per-call MCP (Model Context Protocol) server that verifies a URL or
domain **before** an AI agent fetches, cites, recommends, or follows it.
Monetized per call with the real [x402](https://x402.gitbook.io/x402/)
protocol (signed EIP-3009 authorizations, settled through Coinbase's
hosted facilitator) in USDC on Base — no API keys, no signup, no dashboard.
An agent calls the tool, pays a fraction of a cent, gets a verdict.

pkg-oracle's sibling: same architecture, same payment rails, same verdict
vocabulary — applied to links instead of packages.

## Frequently asked questions

### What is phantom squatting?

Phantom squatting is a 2026-documented attack where attackers register
domains that LLMs hallucinate. Palo Alto Networks' Unit 42 generated 2.1
million URLs across 913 brands and 685,339 adversarial prompts: 809,455
pointed to domains that don't exist, 250,000 of those were unregistered
(ready for an attacker to claim), and 13,229 were already flagged
malicious. A different model asked the same question often hallucinates
the *same* fake domain, which is what makes this predictable and worth
pre-registering. Researchers call it structurally unpatchable at the
model level — the fix has to live at the point of use, before a link is
trusted.

### How do I check if a URL is safe before an agent follows it?

Call the `verify_url` MCP tool with the exact URL. It checks the domain's
RDAP registration (does it exist, how old is it), runs a
Levenshtein-distance brand-similarity check against well-known domains,
and checks the URL against a known-malicious-infrastructure blocklist
(URLhaus). Returns one verdict — `ALLOW`, `WARN`, or `BLOCK`.

### How is this different from a typosquat/malicious-package checker?

Same underlying pattern — an LLM hallucinates a name, an attacker
pre-registers it — applied one layer up: pkg-oracle (its sibling project)
checks npm/PyPI/crates.io package names before an install; url-oracle
checks URLs and domains before a fetch, citation, or click. Any agent
that outputs a link is exposed to this, not just coding agents.

### Is there an existing tool for detecting phantom-squatted domains?

Not a public one as of this writing — Palo Alto's own phantom-squatting
research describes only an internal detection pipeline, no public API or
dataset. url-oracle is built from the same public data sources (RDAP,
URLhaus) rather than proprietary threat intel.

### How much does it cost to verify a URL?

The first 5 calls per wallet/IP are free. After that, $0.003 USDC per
call, paid via the x402 protocol on Base — no subscription, no API key,
no dashboard.

### Does it work with Claude Desktop, Cursor, or Claude Code?

Yes, for the free tier — any Streamable-HTTP-compatible MCP client can
connect (see [Client configuration](#client-configuration) below).
Paying past the free tier needs an x402-aware client.

## Why this exists

AI agents routinely generate URLs they never actually verified — a
documentation link, an API endpoint, a brand's support page — recalled or
inferred rather than given by the user. Most of the time the link is
fine. Sometimes it's a domain nobody has ever registered, sitting there
waiting for an attacker to notice the same pattern Unit 42 found: ask
enough models the same question and they hallucinate the same fake
domain, which makes it a predictable, pre-registerable target.

`verify_url` closes that gap with a single tool call that:

1. Looks up the domain's **RDAP registration record** — does it exist at
   all, and how old is it.
2. Runs a **Levenshtein-distance brand-similarity check** against a
   curated list of well-known domains (AI/dev tooling, cloud, finance,
   crypto, social, everyday utility — the categories phantom-squatting
   research found attackers actually targeting).
3. Checks the exact URL against **URLhaus**, a community-maintained feed
   of confirmed malware/phishing infrastructure.

It returns one synthetic verdict: **ALLOW**, **WARN**, or **BLOCK**.

## Architecture

```
Agent (Claude, Cursor, custom SDK / x402-aware MCP client)
        │  MCP tools/call verify_url  (_meta["x402/payment"] once paid)
        ▼
StreamableHTTPServerTransport (fresh per request, stateless mode)
        │
        ▼
McpServer → verify_url
        │
        ├─ under free tier? ──▶ raw handler (no charge)
        │
        └─ else ──▶ x402 payment wrapper (@x402/mcp)
                       │
                       ├──▶ CDP facilitator: verify signed payment, settle on-chain
                       └──▶ raw handler
                              │
                              ├──▶ rdap.ts         (rdap.org — IANA bootstrap, any TLD)
                              ├──▶ domainSquat.ts   (fast-levenshtein vs. curated brand list)
                              └──▶ urlhaus.ts       (urlhaus-api.abuse.ch — known-malicious feed)
                                     │
                                     ▼
                              oracle.ts aggregates → { verdict, findings[] }
```

Payment gating happens **per MCP tool**, not per HTTP route — `initialize`
and `tools/list` are never charged, only an actual `verify_url` call past
the free tier is.

There's also a plain-HTTP twin at `POST /verify` — see
[Monetization](#monetization-x402-on-base-via-the-cdp-facilitator) for why.

## Quickstart

```bash
npm install
cp .env.example .env   # RECIPIENT_WALLET + CDP_API_KEY_ID/SECRET are required, even in dev
npm run build
npm start
```

Or for local iteration with hot reload:

```bash
npm run dev
```

Unlike most values in `.env.example`, `RECIPIENT_WALLET` and the two CDP
credentials have no safe placeholder — the resource server authenticates
against CDP's real hosted facilitator at boot, regardless of environment.

The server listens on `PORT` (default `3000`) and exposes:

| Endpoint      | Method            | Purpose                                    |
| ------------- | ----------------- | ------------------------------------------- |
| `/mcp`        | `POST`            | MCP tool calls — `verify_url` is payment-gated past the free tier |
| `/mcp`        | `GET`, `DELETE`   | Streamable HTTP protocol completeness (no-ops) |
| `/verify`     | `POST`            | Plain-HTTP twin of `verify_url`, no free tier — the Bazaar-discoverable surface |
| `/health`     | `GET`             | Liveness check, always free                 |

## Environment variables

See [`.env.example`](.env.example) for the full list with defaults.

| Variable                     | Default                                     | Meaning |
| ----------------------------- | -------------------------------------------- | ------- |
| `RECIPIENT_WALLET`            | *(dev-only burn address)*                    | Base L2 wallet that receives USDC payments — required |
| `SOLANA_RECIPIENT_WALLET`     | *(unset — Solana not offered)*               | Optional second settlement network, base58 Solana address |
| `CDP_API_KEY_ID`              | *(none — required)*                          | Coinbase Developer Platform API key ID |
| `CDP_API_KEY_SECRET`          | *(none — required)*                          | Coinbase Developer Platform API key secret |
| `URLHAUS_AUTH_KEY`            | *(unset — threat-intel check skipped)*       | Free key from https://auth.abuse.ch/ |
| `PRICE_ATOMIC_USDC`           | `3000` (= $0.003)                            | Price per call once the free tier is spent |
| `FREE_TIER_LIMIT`             | `5`                                          | Free calls per wallet/IP before payment is required |
| `UPSTREAM_TIMEOUT_MS`         | `8000`                                       | Timeout for RDAP/URLhaus calls |
| `NEW_DOMAIN_THRESHOLD_DAYS`   | `30`                                         | Age under which a domain is "new" |
| `BRAND_SQUAT_MAX_DISTANCE`    | `2`                                          | Max Levenshtein distance still flagged |

## The `verify_url` tool

**Input schema:**

```json
{
  "url": "string (required, e.g. \"https://example.com/path\")"
}
```

**Example call and response:**

```jsonc
// request
{ "url": "https://opneai.com/api" }

// response (verdict text + machine-readable JSON in content[])
{
  "verdict": "WARN",
  "findings": [
    {
      "code": "BRAND_NAME_SIMILARITY",
      "message": "\"opneai.com\" is close (distance 2) to the well-known domain \"openai.com\"..."
    }
  ],
  "domain": { "exists": true, "ageDays": 1400, "registrar": "..." },
  "threatIntel": { "queried": false, "flagged": false },
  "brandSimilarity": { "suspected": true, "nearestBrandDomain": "openai.com", "distance": 2, "redFlag": false }
}
```

### Verdict logic (first match wins)

1. **BLOCK** — the URL is on a known malicious-infrastructure blocklist
   (URLhaus) — a confirmed active threat, not just a plausible target.
2. **BLOCK** — the domain is a near-miss of a well-known brand **and** is
   unregistered or brand-new — the canonical phantom-squat pattern.
3. **WARN** — the domain isn't registered at all but isn't brand-similar
   either (a dead/broken link).
4. **WARN** — brand-name similarity exists but the domain is old enough
   that this is plausibly coincidental.
5. **WARN** — the domain is registered and brand-safe, but very new.
6. **ALLOW** — nothing above fired.

## Monetization: x402 on Base, via the CDP facilitator

Same real x402 "exact" scheme as pkg-oracle — see that project's README
for the full mechanics (EIP-3009 `transferWithAuthorization`, CDP never
custodying funds, Bazaar auto-discovery on first settled payment). The
one addition here: **two endpoints, not one**.

`/mcp` has a 5-call free tier for human-configured clients (Claude
Desktop, Cursor, custom agent SDKs). `/verify` is a plain-HTTP twin with
**no free tier** — every call pays from the first request. It exists
because the CDP Bazaar's discovery catalog only surfaces HTTP-transport
resources; an MCP tool declaring Bazaar discovery never appears there,
even after a real payment settles (confirmed empirically while building
pkg-oracle). `/verify` is what makes `verify_url` discoverable by
autonomous agents without any human configuration.

### Multi-network: Base + Solana

Set `SOLANA_RECIPIENT_WALLET` to accept payment on Solana mainnet too —
every x402 challenge then offers both networks side by side. Unset by
default (Base only). Handled entirely by `@x402/svm`'s `ExactSvmScheme`
and CDP's facilitator — this server never holds a Solana keypair.

## Client configuration

### Claude Desktop / Cursor (free tier only)

```json
{
  "mcpServers": {
    "url-oracle": {
      "type": "http",
      "url": "https://url-oracle.fly.dev/mcp",
      "headers": {
        "Authorization": "Bearer 0xYourAgentWalletAddress"
      }
    }
  }
}
```

### Custom agent with x402 support

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { wrapMCPClientWithPaymentFromConfig } from "@x402/mcp";
import { ExactEvmScheme } from "@x402/evm/exact/client";

const mcpClient = new Client({ name: "my-agent", version: "1.0.0" });
await mcpClient.connect(
  new StreamableHTTPClientTransport(new URL("https://url-oracle.fly.dev/mcp")),
);

const x402Client = wrapMCPClientWithPaymentFromConfig(mcpClient, {
  schemes: [{ network: "eip155:8453", client: new ExactEvmScheme(account) }],
});

const result = await x402Client.callTool("verify_url", {
  url: "https://opneai.com/api",
});
```

## Docker

```bash
docker build -t url-oracle .
docker run -p 3000:3000 \
  -e RECIPIENT_WALLET=0xYourWalletAddress \
  -e CDP_API_KEY_ID=your-cdp-key-id \
  -e CDP_API_KEY_SECRET=your-cdp-key-secret \
  -e FREE_TIER_LIMIT=5 \
  url-oracle
```

## Known limitations / honest scope notes

- **Brand-domain list is curated, not exhaustive.** A hand-picked
  shortlist of the highest-value impersonation targets
  (`src/services/popularDomains.ts`), not a live top-ranked-sites feed.
  Catches `githu-b.com` → `github.com`; won't catch a typo of a
  lower-profile brand outside the list.
- **URLhaus requires a free API key you provide** (`URLHAUS_AUTH_KEY`) —
  abuse.ch started requiring one mid-2025. Without it, `verify_url` still
  runs on RDAP + brand-similarity alone; the threat-intel signal is just
  absent rather than the call failing.
- **Certificate Transparency logs (crt.sh) were deliberately left out.**
  It's a free, commonly-used signal, but it returned `502` on every live
  test while building this — unreliable enough that depending on it would
  degrade the oracle's own availability more often than it would help.
- **The free-tier counter is in-memory (LRU)**, not persisted — resets on
  restart, doesn't share state across instances. Fine at
  `min_machines_running: 1`.
- **RDAP's eTLD+1 parsing uses `tldts`**, which bundles a public suffix
  list — correct for the vast majority of TLDs, but a suffix list can lag
  a brand-new TLD by days.
