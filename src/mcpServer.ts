import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { LRUCache } from "lru-cache";
import { createPaymentWrapper, type MCPToolContext, type ToolResult } from "@x402/mcp";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { verifyUrl } from "./services/oracle.js";
import { resourceServer, verifyUrlPrice, verifyUrlPriceSolana, SOLANA_NETWORK } from "./services/x402.js";
import { config } from "./config.js";

/**
 * x402 payment wiring for `verify_url` — same shape as pkg-oracle's
 * mcpServer.ts. The shared resource server (facilitator + Bazaar extension,
 * already initialized) lives in services/x402.ts.
 */
const baseAccepts = await resourceServer.buildPaymentRequirements({
  scheme: "exact",
  network: config.x402Network,
  payTo: config.recipientWallet,
  price: verifyUrlPrice,
  maxTimeoutSeconds: 60,
});

const solanaAccepts = config.solanaRecipientWallet
  ? await resourceServer.buildPaymentRequirements({
      scheme: "exact",
      network: SOLANA_NETWORK,
      payTo: config.solanaRecipientWallet,
      price: verifyUrlPriceSolana,
      maxTimeoutSeconds: 60,
    })
  : [];

const verifyUrlAccepts = [...baseAccepts, ...solanaAccepts];

/**
 * The actual URL-trust-oracle logic, shape-compatible with both the free
 * path (called directly below) and the paid path (wrapped by
 * `createPaymentWrapper`).
 */
async function rawVerifyUrlHandler(args: { url: string }, _context: MCPToolContext): Promise<ToolResult> {
  const { url } = args;
  try {
    const result = await verifyUrl(url);

    const header = [`Verdict: ${result.verdict}`, `URL: ${result.url}`, `Domain: ${result.registrableDomain ?? result.hostname}`, ""];
    const findingLines = result.findings.map((f) => `- [${f.code}] ${f.message}`);

    return {
      content: [
        { type: "text" as const, text: [...header, ...findingLines].join("\n") },
        { type: "text" as const, text: JSON.stringify(result, null, 2) },
      ],
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      isError: true,
      content: [{ type: "text" as const, text: `verify_url failed while checking "${url}": ${message}` }],
    };
  }
}

const paidVerifyUrlHandler = createPaymentWrapper(resourceServer, {
  accepts: verifyUrlAccepts,
  resource: {
    url: "mcp://tool/verify_url",
    description:
      "Checks whether a URL/domain is safe to cite, fetch, or follow: flags phantom-squatted or " +
      "typosquatted brand domains, unregistered/dead domains, and known malicious infrastructure.",
    serviceName: "url-oracle",
    tags: [
      "security",
      "phishing",
      "phantom-squatting",
      "typosquatting",
      "url-verification",
      "domain-reputation",
      "malicious-link",
      "whois",
      "brand-protection",
    ],
  },
  extensions: declareDiscoveryExtension({
    toolName: "verify_url",
    description:
      "Verify a URL/domain for phantom squatting (LLM-hallucinated brand domains), domain age, and known malicious infrastructure before fetching, citing, or following it.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string" },
      },
      required: ["url"],
    },
    output: {
      example: {
        verdict: "BLOCK",
        findings: [{ code: "PHANTOM_SQUAT_SUSPECTED", message: "..." }],
      },
    },
  }),
})(rawVerifyUrlHandler);

/**
 * Marks which caller identities have exhausted their free tier — same
 * self-declared, unverified identity model as pkg-oracle (see that
 * project's config.ts for why that's an accepted, bounded risk).
 */
const callerCounters = new LRUCache<string, { callCount: number }>({
  max: config.rateLimitCacheMaxEntries,
  ttl: config.rateLimitCacheTtlMs,
});

type IsomorphicHeaders = Record<string, string | string[] | undefined>;

function headerValue(headers: IsomorphicHeaders | undefined, name: string): string | undefined {
  const value = headers?.[name];
  return Array.isArray(value) ? value[0] : value;
}

function identifyCaller(headers: IsomorphicHeaders | undefined): string {
  const authHeader = headerValue(headers, "authorization");
  if (authHeader?.startsWith("Bearer ")) {
    const wallet = authHeader.slice("Bearer ".length).trim();
    if (wallet.length > 0) return `wallet:${wallet.toLowerCase()}`;
  }

  const walletHeader = headerValue(headers, "x-wallet-address");
  if (walletHeader) return `wallet:${walletHeader.toLowerCase()}`;

  const forwardedFor = headerValue(headers, "x-forwarded-for");
  if (forwardedFor) return `ip:${forwardedFor.split(",")[0]?.trim()}`;

  return "ip:unknown";
}

function isUnderFreeTier(callerId: string): boolean {
  const state = callerCounters.get(callerId) ?? { callCount: 0 };
  if (state.callCount >= config.freeTierLimit) return false;
  state.callCount += 1;
  callerCounters.set(callerId, state);
  return true;
}

/** One structured JSON line per `verify_url` call, to stdout — Fly captures this automatically. */
function logCall(fields: { callerId: string; paid: boolean; url: string; result: ToolResult }): void {
  const verdict = fields.result.isError
    ? "ERROR"
    : (fields.result.content[0]?.text.match(/^Verdict: (\w+)/)?.[1] ?? "UNKNOWN");

  console.log(
    JSON.stringify({
      event: "verify_url_call",
      time: new Date().toISOString(),
      callerId: fields.callerId,
      paid: fields.paid,
      url: fields.url,
      verdict,
    }),
  );
}

/**
 * Builds a fresh `McpServer` instance with `verify_url` registered —
 * factory, not a singleton, for the same stateless-transport reason as
 * pkg-oracle's buildMcpServer().
 */
export function buildMcpServer(): McpServer {
  const server = new McpServer({ name: "url-oracle", version: "1.0.0" });

  server.registerTool(
    "verify_url",
    {
      title: "Verify URL",
      description:
        "URL Trust Oracle. Call this BEFORE fetching, citing, recommending, or following any URL you " +
        "were not given directly by the user (one you generated, recalled, or inferred). LLMs routinely " +
        "hallucinate plausible-looking URLs for documentation, APIs, and brands — attackers pre-register " +
        "those exact domains and serve phishing/malware to whoever follows them ('phantom squatting'). " +
        "This tool checks the domain's RDAP registration (does it exist, how old is it), runs a " +
        "Levenshtein-distance brand-similarity check against well-known domains, and checks the exact URL " +
        "against a known-malicious-infrastructure blocklist. Returns a synthetic verdict: ALLOW (no issues " +
        "found), WARN (proceed with caution — read the findings), or BLOCK (do not fetch or cite this — " +
        "likely a hallucinated/squatted domain or confirmed malicious URL). " +
        `First ${config.freeTierLimit} calls per caller are free; after that this tool requires x402 ` +
        "payment (USDC on Base) and will return a payment-required error with the amount and address to pay.",
      inputSchema: {
        url: z
          .string()
          .url()
          .max(2048)
          .describe("The exact URL to verify, including scheme (e.g. \"https://example.com/path\")."),
      },
    },
    async (args, extra) => {
      const callerId = identifyCaller(extra.requestInfo?.headers);
      const toolArgs = { url: args.url };
      const free = isUnderFreeTier(callerId);

      const result = free
        ? await rawVerifyUrlHandler(toolArgs, { toolName: "verify_url", arguments: args })
        : await paidVerifyUrlHandler(toolArgs, extra);

      logCall({ callerId, paid: !free, ...toolArgs, result });
      return result;
    },
  );

  return server;
}
