import type { Request, Response } from "express";
import { paymentMiddleware } from "@x402/express";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { resourceServer, verifyUrlPrice, verifyUrlPriceSolana, SOLANA_NETWORK } from "./services/x402.js";
import { verifyUrl } from "./services/oracle.js";
import { config } from "./config.js";

/**
 * Plain-HTTP twin of the MCP `verify_url` tool — same reasoning as
 * pkg-oracle's httpVerify.ts: the CDP Bazaar's discovery catalog only
 * surfaces HTTP-transport resources, so this route is what makes
 * verify_url discoverable by autonomous agents without human configuration.
 * No free tier here — every call pays, same as pkg-oracle's /verify.
 */
const routes = {
  "POST /verify": {
    accepts: [
      {
        scheme: "exact",
        network: config.x402Network,
        payTo: config.recipientWallet,
        price: verifyUrlPrice,
        maxTimeoutSeconds: 60,
      },
      ...(config.solanaRecipientWallet
        ? [
            {
              scheme: "exact",
              network: SOLANA_NETWORK,
              payTo: config.solanaRecipientWallet,
              price: verifyUrlPriceSolana,
              maxTimeoutSeconds: 60,
            },
          ]
        : []),
    ],
    description:
      "Checks whether a URL/domain is safe to fetch, cite, or follow: flags phantom-squatted or " +
      "typosquatted brand domains, unregistered or brand-new domains, and known malicious infrastructure " +
      "(URLhaus). Returns an ALLOW/WARN/BLOCK verdict before your agent trusts the link.",
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
    extensions: {
      ...declareDiscoveryExtension({
        input: { url: "https://github.com" },
        inputSchema: {
          properties: {
            url: { type: "string" },
          },
          required: ["url"],
        },
        bodyType: "json",
        output: {
          example: {
            verdict: "BLOCK",
            findings: [{ code: "PHANTOM_SQUAT_SUSPECTED", message: "..." }],
          },
        },
      }),
    },
  },
};

/**
 * The x402 payment gate for POST /verify. Applied app-wide but only acts on
 * the configured route — /mcp and /health pass straight through. Facilitator
 * sync is disabled here because services/x402.ts already initialized it.
 */
export const httpVerifyPaymentGate = paymentMiddleware(routes, resourceServer, undefined, undefined, false);

/** The actual POST /verify handler, reached only after payment is verified. */
export async function handleHttpVerify(req: Request, res: Response): Promise<void> {
  const body = (req.body ?? {}) as { url?: unknown };
  const { url } = body;

  if (typeof url !== "string" || url.length === 0 || url.length > 2048) {
    res.status(400).json({ error: "'url' must be a non-empty string of at most 2048 characters." });
    return;
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    res.status(400).json({ error: `'url' is not a valid URL: "${url}"` });
    return;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    res.status(400).json({ error: `'url' must use http or https, got "${parsed.protocol}"` });
    return;
  }

  try {
    const result = await verifyUrl(url);
    console.log(
      JSON.stringify({
        event: "verify_url_call",
        transport: "http",
        time: new Date().toISOString(),
        paid: true,
        url,
        verdict: result.verdict,
      }),
    );
    res.json(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    res.status(502).json({ error: `verify_url failed while checking "${url}": ${message}` });
  }
}
