import { createCdpFacilitatorClient } from "@coinbase/cdp-sdk/x402";
import { x402ResourceServer } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { ExactSvmScheme } from "@x402/svm/exact/server";
import { SOLANA_MAINNET_CAIP2, USDC_MAINNET_ADDRESS as SOLANA_USDC_MAINNET_ADDRESS } from "@x402/svm";
import { bazaarResourceServerExtension } from "@x402/extensions/bazaar";
import { config } from "../config.js";

/**
 * The single shared x402 resource server — same pattern as pkg-oracle's
 * services/x402.ts. Both the MCP payment wrapper (mcpServer.ts) and the
 * plain-HTTP payment gate (httpVerify.ts) build, verify, and settle
 * payments through this one instance.
 */
export const SOLANA_NETWORK = SOLANA_MAINNET_CAIP2 as `${string}:${string}`;

const facilitatorClient = createCdpFacilitatorClient({
  apiKeyId: config.cdpApiKeyId,
  apiKeySecret: config.cdpApiKeySecret,
});

let builder = new x402ResourceServer(facilitatorClient).register(config.x402Network, new ExactEvmScheme());

if (config.solanaRecipientWallet) {
  builder = builder.register(SOLANA_NETWORK, new ExactSvmScheme());
}

export const resourceServer = builder.registerExtension(bazaarResourceServerExtension);

await resourceServer.initialize();

/**
 * Price for one verify_url call, as an explicit AssetAmount with the
 * EIP-712 domain spelled out by hand — both details pkg-oracle only
 * discovered by testing a real signed payment (see that project's README
 * for the full story): a bare numeric string parses as Money (dollars),
 * not atomic units, and the `extra` domain fields are required for a real
 * client to construct a valid signature at all.
 */
export const verifyUrlPrice = {
  asset: config.usdcAssetAddress,
  amount: String(config.priceAtomicUsdc),
  extra: { name: "USD Coin", version: "2" },
} as const;

/** Same price on Solana — USDC is 6-decimal on both chains. */
export const verifyUrlPriceSolana = {
  asset: SOLANA_USDC_MAINNET_ADDRESS,
  amount: String(config.priceAtomicUsdc),
} as const;
