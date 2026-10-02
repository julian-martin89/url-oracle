import "dotenv/config";
import { validateSvmAddress } from "@x402/svm";

/**
 * Centralized, validated environment configuration for url-oracle.
 * Mirrors pkg-oracle's config.ts — see that project for the reasoning
 * behind failing loudly at boot instead of silently misconfiguring a
 * live request.
 */

function requireEnv(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (value === undefined || value.length === 0) {
    throw new Error(
      `[config] Missing required environment variable: ${name}. ` +
        `Copy .env.example to .env and fill it in.`,
    );
  }
  return value;
}

function optionalIntEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error(`[config] ${name} must be a non-negative integer, got: "${raw}"`);
  }
  return parsed;
}

const NODE_ENV = process.env.NODE_ENV ?? "development";
const isProduction = NODE_ENV === "production";

const RECIPIENT_WALLET = requireEnv(
  "RECIPIENT_WALLET",
  isProduction ? undefined : "0x000000000000000000000000000000000000dEaD",
);

if (!/^0x[a-fA-F0-9]{40}$/.test(RECIPIENT_WALLET)) {
  throw new Error(
    `[config] RECIPIENT_WALLET must be a valid EVM address (0x + 40 hex chars), got: "${RECIPIENT_WALLET}"`,
  );
}

const SOLANA_RECIPIENT_WALLET_RAW = process.env.SOLANA_RECIPIENT_WALLET?.trim();
const SOLANA_RECIPIENT_WALLET =
  SOLANA_RECIPIENT_WALLET_RAW && SOLANA_RECIPIENT_WALLET_RAW.length > 0 ? SOLANA_RECIPIENT_WALLET_RAW : undefined;

if (SOLANA_RECIPIENT_WALLET && !validateSvmAddress(SOLANA_RECIPIENT_WALLET)) {
  throw new Error(
    `[config] SOLANA_RECIPIENT_WALLET must be a valid base58 Solana address, got: "${SOLANA_RECIPIENT_WALLET}"`,
  );
}

const CDP_API_KEY_ID = requireEnv("CDP_API_KEY_ID");
const CDP_API_KEY_SECRET = requireEnv("CDP_API_KEY_SECRET");

// URLhaus (abuse.ch) now requires a free Auth-Key as of mid-2025. Optional —
// when unset, the threat-intel check degrades to "not queried" rather than
// failing the whole call (same pattern as OSV.dev in pkg-oracle).
const URLHAUS_AUTH_KEY = process.env.URLHAUS_AUTH_KEY?.trim() || undefined;

export const config = {
  nodeEnv: NODE_ENV,
  isProduction,
  port: optionalIntEnv("PORT", 3000),

  recipientWallet: RECIPIENT_WALLET,
  solanaRecipientWallet: SOLANA_RECIPIENT_WALLET,

  cdpApiKeyId: CDP_API_KEY_ID,
  cdpApiKeySecret: CDP_API_KEY_SECRET,

  urlhausAuthKey: URLHAUS_AUTH_KEY,

  /** CAIP-2 network identifier for Base mainnet. */
  x402Network: "eip155:8453",

  /** Native USDC on Base mainnet — Circle-issued FiatTokenProxy. */
  usdcAssetAddress: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",

  /** Price per `verify_url` call once the free tier is exhausted, in atomic USDC units (6 decimals). */
  priceAtomicUsdc: optionalIntEnv("PRICE_ATOMIC_USDC", 3_000), // 3000 / 1e6 = $0.003

  freeTierLimit: optionalIntEnv("FREE_TIER_LIMIT", 5),
  rateLimitCacheMaxEntries: optionalIntEnv("RATE_LIMIT_CACHE_MAX_ENTRIES", 50_000),
  rateLimitCacheTtlMs: optionalIntEnv("RATE_LIMIT_CACHE_TTL_MS", 1000 * 60 * 60 * 24), // 24h

  /** Outbound HTTP timeout for upstream RDAP/threat-intel calls, in ms. */
  upstreamTimeoutMs: optionalIntEnv("UPSTREAM_TIMEOUT_MS", 8_000),

  /** Age (days) under which a brand-adjacent domain is treated as suspicious. */
  newDomainThresholdDays: optionalIntEnv("NEW_DOMAIN_THRESHOLD_DAYS", 30),

  /** Max Levenshtein distance to a known brand domain that still counts as a squat signal. */
  brandSquatMaxDistance: optionalIntEnv("BRAND_SQUAT_MAX_DISTANCE", 2),
} as const;
