/**
 * Curated shortlist of the domains most worth impersonating — the ones an
 * LLM is likely to hallucinate a near-miss of, and an attacker is likely to
 * have pre-registered. Same honest scope note as pkg-oracle's
 * popularPackages.ts: not an exhaustive top-N-by-traffic feed, just the
 * highest-value, highest-recognition targets across the categories real
 * "phantom squatting" research (Unit 42, 2026) found attackers actually
 * exploiting — AI/dev tooling, cloud, finance/crypto, and everyday utility
 * brands a hallucinated citation would plausibly point at.
 */
export const POPULAR_DOMAINS: readonly string[] = [
  // AI / LLM providers and tooling
  "openai.com", "anthropic.com", "claude.ai", "chatgpt.com", "google.com",
  "gemini.google.com", "deepmind.com", "mistral.ai", "cohere.com",
  "huggingface.co", "perplexity.ai", "x.ai", "stability.ai", "midjourney.com",
  "github.com", "gitlab.com", "bitbucket.org", "npmjs.com", "pypi.org",
  "crates.io", "vercel.com", "netlify.com", "cloudflare.com", "fly.io",
  "render.com", "heroku.com", "digitalocean.com",
  // Cloud infrastructure
  "aws.amazon.com", "amazon.com", "azure.microsoft.com", "microsoft.com",
  "cloud.google.com", "oracle.com", "ibm.com", "salesforce.com",
  // Finance / banking
  "paypal.com", "stripe.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
  "citibank.com", "capitalone.com", "americanexpress.com", "visa.com",
  "mastercard.com", "venmo.com", "wise.com", "revolut.com", "sofi.com",
  // Crypto / web3
  "coinbase.com", "binance.com", "kraken.com", "metamask.io", "uniswap.org",
  "opensea.io", "etherscan.io", "basescan.org", "ledger.com", "trezor.io",
  "circle.com", "tether.to", "coindesk.com",
  // Social / comms
  "twitter.com", "x.com", "facebook.com", "instagram.com", "linkedin.com",
  "reddit.com", "discord.com", "slack.com", "telegram.org", "whatsapp.com",
  "youtube.com", "tiktok.com", "zoom.us",
  // Everyday utility / commerce
  "apple.com", "icloud.com", "wikipedia.org", "dropbox.com", "docusign.com",
  "adobe.com", "netflix.com", "spotify.com", "uber.com", "airbnb.com",
  "booking.com", "ebay.com", "walmart.com", "target.com", "fedex.com", "ups.com",
  "usps.com", "irs.gov", "ssa.gov",
  // Package/doc ecosystems an agent is especially likely to cite
  "readthedocs.io", "stackoverflow.com", "docs.python.org", "nodejs.org",
  "developer.mozilla.org", "npmjs.org", "rust-lang.org", "golang.org",
] as const;

const domainSet = new Set<string>(POPULAR_DOMAINS.map((d) => d.toLowerCase()));

export function isKnownPopularDomain(domain: string): boolean {
  return domainSet.has(domain.toLowerCase());
}

export function getPopularDomainList(): readonly string[] {
  return POPULAR_DOMAINS;
}
