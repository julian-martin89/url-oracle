/** Final synthetic verdict handed back to the calling agent. */
export type Verdict = "ALLOW" | "WARN" | "BLOCK";

export interface DomainInfo {
  /** Whether RDAP has any registration record for this domain at all. */
  exists: boolean;
  /** ISO-8601 registration (creation) timestamp, if known. */
  registeredAt: string | null;
  /** ISO-8601 expiration timestamp, if known. */
  expiresAt: string | null;
  /** Age in days since registration (fractional). Null if unknown or unregistered. */
  ageDays: number | null;
  /** Registrar name, if RDAP reports one. */
  registrar: string | null;
}

export interface ThreatIntelResult {
  /** False if the lookup itself failed (service unreachable) — degrades confidence, not a verdict signal on its own. */
  queried: boolean;
  /** True if this host/URL is on a known malicious-infrastructure blocklist. */
  flagged: boolean;
  /** Threat type reported by the source, if flagged (e.g. "malware_download", "phishing"). */
  threatType: string | null;
  /** Which feed supplied the match. */
  source: string | null;
}

export interface BrandSimilarityResult {
  suspected: boolean;
  nearestBrandDomain: string | null;
  distance: number | null;
  /** True only when the distance signal AND the domain-age signal both fire. */
  redFlag: boolean;
}

export interface OracleFinding {
  code: string;
  message: string;
}

export interface UrlOracleResult {
  url: string;
  hostname: string;
  /** Registrable domain (eTLD+1) — what age/brand-similarity checks actually run against. */
  registrableDomain: string | null;
  verdict: Verdict;
  findings: OracleFinding[];
  domain: DomainInfo;
  threatIntel: ThreatIntelResult;
  brandSimilarity: BrandSimilarityResult;
  checkedAt: string;
}
