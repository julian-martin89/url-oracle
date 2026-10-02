import { getDomain, getHostname } from "tldts";
import { config } from "../config.js";
import { fetchDomainInfo } from "./rdap.js";
import { queryUrlhaus } from "./urlhaus.js";
import { checkDomainSquat } from "./domainSquat.js";
import type { OracleFinding, UrlOracleResult, Verdict } from "../types.js";

/**
 * The URL Trust Oracle: runs every check in parallel and folds the results
 * into a single synthetic verdict — pkg-oracle's exact pattern, applied to
 * "phantom squatting" (LLM-hallucinated URLs/domains attackers pre-register
 * for phishing) instead of hallucinated package names.
 *
 * Verdict precedence (first match wins):
 *   1. BLOCK — the URL is on a known malicious-infrastructure blocklist
 *      (URLhaus). The strongest possible signal — this isn't a plausible
 *      hallucination target, it's a confirmed active threat.
 *   2. BLOCK — the domain is a near-miss of a well-known brand AND is
 *      unregistered or brand-new — the canonical phantom-squat pattern: a
 *      name close enough to fool a reader (or an LLM citing it), claimed
 *      (or claimable) recently enough that it can't have earned trust.
 *   3. WARN  — the domain isn't registered at all but isn't brand-similar
 *      either (a dead/broken link — still don't treat it as authoritative).
 *   4. WARN  — brand-name similarity exists but the domain is old enough
 *      that this is plausibly coincidental.
 *   5. WARN  — the domain is registered and brand-safe, but very new.
 *   6. ALLOW — nothing above fired.
 */
export async function verifyUrl(rawUrl: string): Promise<UrlOracleResult> {
  const parsed = new URL(rawUrl);
  const hostname = getHostname(parsed.hostname) ?? parsed.hostname;
  const registrableDomain = getDomain(parsed.hostname);

  const [domain, threatIntel] = await Promise.all([
    registrableDomain ? fetchDomainInfo(registrableDomain) : Promise.resolve(null),
    queryUrlhaus(rawUrl),
  ]);

  const effectiveDomainInfo = domain ?? { exists: false, registeredAt: null, expiresAt: null, ageDays: null, registrar: null };
  const brandSimilarity = registrableDomain
    ? checkDomainSquat(registrableDomain, effectiveDomainInfo.ageDays)
    : { suspected: false, nearestBrandDomain: null, distance: null, redFlag: false };

  const findings: OracleFinding[] = [];
  let verdict: Verdict = "ALLOW";

  const escalate = (next: Verdict) => {
    const order: Record<Verdict, number> = { ALLOW: 0, WARN: 1, BLOCK: 2 };
    if (order[next] > order[verdict]) verdict = next;
  };

  if (threatIntel.queried && threatIntel.flagged) {
    escalate("BLOCK");
    findings.push({
      code: "MALICIOUS_URL_CONFIRMED",
      message:
        `This exact URL is on a known malicious-infrastructure blocklist (${threatIntel.source}), ` +
        `threat type "${threatIntel.threatType}". Do not fetch, cite, or follow it.`,
    });
  } else if (!threatIntel.queried) {
    findings.push({
      code: "THREAT_INTEL_UNAVAILABLE",
      message: "Could not check URLhaus for known malicious infrastructure — verdict is based on the remaining signals only.",
    });
  }

  if (brandSimilarity.redFlag) {
    escalate("BLOCK");
    findings.push({
      code: "PHANTOM_SQUAT_SUSPECTED",
      message:
        `"${registrableDomain}" is a Levenshtein distance of ${brandSimilarity.distance} from the well-known domain ` +
        `"${brandSimilarity.nearestBrandDomain}" and is ${
          effectiveDomainInfo.ageDays === null
            ? "not yet registered"
            : `only ${Math.round(effectiveDomainInfo.ageDays)} day(s) old`
        }. This is the exact pattern of phantom squatting: an LLM hallucinates a near-miss of a trusted ` +
        `brand's domain, and an attacker registers it to catch the traffic. Do not treat this as the real site.`,
    });
  } else if (brandSimilarity.suspected) {
    escalate("WARN");
    findings.push({
      code: "BRAND_NAME_SIMILARITY",
      message:
        `"${registrableDomain}" is close (distance ${brandSimilarity.distance}) to the well-known domain ` +
        `"${brandSimilarity.nearestBrandDomain}". The domain is old enough that this is plausibly coincidental, ` +
        `but confirm this is really the site you meant to reference.`,
    });
  }

  if (!effectiveDomainInfo.exists && !brandSimilarity.redFlag) {
    escalate("WARN");
    findings.push({
      code: "DOMAIN_NOT_REGISTERED",
      message:
        `"${registrableDomain ?? hostname}" has no RDAP registration record — this domain does not currently ` +
        `exist. It may be a dead link, a typo, or a hallucinated URL nobody has claimed yet. Do not treat it as ` +
        `a live, authoritative source.`,
    });
  } else if (
    effectiveDomainInfo.exists &&
    !brandSimilarity.redFlag &&
    !brandSimilarity.suspected &&
    effectiveDomainInfo.ageDays !== null &&
    effectiveDomainInfo.ageDays < config.newDomainThresholdDays
  ) {
    escalate("WARN");
    findings.push({
      code: "NEW_DOMAIN",
      message: `Registered only ${Math.round(effectiveDomainInfo.ageDays)} day(s) ago. New domains haven't had ` +
        `time to accumulate reputation or show up on blocklists even if malicious — treat with extra caution.`,
    });
  }

  if (verdict === "ALLOW" && findings.filter((f) => f.code !== "THREAT_INTEL_UNAVAILABLE").length === 0) {
    findings.push({
      code: "NO_ISSUES_FOUND",
      message: `No red flags found. Domain age: ${
        effectiveDomainInfo.ageDays !== null ? `${Math.round(effectiveDomainInfo.ageDays)} day(s)` : "unknown"
      }. Not on any known threat blocklist. No brand-similarity signal.`,
    });
  }

  return {
    url: rawUrl,
    hostname,
    registrableDomain,
    verdict,
    findings,
    domain: effectiveDomainInfo,
    threatIntel,
    brandSimilarity,
    checkedAt: new Date().toISOString(),
  };
}
