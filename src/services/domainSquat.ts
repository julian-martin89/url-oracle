import levenshtein from "fast-levenshtein";
import { config } from "../config.js";
import { getPopularDomainList, isKnownPopularDomain } from "./popularDomains.js";
import type { BrandSimilarityResult } from "../types.js";

/**
 * Compares `registrableDomain` against the curated brand-domain shortlist
 * and flags near-miss spellings — same technique as pkg-oracle's
 * typosquat.ts, applied to domains instead of package names. A distance of
 * 0 means the domain IS a known brand (not a squat candidate itself).
 *
 * `ageDays` is `null` when RDAP has no registration record at all (the
 * strongest possible signal — the domain a model hallucinated hasn't even
 * been claimed yet) and is treated as "as suspicious as day zero" here.
 */
export function checkDomainSquat(registrableDomain: string, ageDays: number | null): BrandSimilarityResult {
  const lower = registrableDomain.toLowerCase();

  if (isKnownPopularDomain(lower)) {
    return { suspected: false, nearestBrandDomain: null, distance: null, redFlag: false };
  }

  let bestDistance = Number.POSITIVE_INFINITY;
  let bestMatch: string | null = null;

  for (const brand of getPopularDomainList()) {
    if (Math.abs(brand.length - lower.length) > config.brandSquatMaxDistance) continue;

    const distance = levenshtein.get(lower, brand.toLowerCase());
    if (distance < bestDistance) {
      bestDistance = distance;
      bestMatch = brand;
    }
    if (bestDistance === 1) break;
  }

  const suspected = bestMatch !== null && bestDistance <= config.brandSquatMaxDistance;
  const isNew = ageDays === null || ageDays < config.newDomainThresholdDays;
  const redFlag = suspected && isNew;

  return {
    suspected,
    nearestBrandDomain: suspected ? bestMatch : null,
    distance: suspected ? bestDistance : null,
    redFlag,
  };
}
