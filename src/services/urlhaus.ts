import axios from "axios";
import { config } from "../config.js";
import type { ThreatIntelResult } from "../types.js";

const http = axios.create({ timeout: config.upstreamTimeoutMs });

interface UrlhausResponse {
  query_status: "ok" | "http_post_expected" | "no_results" | "invalid_url";
  threat?: string;
  url_status?: string;
}

const notQueried: ThreatIntelResult = { queried: false, flagged: false, threatType: null, source: null };
const noMatch: ThreatIntelResult = { queried: true, flagged: false, threatType: null, source: null };

/**
 * Checks the exact URL against URLhaus (abuse.ch) — a community-maintained
 * feed of confirmed malware/phishing infrastructure. Requires a free
 * Auth-Key (abuse.ch mandated this mid-2025; see README). Degrades to
 * "not queried" rather than failing the whole call when no key is
 * configured or the service is unreachable — the RDAP + brand-similarity
 * signals still stand on their own.
 */
export async function queryUrlhaus(url: string): Promise<ThreatIntelResult> {
  if (!config.urlhausAuthKey) return notQueried;

  try {
    const { data } = await http.post<UrlhausResponse>(
      "https://urlhaus-api.abuse.ch/v1/url/",
      new URLSearchParams({ url }),
      { headers: { "Auth-Key": config.urlhausAuthKey } },
    );

    if (data.query_status === "no_results") return noMatch;
    if (data.query_status !== "ok") return notQueried;

    return {
      queried: true,
      flagged: true,
      threatType: data.threat ?? "unknown",
      source: "urlhaus.abuse.ch",
    };
  } catch {
    return notQueried;
  }
}
