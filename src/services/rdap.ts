import axios, { AxiosError } from "axios";
import { config } from "../config.js";
import type { DomainInfo } from "../types.js";

const http = axios.create({ timeout: config.upstreamTimeoutMs });

function daysBetween(fromIso: string, toIso: string): number {
  const from = new Date(fromIso).getTime();
  const to = new Date(toIso).getTime();
  return (to - from) / (1000 * 60 * 60 * 24);
}

function notFoundResult(): DomainInfo {
  return { exists: false, registeredAt: null, expiresAt: null, ageDays: null, registrar: null };
}

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}

interface RdapVcardField extends Array<unknown> {
  0: string;
}

interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, RdapVcardField[]];
}

interface RdapDomainResponse {
  events?: RdapEvent[];
  entities?: RdapEntity[];
}

function registrarNameFrom(entities: RdapEntity[] | undefined): string | null {
  const registrar = entities?.find((e) => e.roles?.includes("registrar"));
  const vcard = registrar?.vcardArray?.[1];
  const fnField = vcard?.find((field) => field[0] === "fn");
  const name = fnField?.[3];
  return typeof name === "string" ? name : null;
}

/**
 * Looks up domain registration via RDAP — the IETF-standardized, free,
 * keyless successor to WHOIS, purpose-built for programmatic access.
 * rdap.org acts as the IANA bootstrap redirector: it 302s to whichever
 * registry actually holds the record for the domain's TLD, so this one
 * endpoint works for (almost) any TLD without us maintaining a registry map.
 */
export async function fetchDomainInfo(registrableDomain: string): Promise<DomainInfo> {
  try {
    const { data } = await http.get<RdapDomainResponse>(
      `https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`,
    );

    const registeredAt = data.events?.find((e) => e.eventAction === "registration")?.eventDate ?? null;
    const expiresAt = data.events?.find((e) => e.eventAction === "expiration")?.eventDate ?? null;
    const now = new Date().toISOString();

    return {
      exists: true,
      registeredAt,
      expiresAt,
      ageDays: registeredAt ? daysBetween(registeredAt, now) : null,
      registrar: registrarNameFrom(data.entities),
    };
  } catch (err) {
    if (err instanceof AxiosError && (err.response?.status === 404 || err.response?.status === 400)) {
      return notFoundResult();
    }
    throw new Error(`RDAP lookup failed for "${registrableDomain}": ${(err as Error).message}`);
  }
}
