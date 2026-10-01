// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MAIGUS

import { createHash, createPublicKey, timingSafeEqual, verify, KeyObject } from "node:crypto";
import type { OperatorDirectory } from "./types.js";

/**
 * Verification of Web Bot Auth style signatures (RFC 9421 HTTP Message Signatures).
 *
 * Scope of this reference implementation (see README "Limitations"):
 *  - only the FIRST signature in Signature-Input is examined;
 *  - only Ed25519;
 *  - public keys come from a LOCAL operator directory, not fetched from Signature-Agent
 *    (fetching remote key directories needs SSRF protections that are not implemented yet);
 *  - request bodies can be bound to signatures via the Content-Digest component (RFC 9530 / RFC 9421).
 */

export interface SignatureResult {
  valid: boolean;
  reason?: string;
  operatorId?: string;
  keyid?: string;
  signedComponents?: string[];
}

export interface VerifyOptions {
  now?: number; // seconds since epoch
  clockSkewSeconds?: number;
  maxLifetimeSeconds?: number;
  replayCache?: ReplayCache;
  /** Components that MUST be signed. Default: ["@authority"]. Add "@path" and "@method" to bind a signature to one endpoint. */
  requiredComponents?: string[];
  /** If true, require that "content-digest" is covered by the signature and matches the body. */
  requireContentDigest?: boolean;
}

/** Serializes a request body to a Buffer for Content-Digest computation. */
export function serializeBody(body: unknown): Buffer {
  if (body === undefined || body === null) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === "string") return Buffer.from(body, "utf8");
  return Buffer.from(JSON.stringify(body), "utf8");
}

function safeCompareBase64(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/**
 * Computes an RFC 9530 Content-Digest header value for a request body.
 * Default algorithm is sha-256.
 *
 * Example: `sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:`
 */
export function computeContentDigest(
  body: unknown,
  algorithm: "sha-256" | "sha-512" = "sha-256",
): string {
  const bytes = serializeBody(body);
  const hashAlg = algorithm === "sha-512" ? "sha512" : "sha256";
  const b64 = createHash(hashAlg).update(bytes).digest("base64");
  return `${algorithm}=:${b64}:`;
}

/**
 * Parses an RFC 9530 Content-Digest header into an algorithm -> base64 digest map.
 */
export function parseContentDigest(header: string): Map<string, string> {
  const digests = new Map<string, string>();
  const re = /(?:^|\s*,\s*)([a-zA-Z0-9_-]+)=:?([A-Za-z0-9+/=]+):?/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(header)) !== null) {
    if (match[1] && match[2]) {
      digests.set(match[1].toLowerCase(), match[2]);
    }
  }
  return digests;
}

/**
 * Verifies that the Content-Digest header matches the digest of the request body.
 * Supports sha-256 and sha-512 algorithms.
 */
export function verifyContentDigest(header: string, body: unknown): boolean {
  const digests = parseContentDigest(header);
  if (digests.size === 0) return false;

  const bytes = serializeBody(body);
  let checkedAtLeastOne = false;

  if (digests.has("sha-256")) {
    const expected = digests.get("sha-256")!;
    const actual = createHash("sha256").update(bytes).digest("base64");
    if (!safeCompareBase64(expected, actual)) return false;
    checkedAtLeastOne = true;
  }

  if (digests.has("sha-512")) {
    const expected = digests.get("sha-512")!;
    const actual = createHash("sha512").update(bytes).digest("base64");
    if (!safeCompareBase64(expected, actual)) return false;
    checkedAtLeastOne = true;
  }

  return checkedAtLeastOne;
}

export class ReplayCache {
  private seen = new Map<string, number>();
  /** Returns true if this signature was already seen (replay). */
  check(signatureB64: string, expires: number, now: number): boolean {
    for (const [k, exp] of this.seen) if (exp < now) this.seen.delete(k);
    const key = createHash("sha256").update(signatureB64).digest("hex");
    if (this.seen.has(key)) return true;
    this.seen.set(key, expires);
    return false;
  }
}

interface ParsedInput {
  label: string;
  components: string[];
  paramsRaw: string; // everything after the closing parenthesis, e.g. ;created=1;expires=2
  innerList: string; // e.g. ("@authority" "signature-agent")
  params: Record<string, string | number>;
}

export function parseSignatureInput(header: string): ParsedInput | null {
  const first = header.split(/,(?=\s*[a-zA-Z0-9_-]+=\()/)[0]?.trim();
  if (!first) return null;
  const m = /^([a-zA-Z0-9_-]+)=(\(([^)]*)\))(.*)$/.exec(first);
  if (!m) return null;
  const [, label, innerList, inner, paramsRaw] = m as unknown as [string, string, string, string, string];
  const components: string[] = [];
  for (const tok of inner.trim().split(/\s+/).filter(Boolean)) {
    const q = /^"([^"]+)"$/.exec(tok);
    if (!q || !q[1]) return null;
    components.push(q[1]);
  }
  const params: Record<string, string | number> = {};
  for (const part of paramsRaw.split(";").filter((p) => p.length > 0)) {
    const kv = /^([a-zA-Z0-9_*-]+)=(.+)$/.exec(part);
    if (!kv || !kv[1] || kv[2] === undefined) return null;
    const v = kv[2];
    const str = /^"(.*)"$/.exec(v);
    if (str && str[1] !== undefined) params[kv[1]] = str[1];
    else if (/^-?\d+$/.test(v)) params[kv[1]] = Number(v);
    else return null;
  }
  return { label, components, paramsRaw, innerList, params };
}

function extractSignature(header: string, label: string): Buffer | null {
  const re = new RegExp(`(?:^|,)\\s*${label}=:([A-Za-z0-9+/=]+):`);
  const m = re.exec(header);
  return m && m[1] ? Buffer.from(m[1], "base64") : null;
}

export function buildSignatureBase(
  components: string[],
  req: { authority: string; method: string; path: string; headers: Record<string, string> },
  signatureParamsValue: string,
): string | null {
  const lines: string[] = [];
  for (const c of components) {
    let value: string | undefined;
    if (c === "@authority") value = req.authority.toLowerCase();
    else if (c === "@method") value = req.method.toUpperCase();
    else if (c === "@path") value = req.path;
    else if (c.startsWith("@")) return null; // unsupported derived component
    else value = req.headers[c.toLowerCase()]?.trim();
    if (value === undefined) return null;
    lines.push(`"${c}": ${value}`);
  }
  lines.push(`"@signature-params": ${signatureParamsValue}`);
  return lines.join("\n");
}

export function verifyWebBotAuth(
  req: { authority: string; method: string; path: string; headers: Record<string, string>; body?: unknown },
  directory: OperatorDirectory,
  opts: VerifyOptions = {},
): SignatureResult {
  const sigInput = req.headers["signature-input"];
  const sigHeader = req.headers["signature"];
  if (!sigInput || !sigHeader) return { valid: false, reason: "no-signature" };

  const parsed = parseSignatureInput(sigInput);
  if (!parsed) return { valid: false, reason: "malformed-signature-input" };

  const { params, components } = parsed;
  if (params["tag"] !== "web-bot-auth") return { valid: false, reason: "wrong-tag" };
  if (params["alg"] !== undefined && params["alg"] !== "ed25519") return { valid: false, reason: "unsupported-alg" };
  const keyid = params["keyid"];
  const created = params["created"];
  const expires = params["expires"];
  if (typeof keyid !== "string" || typeof created !== "number" || typeof expires !== "number") {
    return { valid: false, reason: "missing-params" };
  }
  for (const required of opts.requiredComponents ?? ["@authority"]) {
    if (!components.includes(required)) return { valid: false, reason: `component-not-signed:${required}` };
  }
  if (opts.requireContentDigest && !components.includes("content-digest")) {
    return { valid: false, reason: "component-not-signed:content-digest" };
  }
  if (components.includes("content-digest")) {
    const digestHeader = req.headers["content-digest"];
    if (!digestHeader) return { valid: false, reason: "missing-content-digest" };
    if (!verifyContentDigest(digestHeader, req.body)) {
      return { valid: false, reason: "content-digest-mismatch" };
    }
  }

  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const skew = opts.clockSkewSeconds ?? 30;
  const maxLife = opts.maxLifetimeSeconds ?? 600;
  if (created > now + skew) return { valid: false, reason: "created-in-future" };
  if (expires < now - skew) return { valid: false, reason: "expired" };
  if (expires - created > maxLife) return { valid: false, reason: "lifetime-too-long" };

  // Find the key in the local directory.
  let key: KeyObject | null = null;
  let operatorId: string | undefined;
  for (const [op, entry] of Object.entries(directory.operators)) {
    const k = entry.keys[keyid];
    if (k) {
      try {
        key = createPublicKey({ key: k.jwk, format: "jwk" });
        operatorId = op;
      } catch {
        return { valid: false, reason: "bad-key" };
      }
      break;
    }
  }
  if (!key || !operatorId) return { valid: false, reason: "unknown-key" };

  const sig = extractSignature(sigHeader, parsed.label);
  if (!sig) return { valid: false, reason: "malformed-signature" };

  const paramsValue = `${parsed.innerList}${parsed.paramsRaw}`;
  const base = buildSignatureBase(components, req, paramsValue);
  if (base === null) return { valid: false, reason: "cannot-build-base" };

  let ok = false;
  try {
    ok = verify(null, Buffer.from(base), key, sig);
  } catch {
    ok = false;
  }
  if (!ok) return { valid: false, reason: "bad-signature" };

  if (opts.replayCache) {
    const b64 = sig.toString("base64");
    if (opts.replayCache.check(b64, expires, now)) return { valid: false, reason: "replay" };
  }
  return { valid: true, operatorId, keyid, signedComponents: components };
}
