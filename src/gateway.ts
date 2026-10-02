// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MAIGUS

import { createHash, randomUUID } from "node:crypto";
import { findCapability, validateInput, validatePolicy } from "./policy.js";
import { RateLimiter } from "./ratelimit.js";
import { ReplayCache, verifyWebBotAuth } from "./signature.js";
import {
  TIER_ORDER,
  type AuditSink,
  type Capability,
  type GatewayRequest,
  type GatewayResponse,
  type Handlers,
  type OperatorDirectory,
  type Policy,
  type Tier,
  type TierLists,
} from "./types.js";

export interface GatewayConfig {
  policy: Policy;
  operators: OperatorDirectory;
  lists: TierLists;
  handlers: Handlers;
  audit: AuditSink;
  /** Salt for hashing client addresses in the audit log. Set a random secret in production. */
  ipSalt: string;
  /**
   * Host names (with port if not default) that this gateway serves, lower-case. A request whose
   * authority is not in this list is refused (SPEC section 4.1), so a signature made for another
   * site cannot be replayed here. The list is read on every request.
   */
  allowedAuthorities: string[];
  /** Components every signature must cover. Default ["@authority"]; ["@authority","@method","@path"] is recommended. */
  requiredSignedComponents?: string[];
  baseProblemUri?: string;
  now?: () => number; // ms, for tests
}

const SUBJECT_RE = /^[A-Za-z0-9._~-]{1,128}$/;
const JSON_HEADERS = { "content-type": "application/json" };
const PROBLEM_HEADERS = { "content-type": "application/problem+json" };

export class Gateway {
  private readonly limiter = new RateLimiter();
  private readonly replay = new ReplayCache();

  constructor(private readonly cfg: GatewayConfig) {
    validatePolicy(cfg.policy);
    for (const c of cfg.policy.capabilities) {
      if (!Object.hasOwn(cfg.handlers, c.id)) throw new Error(`no handler registered for capability ${c.id}`);
    }
  }

  private nowMs(): number {
    return this.cfg.now ? this.cfg.now() : Date.now();
  }

  /** SPEC section 5: tier comes ONLY from a valid signature plus the site's lists. */
  resolveIdentity(req: GatewayRequest): { tier: Tier; operatorId: string | null; subjectId: string | null } {
    const result = verifyWebBotAuth(req, this.cfg.operators, {
      now: Math.floor(this.nowMs() / 1000),
      replayCache: this.replay,
      ...(this.cfg.requiredSignedComponents ? { requiredComponents: this.cfg.requiredSignedComponents } : {}),
    });
    if (!result.valid || !result.operatorId) return { tier: "anonymous", operatorId: null, subjectId: null };

    let tier: Tier = "anonymous";
    if (this.cfg.lists.partner.includes(result.operatorId)) tier = "partner";
    else if (this.cfg.lists.verified.includes(result.operatorId)) tier = "verified";

    // The subject identifier counts only if it is covered by the signature (SPEC section 4.3).
    let subjectId: string | null = null;
    const raw = req.headers["ai-subject-id"];
    if (raw && result.signedComponents?.includes("ai-subject-id") && SUBJECT_RE.test(raw)) subjectId = raw;

    return { tier, operatorId: result.operatorId, subjectId };
  }

  private accessible(tier: Tier): Capability[] {
    return this.cfg.policy.capabilities.filter((c) => TIER_ORDER[tier] >= TIER_ORDER[c.min_tier]);
  }

  private problem(
    status: number,
    slug: string,
    title: string,
    extra: Record<string, unknown>,
    headers: Record<string, string> = {},
  ): GatewayResponse {
    const base = this.cfg.baseProblemUri ?? "https://example.org/windi/problems";
    return {
      status,
      headers: { ...PROBLEM_HEADERS, ...headers },
      body: { type: `${base}/${slug}`, title, status, ...extra },
    };
  }

  handle(req: GatewayRequest): GatewayResponse {
    const requestId = randomUUID();
    // SPEC section 4.1: only requests addressed to one of our own hosts are examined. Checked BEFORE the
    // signature, so a refused request never touches the replay cache.
    const authorityOk = this.cfg.allowedAuthorities.includes(req.authority.toLowerCase());
    const id = authorityOk
      ? this.resolveIdentity(req)
      : { tier: "anonymous" as Tier, operatorId: null, subjectId: null };
    const clientHash = createHash("sha256")
      .update(`${this.cfg.ipSalt}|${req.remoteAddress ?? ""}`)
      .digest("hex")
      .slice(0, 16);

    const log = (
      outcome: "allowed" | "denied" | "rate_limited",
      cap: Capability | null,
      bytes: number,
      reason?: string,
    ) => {
      this.cfg.audit.write({
        timestamp: new Date(this.nowMs()).toISOString(),
        request_id: requestId,
        tier: id.tier,
        operator_id: id.operatorId,
        subject_id: id.subjectId,
        capability_id: cap ? cap.id : null, // never log request-supplied strings (log poisoning)
        domain: cap ? cap.domain : null,
        outcome,
        ...(reason ? { reason } : {}),
        bytes_returned: bytes,
        client_hash: clientHash,
      });
    };

    if (!authorityOk) {
      log("denied", null, 0, "wrong-authority");
      return this.problem(421, "wrong-authority", "This gateway does not serve that host", {});
    }

    // Public policy document.
    if (req.method === "GET" && req.path === "/.well-known/windi-policy.json") {
      const body = {
        version: this.cfg.policy.version,
        contact: this.cfg.policy.contact,
        how_to_upgrade: this.cfg.policy.how_to_upgrade,
        capabilities: this.cfg.policy.capabilities.map(({ id, description, domain, kind, min_tier, mutating, input_schema }) => ({
          id, description, domain, kind, min_tier, mutating, ...(input_schema ? { input_schema } : {}),
        })),
      };
      return { status: 200, headers: JSON_HEADERS, body };
    }

    // List what the caller's tier may use.
    if (req.method === "GET" && req.path === "/windi/capabilities") {
      const list = this.accessible(id.tier).map((c) => ({ id: c.id, description: c.description, domain: c.domain, kind: c.kind }));
      return { status: 200, headers: JSON_HEADERS, body: { your_tier: id.tier, capabilities: list } };
    }

    const m = /^\/windi\/invoke\/([a-z0-9-]{1,64})$/.exec(req.path);
    if (req.method !== "POST" || !m || !m[1]) {
      log("denied", null, 0, "not-found");
      return this.problem(404, "not-found", "No such Windi endpoint", { your_tier: id.tier });
    }

    const cap = findCapability(this.cfg.policy, m[1]);
    if (!cap) {
      log("denied", null, 0, "unknown-capability");
      return this.problem(404, "unknown-capability", "Unknown capability", {
        your_tier: id.tier,
        available_capabilities: this.accessible(id.tier).map((c) => c.id),
      });
    }

    // Tier check (refusal never leaks content, SPEC section 7).
    if (TIER_ORDER[id.tier] < TIER_ORDER[cap.min_tier]) {
      log("denied", cap, 0, "tier-too-low");
      return this.problem(403, "tier-too-low", "Access level too low for this capability", {
        your_tier: id.tier,
        required_tier: cap.min_tier,
        available_capabilities: this.accessible(id.tier).map((c) => c.id),
        how_to_upgrade: this.cfg.policy.how_to_upgrade,
        retry_after: null,
      });
    }

    // Rate limit, keyed per caller and capability.
    const limit = cap.rate_limit[id.tier];
    if (limit) {
      // Keyed per operator. The subject id must NOT be part of the key: the operator signs it, so it could
      // mint unlimited subject ids and multiply its quota (SPEC section 4.3).
      const who = id.operatorId ? `op:${id.operatorId}` : `ip:${clientHash}`;
      const wait = this.limiter.hit(`${who}|${cap.id}`, limit, this.nowMs());
      if (wait !== null) {
        log("rate_limited", cap, 0, "rate-limit");
        return this.problem(
          429,
          "rate-limited",
          "Rate limit exceeded",
          { your_tier: id.tier, retry_after: wait },
          { "retry-after": String(wait) },
        );
      }
    }

    // Input validation, unknown fields rejected.
    const input = req.body === undefined ? {} : req.body;
    const err = validateInput(cap.input_schema, input);
    if (err) {
      log("denied", cap, 0, "invalid-input");
      return this.problem(400, "invalid-input", "Invalid input", { detail: err, your_tier: id.tier });
    }

    let result: unknown;
    try {
      result = this.cfg.handlers[cap.id]!(input as Record<string, unknown>);
    } catch {
      log("denied", cap, 0, "handler-error");
      return this.problem(500, "handler-error", "The capability failed", { your_tier: id.tier });
    }
    const payload = { capability: cap.id, result };
    const bytes = Buffer.byteLength(JSON.stringify(payload));
    log("allowed", cap, bytes);
    return { status: 200, headers: JSON_HEADERS, body: payload };
  }
}
