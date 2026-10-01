// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MAIGUS

import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { Gateway, MemoryAudit, type Handlers, type OperatorDirectory, type Policy, type TierLists } from "../src/index.js";

/** A fictional site with five capabilities. Replace handlers with your real data. */
export const demoPolicy: Policy = {
  version: "0.1",
  contact: "mailto:ai-access@example.org",
  how_to_upgrade: "https://example.org/ai-access",
  capabilities: [
    { id: "public-articles", description: "Titles and summaries of public articles", domain: "news", kind: "read", min_tier: "anonymous", mutating: false, rate_limit: { anonymous: { max: 5, windowSeconds: 60 }, verified: { max: 60, windowSeconds: 60 }, partner: { max: 300, windowSeconds: 60 } } },
    { id: "site-search", description: "Search public pages by keyword", domain: "search", kind: "query", min_tier: "anonymous", mutating: false, rate_limit: { anonymous: { max: 3, windowSeconds: 60 }, verified: { max: 30, windowSeconds: 60 } }, input_schema: { type: "object", properties: { q: { type: "string", maxLength: 100 }, limit: { type: "number" } }, required: ["q"], additionalProperties: false } },
    { id: "article-full", description: "Full text of public articles", domain: "news", kind: "read", min_tier: "verified", mutating: false, rate_limit: { verified: { max: 30, windowSeconds: 60 }, partner: { max: 300, windowSeconds: 60 } } },
    { id: "catalog-query", description: "Product catalog by category", domain: "catalog", kind: "query", min_tier: "verified", mutating: false, rate_limit: { verified: { max: 30, windowSeconds: 60 }, partner: { max: 300, windowSeconds: 60 } }, input_schema: { type: "object", properties: { category: { type: "string", maxLength: 50 } }, additionalProperties: false } },
    { id: "request-callback", description: "Ask the site team to contact a person (changes state)", domain: "support", kind: "action", min_tier: "partner", mutating: true, rate_limit: { partner: { max: 10, windowSeconds: 3600 } }, input_schema: { type: "object", properties: { topic: { type: "string", maxLength: 200 } }, required: ["topic"], additionalProperties: false } },
  ],
};

export const demoHandlers: Handlers = {
  "public-articles": () => [{ title: "Welcome", summary: "A public article." }],
  "site-search": (i) => ({ query: i["q"], hits: [] }),
  "article-full": () => ({ title: "Welcome", body: "Full text of the article." }),
  "catalog-query": (i) => ({ category: i["category"] ?? "all", items: ["item-1", "item-2"] }),
  "request-callback": (i) => ({ queued: true, topic: i["topic"] }),
};

export interface DemoKeys {
  verifiedKey: KeyObject;
  partnerKey: KeyObject;
  strangerKey: KeyObject; // valid operator key, but NOT on any list
}

export function buildDemo(now?: () => number) {
  const make = () => generateKeyPairSync("ed25519");
  const v = make(), p = make(), s = make();
  const jwk = (k: { publicKey: KeyObject }) => k.publicKey.export({ format: "jwk" }) as { kty: "OKP"; crv: "Ed25519"; x: string };
  const operators: OperatorDirectory = {
    operators: {
      "verified-ai": { keys: { "verified-key-1": { jwk: jwk(v) } } },
      "partner-ai": { keys: { "partner-key-1": { jwk: jwk(p) } } },
      "stranger-ai": { keys: { "stranger-key-1": { jwk: jwk(s) } } },
    },
  };
  const lists: TierLists = { verified: ["verified-ai"], partner: ["partner-ai"] };
  const audit = new MemoryAudit();
  const gateway = new Gateway({ policy: demoPolicy, operators, lists, handlers: demoHandlers, audit, ipSalt: "demo-salt-change-me", requiredSignedComponents: ["@authority", "@method", "@path"], ...(now ? { now } : {}) });
  const keys: DemoKeys = { verifiedKey: v.privateKey, partnerKey: p.privateKey, strangerKey: s.privateKey };
  return { gateway, audit, keys, operators };
}
