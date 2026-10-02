// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MAIGUS

import assert from "node:assert/strict";
import { test } from "node:test";
import { signRequest, validatePolicy, type GatewayRequest, type Policy } from "../src/index.js";
import { buildDemo, demoPolicy } from "../examples/demo-site.js";

const AUTHORITY = "site.test";
let clock = 1_800_000_000_000;
const now = () => clock;

function setup() {
  clock += 10_000; // fresh window for each test
  return buildDemo(now);
}

function req(capability: string, body: unknown, headers: Record<string, string> = {}, path?: string): GatewayRequest {
  return { method: "POST", path: path ?? `/windi/invoke/${capability}`, authority: AUTHORITY, headers, body, remoteAddress: "203.0.113.9" };
}

function signed(key: Parameters<typeof signRequest>[0]["privateKey"], keyid: string, capability: string, extra: Partial<Parameters<typeof signRequest>[0]> = {}) {
  return signRequest({ authority: AUTHORITY, path: `/windi/invoke/${capability}`, privateKey: key, keyid, created: Math.floor(now() / 1000), ...extra });
}

// Spec section 10 test cases -------------------------------------------------

test("1. unsigned request to a verified capability is refused with a structured refusal", () => {
  const { gateway } = setup();
  const res = gateway.handle(req("article-full", {}));
  assert.equal(res.status, 403);
  assert.equal(res.headers["content-type"], "application/problem+json");
  const b = res.body as Record<string, unknown>;
  assert.equal(b["your_tier"], "anonymous");
  assert.equal(b["required_tier"], "verified");
  assert.deepEqual(b["available_capabilities"], ["public-articles", "site-search"]);
});

test("2. valid signature, operator on verified list, read capability", () => {
  const { gateway, audit, keys } = setup();
  const res = gateway.handle(req("article-full", {}, signed(keys.verifiedKey, "verified-key-1", "article-full")));
  assert.equal(res.status, 200);
  const e = audit.entries.at(-1)!;
  assert.equal(e.tier, "verified");
  assert.equal(e.operator_id, "verified-ai");
  assert.equal(e.capability_id, "article-full");
  assert.equal(e.domain, "news");
  assert.equal(e.outcome, "allowed");
});

test("3. valid signature, operator not on any list, is anonymous", () => {
  const { gateway, audit, keys } = setup();
  const res = gateway.handle(req("catalog-query", {}, signed(keys.strangerKey, "stranger-key-1", "catalog-query")));
  assert.equal(res.status, 403);
  assert.equal(audit.entries.at(-1)!.tier, "anonymous");
  assert.equal(audit.entries.at(-1)!.operator_id, "stranger-ai"); // signature was valid, so the operator is known
});

test("4. forged User-Agent and Signature-Agent without a signature stay anonymous", () => {
  const { gateway, audit } = setup();
  const res = gateway.handle(req("article-full", {}, { "user-agent": "verified-ai/1.0", "signature-agent": "https://verified-ai.example" }));
  assert.equal(res.status, 403);
  assert.equal(audit.entries.at(-1)!.tier, "anonymous");
  assert.equal(audit.entries.at(-1)!.operator_id, null);
});

test("5. mutating capability requested by verified tier is refused", () => {
  const { gateway, keys } = setup();
  const res = gateway.handle(req("request-callback", { topic: "x" }, signed(keys.verifiedKey, "verified-key-1", "request-callback")));
  assert.equal(res.status, 403);
  assert.equal((res.body as Record<string, unknown>)["required_tier"], "partner");
});

test("5b. partner may use the mutating capability", () => {
  const { gateway, keys } = setup();
  const res = gateway.handle(req("request-callback", { topic: "x" }, signed(keys.partnerKey, "partner-key-1", "request-callback")));
  assert.equal(res.status, 200);
});

test("6. unknown input field is rejected and nothing executes", () => {
  const { gateway, audit } = setup();
  const res = gateway.handle(req("site-search", { q: "hello", admin: true }));
  assert.equal(res.status, 400);
  assert.equal(audit.entries.at(-1)!.reason, "invalid-input");
});

test("7. rate limit exceeded returns 429 with retry_after", () => {
  const { gateway } = setup();
  const limit = demoPolicy.capabilities.find((c) => c.id === "public-articles")!.rate_limit.anonymous!.max;
  for (let i = 0; i < limit; i++) assert.equal(gateway.handle(req("public-articles", {})).status, 200);
  const res = gateway.handle(req("public-articles", {}));
  assert.equal(res.status, 429);
  assert.ok(Number((res.body as Record<string, unknown>)["retry_after"]) >= 1);
  assert.ok(res.headers["retry-after"]);
});

// Additional security tests ---------------------------------------------------

test("tampered path: signature for one endpoint cannot be replayed on another", () => {
  const { gateway, keys } = setup();
  const headers = signed(keys.verifiedKey, "verified-key-1", "public-articles");
  const res = gateway.handle(req("article-full", {}, headers)); // signed for public-articles
  assert.equal(res.status, 403);
});

test("identical signature is rejected as replay", () => {
  const { gateway, audit, keys } = setup();
  const headers = signed(keys.verifiedKey, "verified-key-1", "article-full");
  assert.equal(gateway.handle(req("article-full", {}, headers)).status, 200);
  assert.equal(gateway.handle(req("article-full", {}, headers)).status, 403);
  assert.equal(audit.entries.at(-1)!.tier, "anonymous");
});

test("expired signature is treated as anonymous", () => {
  const { gateway, keys } = setup();
  const headers = signed(keys.verifiedKey, "verified-key-1", "article-full", { created: Math.floor(now() / 1000) - 3600, ttlSeconds: 60 });
  assert.equal(gateway.handle(req("article-full", {}, headers)).status, 403);
});

test("signature missing the required @path component is rejected", () => {
  const { gateway, keys } = setup();
  const headers = signed(keys.verifiedKey, "verified-key-1", "article-full", { bindRequest: false });
  assert.equal(gateway.handle(req("article-full", {}, headers)).status, 403);
});

test("signature made with an unknown key is anonymous", async () => {
  const { gateway } = setup();
  const { generateKeyPairSync } = await import("node:crypto");
  const rogue = generateKeyPairSync("ed25519").privateKey;
  const headers = signed(rogue, "verified-key-1", "article-full"); // claims a real keyid, wrong private key
  assert.equal(gateway.handle(req("article-full", {}, headers)).status, 403);
});

test("subject id is used only when covered by the signature", () => {
  const { gateway, audit, keys } = setup();
  const good = signed(keys.verifiedKey, "verified-key-1", "article-full", { subjectId: "user-abc" });
  gateway.handle(req("article-full", {}, good));
  assert.equal(audit.entries.at(-1)!.subject_id, "user-abc");

  const unsignedSubject = { ...signed(keys.verifiedKey, "verified-key-1", "article-full"), "ai-subject-id": "someone-else" };
  gateway.handle(req("article-full", {}, unsignedSubject));
  assert.equal(audit.entries.at(-1)!.subject_id, null);
});

test("audit log never records request-supplied strings", () => {
  const { gateway, audit } = setup();
  gateway.handle(req("x", {}, {}, "/windi/invoke/evil\nINJECTED-LINE"));
  gateway.handle(req("no-such-capability", {}));
  for (const e of audit.entries) {
    assert.equal(e.capability_id, null);
    assert.ok(!JSON.stringify(e).includes("INJECTED"));
    assert.ok(!JSON.stringify(e).includes("203.0.113.9")); // raw IP is hashed
  }
});

test("policy: a mutating capability may not allow the anonymous tier", () => {
  const bad: Policy = { ...demoPolicy, capabilities: [{ ...demoPolicy.capabilities[0]!, id: "bad", mutating: true, kind: "action" }] };
  assert.throws(() => validatePolicy(bad), /MUST NOT allow the anonymous tier/);
});

test("public policy document exposes capabilities but no rate limits or handlers", () => {
  const { gateway } = setup();
  const res = gateway.handle({ method: "GET", path: "/.well-known/windi-policy.json", authority: AUTHORITY, headers: {} });
  assert.equal(res.status, 200);
  const text = JSON.stringify(res.body);
  assert.ok(text.includes("request-callback"));
  assert.ok(!text.includes("rate_limit"));
});

// Regression tests for the review fixes -----------------------------------------

test("8. inherited property names are not accepted as input fields", () => {
  const { gateway, audit } = setup();
  const body = JSON.parse('{"q":"hi","constructor":1,"toString":2,"__proto__":3}');
  const res = gateway.handle(req("site-search", body));
  assert.equal(res.status, 400);
  assert.equal(audit.entries.at(-1)!.reason, "invalid-input");
});

test("9. a signature made for another host is refused, and does not burn the replay cache", () => {
  const { gateway, audit, keys } = setup();
  const other = signRequest({ authority: "site-a.test", path: "/windi/invoke/article-full", privateKey: keys.verifiedKey, keyid: "verified-key-1", created: Math.floor(now() / 1000) });
  const res = gateway.handle({ method: "POST", path: "/windi/invoke/article-full", authority: "site-a.test", headers: other, body: {}, remoteAddress: "203.0.113.9" });
  assert.equal(res.status, 421);
  assert.equal(audit.entries.at(-1)!.reason, "wrong-authority");
  assert.equal(audit.entries.at(-1)!.tier, "anonymous");
  // The same signature, if it was really meant for this site, still works once.
  const mine = signed(keys.verifiedKey, "verified-key-1", "article-full");
  assert.equal(gateway.handle(req("article-full", {}, mine)).status, 200);
});

test("9b. host comparison is case-insensitive", () => {
  const { gateway, keys } = setup();
  const h = signed(keys.verifiedKey, "verified-key-1", "article-full");
  const res = gateway.handle({ ...req("article-full", {}, h), authority: "SITE.test" });
  assert.equal(res.status, 200);
});

test("10. rotating signed subject ids does not multiply an operator's quota", () => {
  const { gateway, keys } = setup();
  const max = demoPolicy.capabilities.find((c) => c.id === "article-full")!.rate_limit.verified!.max;
  let allowed = 0;
  for (let i = 0; i < max + 20; i++) {
    const h = signed(keys.verifiedKey, "verified-key-1", "article-full", { subjectId: `user-${i}` });
    if (gateway.handle(req("article-full", {}, h)).status === 200) allowed++;
  }
  assert.equal(allowed, max);
});
