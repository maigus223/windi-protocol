// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MAIGUS

import type { AddressInfo } from "node:net";
import { createGatewayServer, signRequest } from "../src/index.js";
import { buildDemo } from "./demo-site.js";

/** Starts the demo site and lets three simulated AIs call it. Run with: npm run demo */
const allowedAuthorities: string[] = [];
const { gateway, audit, keys } = buildDemo(undefined, allowedAuthorities);
const server = createGatewayServer(gateway);

await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
const port = (server.address() as AddressInfo).port;
const authority = `127.0.0.1:${port}`;
allowedAuthorities.push(authority);

async function call(who: string, capability: string, body: unknown, signing?: { key: typeof keys.verifiedKey; keyid: string }) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (signing) {
    Object.assign(headers, signRequest({ authority, path: `/windi/invoke/${capability}`, privateKey: signing.key, keyid: signing.keyid, agentUrl: "https://agent.example", subjectId: "user-7f3a" }));
  }
  const res = await fetch(`http://${authority}/windi/invoke/${capability}`, { method: "POST", headers, body: JSON.stringify(body) });
  const json = (await res.json()) as Record<string, unknown>;
  const summary = res.status === 200 ? "OK" : `${json["title"]} (your_tier=${json["your_tier"]}, available=${JSON.stringify(json["available_capabilities"] ?? [])})`;
  console.log(`${who.padEnd(10)} -> ${capability.padEnd(16)} ${res.status}  ${summary}`);
}

await call("anonymous", "public-articles", {});
await call("anonymous", "article-full", {});
await call("verified", "article-full", {}, { key: keys.verifiedKey, keyid: "verified-key-1" });
await call("verified", "request-callback", { topic: "hello" }, { key: keys.verifiedKey, keyid: "verified-key-1" });
await call("partner", "request-callback", { topic: "hello" }, { key: keys.partnerKey, keyid: "partner-key-1" });
await call("stranger", "catalog-query", {}, { key: keys.strangerKey, keyid: "stranger-key-1" });

console.log("\nAudit log:");
for (const e of audit.entries) {
  console.log(`${e.tier.padEnd(9)} ${String(e.operator_id).padEnd(12)} ${String(e.capability_id).padEnd(16)} ${e.domain ?? "-"}  ${e.outcome}${e.reason ? ` (${e.reason})` : ""}`);
}
server.close();
