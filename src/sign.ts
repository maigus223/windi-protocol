// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MAIGUS

import { randomBytes, sign, KeyObject } from "node:crypto";
import { buildSignatureBase } from "./signature.js";

export interface SignOptions {
  authority: string;
  method?: string;
  path?: string;
  privateKey: KeyObject;
  keyid: string;
  agentUrl?: string; // value for Signature-Agent
  subjectId?: string; // optional pseudonymous subject (proposal, see SPEC section 4.3)
  created?: number;
  ttlSeconds?: number;
  /** Also sign @method and @path so the signature cannot be replayed on another endpoint. Default: true. */
  bindRequest?: boolean;
}

/** Client-side helper used by tests and the demo to play the role of an AI agent. */
export function signRequest(o: SignOptions): Record<string, string> {
  const created = o.created ?? Math.floor(Date.now() / 1000);
  const expires = created + (o.ttlSeconds ?? 300);
  const headers: Record<string, string> = {};
  const components = ["@authority"];
  if (o.bindRequest !== false) components.push("@method", "@path");
  if (o.agentUrl) {
    headers["signature-agent"] = o.agentUrl;
    components.push("signature-agent");
  }
  if (o.subjectId) {
    headers["ai-subject-id"] = o.subjectId;
    components.push("ai-subject-id");
  }
  const inner = `(${components.map((c) => `"${c}"`).join(" ")})`;
  const nonce = randomBytes(12).toString("base64url");
  const params = `;created=${created};expires=${expires};keyid="${o.keyid}";alg="ed25519";nonce="${nonce}";tag="web-bot-auth"`;
  const base = buildSignatureBase(
    components,
    { authority: o.authority, method: o.method ?? "POST", path: o.path ?? "/", headers },
    `${inner}${params}`,
  );
  if (base === null) throw new Error("cannot build signature base");
  const sig = sign(null, Buffer.from(base), o.privateKey).toString("base64");
  headers["signature-input"] = `sig1=${inner}${params}`;
  headers["signature"] = `sig1=:${sig}:`;
  return headers;
}
