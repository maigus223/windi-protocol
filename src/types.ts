// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MAIGUS

export type Tier = "anonymous" | "verified" | "partner";
export const TIER_ORDER: Record<Tier, number> = { anonymous: 0, verified: 1, partner: 2 };

export type CapabilityKind = "read" | "query" | "action";

export interface RateLimit {
  max: number;
  windowSeconds: number;
}

/** Minimal input schema (subset of JSON Schema) understood by this reference implementation. */
export interface InputSchema {
  type: "object";
  properties: Record<string, { type: "string" | "number" | "boolean"; maxLength?: number }>;
  required?: string[];
  additionalProperties?: false;
}

export interface Capability {
  id: string;
  description: string;
  domain: string;
  kind: CapabilityKind;
  min_tier: Tier;
  mutating: boolean;
  rate_limit: Partial<Record<Tier, RateLimit>>;
  input_schema?: InputSchema;
}

export interface Policy {
  version: string;
  contact: string;
  how_to_upgrade: string;
  capabilities: Capability[];
}

export interface OperatorKey {
  /** Ed25519 public key as a JWK (kty "OKP", crv "Ed25519"). */
  jwk: { kty: "OKP"; crv: "Ed25519"; x: string };
}

export interface OperatorDirectory {
  /** operator id -> keyid -> key */
  operators: Record<string, { keys: Record<string, OperatorKey> }>;
}

export interface TierLists {
  verified: string[];
  partner: string[];
}

export interface GatewayRequest {
  method: string;
  path: string;
  authority: string;
  headers: Record<string, string>; // lower-cased names
  body?: unknown;
  remoteAddress?: string;
}

export interface GatewayResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

export interface AuditEntry {
  timestamp: string;
  request_id: string;
  tier: Tier;
  operator_id: string | null;
  subject_id: string | null;
  capability_id: string | null;
  domain: string | null;
  outcome: "allowed" | "denied" | "rate_limited";
  reason?: string;
  bytes_returned: number;
  client_hash: string;
}

export interface AuditSink {
  write(entry: AuditEntry): void;
}

export type Handlers = Record<string, (input: Record<string, unknown>) => unknown>;
