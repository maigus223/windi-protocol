// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MAIGUS

import type { Capability, InputSchema, Policy } from "./types.js";

/** Throws if the policy violates the constraints of SPEC section 6. */
export function validatePolicy(policy: Policy): void {
  const seen = new Set<string>();
  for (const c of policy.capabilities) {
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(c.id)) throw new Error(`invalid capability id: ${c.id}`);
    if (seen.has(c.id)) throw new Error(`duplicate capability id: ${c.id}`);
    seen.add(c.id);
    if (c.mutating && c.min_tier === "anonymous") {
      throw new Error(`capability ${c.id}: a mutating capability MUST NOT allow the anonymous tier`);
    }
    if (c.kind === "action" && !c.mutating) {
      throw new Error(`capability ${c.id}: kind "action" must be mutating`);
    }
  }
}

export function findCapability(policy: Policy, id: string): Capability | undefined {
  return policy.capabilities.find((c) => c.id === id);
}

/**
 * Validates inputs against the minimal schema. Unknown fields are rejected
 * (SPEC section 6). Returns an error string, or null when valid.
 */
export function validateInput(schema: InputSchema | undefined, input: unknown): string | null {
  if (!schema) {
    if (input === undefined || (typeof input === "object" && input !== null && Object.keys(input).length === 0)) {
      return null;
    }
    return "this capability takes no input";
  }
  if (typeof input !== "object" || input === null || Array.isArray(input)) return "input must be an object";
  const obj = input as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (!(key in schema.properties)) return `unknown field: ${key.slice(0, 40)}`;
  }
  for (const req of schema.required ?? []) {
    if (!(req in obj)) return `missing required field: ${req}`;
  }
  for (const [key, spec] of Object.entries(schema.properties)) {
    const v = obj[key];
    if (v === undefined) continue;
    if (typeof v !== spec.type) return `field ${key} must be a ${spec.type}`;
    if (spec.type === "string") {
      const max = spec.maxLength ?? 500;
      if ((v as string).length > max) return `field ${key} is too long`;
    }
    if (spec.type === "number" && !Number.isFinite(v as number)) return `field ${key} must be finite`;
  }
  return null;
}
