# Windi: Open Agent Access Gateway — Specification

**Version:** 0.1 (draft)
**Status:** Experimental. Not a standard. Expect breaking changes.
**Name:** *Windi* means "concession, courtyard" in Songhay.
**Copyright:** (c) 2026 MAIGUS.
**License:** This specification text is licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/); see `LICENSE-SPEC`. The code in this repository is licensed separately under the MIT License; see `LICENSE`.

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT" and "MAY" are to be interpreted as described in RFC 2119.

---

## 1. Purpose

Many websites block AI agents entirely because open access is risky and there is no middle ground. Many agents, in turn, hit a bare refusal and learn nothing about what they *could* access.

Windi defines a **contract** between a website and AI agents:

- the site declares exactly which information, services and actions it offers to agents;
- agents are identified, and receive a **trust tier** that determines what they may do;
- every access is recorded in an **audit log**;
- when access is denied, the agent receives a **structured refusal** that says what is available and under which conditions.

### 1.1 Non-goals

Windi does **not**:

- stop a malicious end user from lying to an agent or using it for abuse;
- replace authentication for human users;
- define payments or content licensing (sites MAY add their own terms);
- define a new identity scheme: it reuses existing work (see §4).

## 2. Terminology

- **Site**: a website or service that implements Windi.
- **Agent**: an automated client acting for an AI system.
- **Operator**: the organisation that runs the agent (e.g. an AI company).
- **Subject**: an optional pseudonymous identifier for the end user behind an agent (see §4.3).
- **Capability**: one thing the site offers to agents (§6).
- **Tier**: the trust level assigned to a request (§5).
- **Gateway**: the site-side component that applies this specification.

## 3. Discovery

A site SHOULD publish its agent-facing resources through the Agentic Resource Discovery (ARD) catalog at `/.well-known/ai-catalog.json`, and MAY publish its Windi policy at `/.well-known/windi-policy.json`.

> **Open question:** the exact mapping between a Windi policy and an ARD catalog entry is not yet defined. A future version will align with the current ARD specification.

The policy document MUST include: `version`, the list of `capabilities` (§6), the tier rules (§5) and a human-readable contact.

## 4. Identity

### 4.1 Operator identity

Gateways SHOULD identify operators using **Web Bot Auth** (HTTP Message Signatures, RFC 9421): the agent signs its requests and sends the `Signature`, `Signature-Input` and (optionally) `Signature-Agent` headers; the gateway verifies the signature against the operator's published public keys.

A request is **signed** only if the signature verifies and its `created`/`expires` parameters are valid. Gateways MUST reject replayed signatures within their validity window where feasible.

Gateways SHOULD require that signatures cover `@authority`, `@method` and `@path`, so a captured signature cannot be replayed against another endpoint of the same site. Agents SHOULD include a fresh `nonce` parameter in every signature; without one, two legitimate requests made in the same second can produce identical signatures and be mistaken for a replay. Signatures do not cover request bodies unless a digest component is also signed (not yet defined in this version).

> Web Bot Auth is currently an IETF Internet-Draft, not a finished standard. Windi follows it as it evolves.

### 4.2 Claims are never trusted

The `User-Agent` string, IP address, or any unsigned header MUST NOT be used to raise a request's tier. They MAY be logged.

### 4.3 Optional subject identifier

An operator MAY include an opaque **subject identifier** for the end user, covered by the signature.

- It MUST NOT contain personal data (name, email, phone, etc.).
- It SHOULD be derived **per site** by the operator (for example with a keyed hash of the user's account ID and the site's domain), so that two sites cannot correlate the same person.
- It is optional: gateways MUST work without it.
- Its purpose is limited to rate limiting, abuse handling and audit. A site can ask the operator to act on a subject, but the subject ID alone does not reveal who the person is.

> Privacy note: a stable pseudonymous identifier may still count as personal data under laws such as the GDPR. Sites SHOULD apply the retention limits in §8.

> Open question: no standard currently carries the subject identifier. Until one does, the transport (a signed header name) is a proposal only.

## 5. Trust tiers

| Tier | Condition | Default access |
|---|---|---|
| `anonymous` | No valid signature, or operator not on any list | Only capabilities explicitly marked public-read |
| `verified` | Valid signature **and** operator on the site's verified list | Read capabilities |
| `partner` | Valid signature **and** operator on the site's partner list | Read and, if the site enables it, actions |

Rules:

1. Tier is decided **only** by a valid signature plus the site's lists.
2. Lists are maintained by the site owner. A gateway MAY import community lists, but the site MUST be able to override them.
3. Unknown or unsupported signatures resolve to `anonymous`, never to an error that hides what is available.
4. Tiers are ordered: `anonymous` < `verified` < `partner`.

## 6. Capabilities

Each capability declares:

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Stable identifier |
| `description` | yes | What it provides, for humans and agents |
| `domain` | yes | Topic tag (e.g. `news`, `catalog`, `support`) used in the audit log |
| `kind` | yes | `read`, `query` or `action` |
| `min_tier` | yes | Lowest tier allowed |
| `rate_limit` | yes | Per tier, per time window |
| `input_schema` | if inputs | JSON Schema |
| `mutating` | yes | `true` if it changes state |

Defaults and constraints:

- Gateways MUST be **read-only by default**.
- A capability with `mutating: true` MUST NOT allow `anonymous`.
- Gateways MUST validate all inputs against `input_schema` and reject unknown fields.
- A capability MUST NOT expose data classes the site has not explicitly listed. Sites SHOULD declare sensitive data classes (personal, financial, security) and keep them out of the agent interface by default.

## 7. Structured refusal

When a request is denied, the gateway SHOULD respond with an HTTP error status (`401`, `403` or `429`) and a body of type `application/problem+json` (RFC 9457) extended with:

```json
{
  "type": "https://example.org/windi/problems/tier-too-low",
  "title": "Access level too low for this capability",
  "status": 403,
  "your_tier": "anonymous",
  "required_tier": "verified",
  "available_capabilities": ["public-articles", "site-search"],
  "how_to_upgrade": "https://example.org/ai-access",
  "retry_after": null
}
```

The refusal MUST NOT leak data the requester is not allowed to see.

## 8. Audit log

Every request to a Windi-protected capability MUST produce a log entry with at least:

| Field | Notes |
|---|---|
| `timestamp` | UTC |
| `request_id` | Unique |
| `tier` | As resolved |
| `operator_id` | From the verified signature, else `null` |
| `subject_id` | If provided, else `null` |
| `capability_id` and `domain` | What was accessed |
| `outcome` | `allowed`, `denied` or `rate_limited` |
| `bytes_returned` | Size only |

Logs MUST NOT store response content or end-user personal data. Raw IP addresses SHOULD be truncated or hashed.

Sites MUST document their retention period. The default RECOMMENDED retention is **90 days or less**.

## 9. Security considerations

- **Spoofing**: handled by never trusting unsigned claims (§4.2).
- **Replay**: validate signature validity windows; track nonces where feasible.
- **Prompt injection**: content returned to agents is **untrusted input** for the agent. Gateways MUST NOT include instructions to the agent in data responses, and SHOULD mark content origin clearly.
- **Abuse via anonymous tier**: keep anonymous capabilities minimal and strictly rate-limited.
- **Key rotation and revocation**: operators rotate keys; sites SHOULD honour revocation promptly.
- **Log poisoning**: log fields derived from requests MUST be escaped or length-limited.
- **Limits of identity**: a valid signature shows who signed the request, not that the agent behaves well. Tiers limit exposure; they do not prove good intent.

## 10. Conformance

An implementation is **Windi-Basic** if it:

1. resolves tiers as in §5;
2. enforces read-only defaults and input validation (§6);
3. returns structured refusals (§7);
4. writes audit entries (§8).

Test cases (implemented as automated tests in the reference implementation; machine-readable vectors are still to be published):

| # | Scenario | Expected |
|---|---|---|
| 1 | Unsigned request to a `verified` capability | `403`, `your_tier: anonymous`, capability list returned |
| 2 | Valid signature, operator on verified list, `read` capability | `200`, log entry with `tier: verified` |
| 3 | Valid signature, operator not listed | Tier `anonymous` |
| 4 | Forged `User-Agent` claiming a known operator, no signature | Tier `anonymous` |
| 5 | Mutating capability requested by `verified` tier | `403` unless `min_tier` allows |
| 6 | Input with an unknown field | `400`, nothing executed |
| 7 | Rate limit exceeded | `429` with `retry_after` |

## 11. Open questions

1. Alignment with the ARD catalog format.
2. Transport for the optional subject identifier.
3. Whether tier lists should have a shared, signed interchange format.
4. Machine-readable conformance test vectors.
5. A security review by people with protocol and web security experience before any "1.0".

## 12. Acknowledgements and related work

Windi builds on, and does not replace: Web Bot Auth (IETF draft), HTTP Message Signatures (RFC 9421), Problem Details for HTTP APIs (RFC 9457), the Model Context Protocol, and Agentic Resource Discovery.

All product, protocol and company names mentioned belong to their respective owners. This project is independent and is not affiliated with, endorsed by, or sponsored by any of them. No text from those specifications is reproduced here; they are referenced by name only.
