# Windi: Open Agent Access Gateway

> **Experimental draft. Not a standard. Not security-audited.**

**A proposed open contract between websites and AI agents, with a small reference implementation in Node.js/TypeScript.**

**About the name:** *Windi* means "concession, courtyard" in Songhay: an enclosed compound whose owner decides who may enter, and how far.

Websites block AI agents because open access is risky. Agents hit a bare refusal and learn nothing. Windi proposes a middle path:

- the site **declares** what it offers to agents (information, services, actions);
- agents are **identified** and given a **trust tier** (`anonymous`, `verified`, `partner`);
- access is **read-only by default**;
- every access is **logged**;
- a denial is a **structured refusal** that says what is available and how to get more.

Windi reuses existing work (Web Bot Auth, HTTP Message Signatures, ARD, MCP, RFC 9457) instead of inventing new identity or discovery formats.

## Contents

- [`SPEC.md`](SPEC.md): the specification draft v0.1.
- [`src/`](src): reference implementation (signature verification, tiers, capabilities, rate limits, audit log, HTTP adapter).
- [`examples/`](examples): a fictional site with 5 capabilities, and a simulation of three AIs.
- [`test/`](test): automated tests for the specification's test cases and extra security checks.

## Quick start

Requires Node.js 20 or later.

```bash
npm install
npm test        # runs the test suite
npm run demo    # starts the demo site and lets 3 simulated AIs call it
```

The demo prints each request's result and the resulting audit log.

## What the demo shows
 
`npm run demo` starts a fictional site and lets three simulated agents call it. Real output:
 
```
anonymous  -> public-articles  200  OK
anonymous  -> article-full     403  Access level too low for this capability (your_tier=anonymous, available=["public-articles","site-search"])
verified   -> article-full     200  OK
verified   -> request-callback 403  Access level too low for this capability (your_tier=verified, available=[...])
partner    -> request-callback 200  OK
stranger   -> catalog-query    403  Access level too low for this capability (your_tier=anonymous, available=["public-articles","site-search"])
 
Audit log:
anonymous null         public-articles  news  allowed
anonymous null         article-full     news  denied (tier-too-low)
verified  verified-ai  article-full     news  allowed
verified  verified-ai  request-callback support  denied (tier-too-low)
partner   partner-ai   request-callback support  allowed
anonymous stranger-ai  catalog-query    catalog  denied (tier-too-low)
```
 
Note how a denied agent is told what it *can* access, and every call, allowed or not, lands in the audit log.

## Why not just robots.txt, Web Bot Auth or MCP?
 
Windi is not meant to replace these. It sits at a different layer.
 
- **robots.txt**: a voluntary, per-path allow/deny file. It cannot tell agents apart, has no notion of trust levels, says nothing about *why* something is refused, and leaves no audit trail.
- **Web Bot Auth / HTTP Message Signatures**: these answer "who signed this request?". They do not say what a site should offer to that agent. Windi consumes that identity and turns it into a trust tier plus a policy.
- **MCP**: defines how agents discover and call tools. Windi is the site-side access contract (tiers, structured refusals, audit log). A site could expose capabilities through MCP and gate them with Windi, but that mapping is not specified yet.
- **ARD**: a discovery catalog. Aligning a Windi policy with an ARD catalog entry is an open question in the spec (section 11).
 
In short: existing work covers identity and discovery; Windi proposes the missing middle, a declared, tiered, auditable contract with refusals that explain themselves.

## How to use it in your own site

1. Describe your capabilities in a `Policy` (see `examples/demo-site.ts`).
2. Register a handler for each capability (your real data goes here).
3. Fill the operator key directory and the `verified` / `partner` lists.
4. Create a `Gateway`, and plug `gateway.handle(request)` into your framework, or use `createGatewayServer` for plain `node:http`.

## Limitations of this reference implementation

Read these before using it for anything real.

- **Not security-reviewed.** Treat it as a teaching and testing tool, not production code.
- Operator public keys come from a **local directory**. It does not fetch remote key directories from `Signature-Agent`, because that requires SSRF protections that are not implemented yet.
- Only the first signature is checked; only Ed25519 is supported.
- Request bodies can be bound to the signature by signing the **`Content-Digest`** component (RFC 9530 / RFC 9421).
- The optional subject identifier (`ai-subject-id` header) is a **proposal**: no standard carries it today.
- Rate limiting and the replay cache are **in memory, single process** only.
- The audit file sink does not delete old data: **retention is the site's responsibility**.
- The input validator supports only a small subset of JSON Schema.

## Contributing

Open an issue to discuss, or a pull request to propose changes. Especially welcome:

- security and protocol review;
- alignment with the ARD catalog format and current Web Bot Auth drafts;
- remote key directory support, with SSRF protection;
- machine-readable test vectors;
- translations of this README.

## License

- **Code** (`src/`, `test/`, `examples/`): [MIT License](LICENSE).
- **Specification text** (`SPEC.md`): [Creative Commons Attribution 4.0 International](LICENSE-SPEC) (CC BY 4.0). You may reuse and adapt it, including commercially, if you give credit and indicate changes.

Copyright (c) 2026 MAIGUS.

The reference implementation has **no runtime dependencies**. Development tools (TypeScript, tsx, @types/node) are used only to build and test and are under their own licenses (Apache-2.0 and MIT).

## Authorship and disclaimers

- Conceived by MAIGUS. The specification draft and reference code were written with the assistance of an AI model (Claude, by Anthropic), under the direction of the author. They have not been reviewed by a security professional.
- Provided "as is", without warranty of any kind (see `LICENSE`).
- All product, protocol and company names mentioned (for example Web Bot Auth, ARD, MCP, Cloudflare, Google, Anthropic) belong to their respective owners. This project is independent and is not affiliated with, endorsed by, or sponsored by any of them.

## Security

Please report vulnerabilities privately, as described in [`SECURITY.md`](SECURITY.md). Contribution rules are in [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## Résumé en français

**Windi propose un contrat ouvert entre les sites web et les agents d'IA, avec une petite implémentation de référence en Node.js/TypeScript.**

**À propos du nom :** *Windi* signifie « concession, cour » en songhay : un espace clos dont le maître des lieux décide qui entre, et jusqu'où.

Beaucoup de sites bloquent totalement les IA, car un accès libre est risqué et il n'existe pas de solution intermédiaire. Les IA, de leur côté, se heurtent à un simple refus sans savoir ce qui leur serait accessible.

L'idée :

- le site **déclare** ce qu'il propose aux IA (informations, services, actions) ;
- chaque IA est **identifiée** et reçoit un **niveau de confiance** : `anonymous` (non reconnue), `verified` (acceptée par le site), `partner` (liée au site) ;
- l'accès est en **lecture seule par défaut** ;
- chaque accès est **enregistré** dans un journal d'audit ;
- un refus est un **refus structuré** : il indique ce qui est disponible et comment obtenir plus.

Le projet s'appuie sur des travaux existants (Web Bot Auth, signatures HTTP, ARD, MCP) plutôt que d'inventer de nouveaux formats.

**Essayer :** `npm install`, puis `npm test` (tests) et `npm run demo` (trois IA simulées appellent un site fictif).

**Limites à connaître :** ce n'est pas un standard, la sécurité n'a pas été auditée, les clés des opérateurs sont lues dans un répertoire local, le corps des requêtes n'est pas signé, et une signature valide prouve qui a signé la requête, pas que l'utilisateur derrière l'IA est de bonne foi.

**Licences :** code sous licence MIT ; texte de la spécification sous licence Creative Commons Attribution 4.0 (CC BY 4.0). Fourni « tel quel », sans garantie. Les noms de produits et de protocoles cités appartiennent à leurs propriétaires ; ce projet est indépendant et non affilié.

**Statut :** brouillon de spécification (`SPEC.md`) et implémentation de référence expérimentale. Les contributions sont les bienvenues.
