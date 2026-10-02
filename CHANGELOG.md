# Changelog

## Unreleased (review fixes)

Security-relevant fixes found during a code review. All are covered by new tests (8, 9, 9b, 10).

- **Input validation**: unknown-field detection used the `in` operator, so inherited names such as `constructor`, `toString` and `__proto__` slipped through to handlers. Now uses own-property checks (`Object.hasOwn`), also for required fields and handler lookup.
- **Cross-site replay**: the gateway trusted the request's `Host` as the signed `@authority`, so a signature made for site A could be replayed on site B. The `Gateway` now requires `allowedAuthorities` and refuses other hosts with `421` before looking at the signature. **Breaking:** new required config field.
- **Rate-limit bypass**: the limit key included the operator-signed subject id, so an operator could multiply its quota by rotating subject ids. Limits are now per operator (SPEC 4.3).
- Documentation: reverse-proxy limitation for anonymous rate limiting.
