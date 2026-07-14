# Security Policy

## Supported Versions

Milpa Auth-WebAuthn is pre-1.0. Only the latest `0.x` release line receives security fixes.

## Reporting a Vulnerability

Please report security vulnerabilities **privately** via GitHub Security Advisories
— the repository's **Security** tab → **Report a vulnerability** — rather than opening
a public issue or pull request.

We aim to acknowledge a report within 72 hours and to keep you informed as we work
on a fix. Once a fix is released, we will credit the reporter unless anonymity is
requested.

## Handling WebAuthn ceremonies

Milpa Auth-WebAuthn brokers a cryptographic authentication ceremony, so its own posture is part of
your attack surface. See [ADR 0001](docs/adr/0001-webauthn-mints-a-session.md) for the design
decisions behind these invariants; below is what each one actually claims, and how it is checked.

- **A verified assertion mints a session — it is never a per-request transport.**
  `WebAuthnVerifier` is deliberately not a `Milpa\Auth\Contracts\CredentialVerifier`, and
  `verifyAuthentication()` returns only `WebAuthnAssertionResult` (proof) — never a `SessionRecord` or
  an `AuthContext`. **Enforced by test**, at the interface level: `WebAuthnVerifier` is asserted to not
  be a subclass of `CredentialVerifier`. Minting the actual session from that proof is the host's job,
  outside this package's remit, and outside what this package's own test suite can check.

- **Challenges are single-use, and consumption is fail-closed.** `ChallengeStore::consume()` returns a
  challenge once and invalidates it; an absent, expired, or already-consumed id returns `null`, never
  the record. **Enforced by test** for the shipped `InMemoryChallengeStore` (single-use and expiry are
  both pinned). The shipped in-memory store is explicitly **not** safe for a clustered production
  deployment — a host-supplied store (Doctrine, Redis, …) **MUST** make `consume()` atomic
  (delete-on-read within a transaction, or the storage's equivalent), or a challenge could be read by
  two concurrent requests before either commits its removal. That atomicity requirement is a design
  commitment this package documents on the `ChallengeStore` contract; it is not something a package
  that ships no production store can itself test.

- **Origin allowlist and rpId are both checked, exact-match.** The shipped adapter enforces an
  exact-string origin check against `RelyingParty::$allowedOrigins` on top of `lbuchs/webauthn`'s own
  rpId-hash derivation from the assertion. There is no prefix, suffix, or wildcard matching on origin.
  **Enforced by test:** an origin outside the allowlist is rejected, and an assertion signed for a
  different relying party is rejected by the underlying library's own verification.

- **The sign counter is a SIGNAL, never a gate.** A non-incrementing signature counter surfaces
  `WebAuthnAssertionResult::$cloneWarning`; no implementation this package ships uses it to reject an
  otherwise-valid assertion. A zero or absent reported counter is treated as an ordinary synced
  passkey, not an anomaly. **Enforced by test:** a non-advancing counter still succeeds with the
  warning set, a zero counter succeeds without it, and a stored-nonzero-then-reported-zero transition
  does not false-positive.

- **The challenge and the assertion signature are secret-bearing.** `ChallengeRecord`'s challenge
  bytes and `WebAuthnAuthenticationResponse`'s signature both follow `milpa/auth`'s secret-bearing
  object contract: a `private` property, no `__toString()`, a redacted `__debugInfo()`,
  `__serialize()`/`__clone()` that throw, and one explicit read method (`value()` / `signature()`).
  **Enforced by test** for both types. As with every secret-bearing type in the Milpa family,
  `var_export()` and an `(array)` cast remain **documented, un-sealed residual leak paths** — never
  claimed safe, never claimed sealed.

- **Tampering is rejected at the crypto boundary.** A tampered signature, an assertion echoing a
  different challenge, or an assertion signed for a different relying party is rejected by
  `lbuchs/webauthn`'s own cryptographic verification. **Enforced by integration test**, against real
  WebAuthn fixtures rather than mocked crypto.

- **Registered credential ids are globally unique.** `WebAuthnCredentialStore::save()` must reject a
  duplicate `credentialId` — the contract a usernameless/discoverable login depends on. **Enforced by
  test** for the shipped `InMemoryWebAuthnCredentialStore`; a host-supplied store inherits the same
  requirement from the contract and is responsible for its own uniqueness constraint (e.g. a unique
  database index).

### What this package does not cover

This package verifies a WebAuthn ceremony fail-closed; it does not, on its own, provide rate limiting
or abuse mitigation on the endpoints that expose it, does not manage relying-party resolution for a
multi-tenant host beyond the `RelyingPartyResolver` seam, and does not attempt enterprise attestation
(see [ADR 0001](docs/adr/0001-webauthn-mints-a-session.md)). Those are host responsibilities layered
on top, by design.

---

Milpa is developed and maintained by [TeamX Agency](https://teamx.agency).
