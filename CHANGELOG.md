# Changelog

## Unreleased — 0.3.0 (intent)

Needs `milpa/auth` 0.11.0 (published 2026-09-29): this release uses
`UserVerificationRequirement` and `RelyingParty::allowsOrigin()`, which land there.

### ⚠ BREAKING CHANGES

* `LbuchsWebAuthnVerifier` requires user verification by default. It handed lbuchs
  `requireUserVerification=false`, so a registration or an assertion whose authenticatorData
  lacked the UV flag was accepted: an authenticator that was touched but never checked who held
  it. The constructor takes a fifth argument, `UserVerificationRequirement $userVerification =
  Required`; `::Preferred` or `::Discouraged` relaxes it, only when passed explicitly.
* The creation and request options ask the browser for `userVerification: 'required'` whenever
  the verifier demands it, whatever the context asked for; a relaxed verifier advertises the
  context's value unchanged.
* An assertion whose credential belongs to an actor other than the one the challenge was issued
  for is refused (`credential not allowed`) — WebAuthn L2 §7.2 step 6. Before, it succeeded for
  the other actor when the browser sent no userHandle.
* A registration whose credential id is already in the store is refused
  (`credential already registered`) — §7.1 step 22.
* Requires `milpa/auth` `>=0.11 <1.0` (was `>=0.9 <1.0`).

### Tests

* `LbuchsWebAuthnVerifierCeremonyChecksTest` walks the §7.1/§7.2 checks one at a time through real
  crypto: UV, UP, clientData `type`, origin against the allowlist (a subdomain lbuchs alone would
  admit), rpIdHash, credential ownership and re-registration.

See [UPGRADING.md](UPGRADING.md).

## [0.3.0](https://github.com/getmilpa/auth-webauthn/compare/v0.2.1...v0.3.0) (2026-10-07)


### ⚠ BREAKING CHANGES

* ceremonies without UV are refused unless the verifier is built with UserVerificationRequirement::Preferred or ::Discouraged; a foreign credential answering an actor's challenge and a re-registered credential id are refused; requires milpa/auth >=0.11. See UPGRADING.md.

### Bug Fixes

* a passkey ceremony needs a verified user, and a challenge its own actor ([#10](https://github.com/getmilpa/auth-webauthn/issues/10)) ([c926178](https://github.com/getmilpa/auth-webauthn/commit/c92617802e13e1d65a46b0bdbb7c79c6a853898f))

## 0.2.0 — migration notes

### Breaking

* `milpa/auth` is now the authority for `Milpa\Auth\WebAuthn\*` ceremony types and contracts.
  This package keeps only `Adapter\LbuchsWebAuthnVerifier` and the in-memory stores
  (`InMemoryChallengeStore`, `InMemoryWebAuthnCredentialStore`).
* Require `milpa/auth: ^0.9` (was `^0.3`). Composer `^0.3` could not install auth 0.4+,
  which already shipped a parallel `src/WebAuthn/` tree; bumping the range without moving
  the types would leave two packages claiming the same PSR-4 prefix. Auth 0.8.0 does **not**
  contain `RelyingParty` / `WebAuthnVerifier` / `WebAuthnAssertionResult` /
  `WebAuthnAuthenticationResponse` — those land in auth 0.9 with this split, so the
  constraint is `^0.9`, not `^0.8` (`^0.8` would exclude 0.9 and still resolve 0.8.0).

### Moved to milpa/auth

* `RelyingParty`, `CeremonyType`, `ChallengeRecord`
* `Contracts\WebAuthnVerifier`, `Contracts\ChallengeStore`, `Contracts\WebAuthnCredentialStore`, `Contracts\RelyingPartyResolver`
* `WebAuthnAssertionResult`, `WebAuthnAuthenticationResponse`, `WebAuthnAuthenticationContext`
* `WebAuthnRegistrationResponse`, `WebAuthnRegistrationContext`, `WebAuthnCredentialRecord`
* `PublicKeyCredentialCreationOptions`, `PublicKeyCredentialRequestOptions`
* `Exceptions\WebAuthnCeremonyException`

App imports of those FQCNs keep resolving — from `milpa/auth`.

## [0.2.1](https://github.com/getmilpa/auth-webauthn/compare/v0.2.0...v0.2.1) (2026-09-07)


### Bug Fixes

* admit every minor of milpa/auth, not just 0.9 ([#8](https://github.com/getmilpa/auth-webauthn/issues/8)) ([306af7b](https://github.com/getmilpa/auth-webauthn/commit/306af7b3a4376aab9b0114aba40259bfd10e3605))

## [0.2.0](https://github.com/getmilpa/auth-webauthn/compare/v0.1.1...v0.2.0) (2026-09-02)


### ⚠ BREAKING CHANGES

* ceremony types move to milpa/auth; this package keeps the adapter ([#6](https://github.com/getmilpa/auth-webauthn/issues/6))

### Features

* ceremony types move to milpa/auth; this package keeps the adapter ([#6](https://github.com/getmilpa/auth-webauthn/issues/6)) ([50e99e7](https://github.com/getmilpa/auth-webauthn/commit/50e99e72b9405be1ae17ed4dab1e2ecd335647e5))

## [0.1.1](https://github.com/getmilpa/auth-webauthn/compare/v0.1.0...v0.1.1) (2026-07-30)


### Bug Fixes

* anchor release-please on the v0.1.0 commit, not on itself ([09dfe30](https://github.com/getmilpa/auth-webauthn/commit/09dfe30c9fdf439dcb70f0a9f1359d96764f470f))
* catch up with the family's published versions ([1cc4ed9](https://github.com/getmilpa/auth-webauthn/commit/1cc4ed9b017a756bb962d545c6dcc64851027af8))
* let release-please anchor on the tag, like the other thirty ([81fac9e](https://github.com/getmilpa/auth-webauthn/commit/81fac9e41a4f139a8618e330b3f1e6edf3d0cc1e))
* use last-release-sha (never ignored) to anchor release-please ([19de3a8](https://github.com/getmilpa/auth-webauthn/commit/19de3a822d68712f52467c7565db3327ea8d02ae))

## 0.1.0 (2026-07-14)


### Features

* WebAuthn / passkeys for the Milpa framework ([9514a32](https://github.com/getmilpa/auth-webauthn/commit/9514a324a03e7295106b08a15dc7d6f8f5a7cb00))
