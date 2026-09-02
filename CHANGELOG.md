# Changelog

## Unreleased — 0.2.0 (intent)

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

## [0.1.1](https://github.com/getmilpa/auth-webauthn/compare/v0.1.0...v0.1.1) (2026-07-30)


### Bug Fixes

* anchor release-please on the v0.1.0 commit, not on itself ([09dfe30](https://github.com/getmilpa/auth-webauthn/commit/09dfe30c9fdf439dcb70f0a9f1359d96764f470f))
* catch up with the family's published versions ([1cc4ed9](https://github.com/getmilpa/auth-webauthn/commit/1cc4ed9b017a756bb962d545c6dcc64851027af8))
* let release-please anchor on the tag, like the other thirty ([81fac9e](https://github.com/getmilpa/auth-webauthn/commit/81fac9e41a4f139a8618e330b3f1e6edf3d0cc1e))
* use last-release-sha (never ignored) to anchor release-please ([19de3a8](https://github.com/getmilpa/auth-webauthn/commit/19de3a822d68712f52467c7565db3327ea8d02ae))

## 0.1.0 (2026-07-14)


### Features

* WebAuthn / passkeys for the Milpa framework ([9514a32](https://github.com/getmilpa/auth-webauthn/commit/9514a324a03e7295106b08a15dc7d6f8f5a7cb00))
