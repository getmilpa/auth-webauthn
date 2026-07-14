<p align="center">
  <a href="https://github.com/getmilpa">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/getmilpa/core/main/art/lockup/milpa-lockup-v-color-dark.svg">
      <img src="https://raw.githubusercontent.com/getmilpa/core/main/art/lockup/milpa-lockup-v-color-light.svg" alt="Milpa" width="300">
    </picture>
  </a>
</p>

# Milpa Auth-WebAuthn

> Passkey / WebAuthn for the Milpa PHP framework: the `WebAuthnVerifier`, `ChallengeStore` and
> `WebAuthnCredentialStore` contracts, ceremony value objects, in-memory defaults, and a
> [lbuchs/webauthn](https://github.com/lbuchs/WebAuthn) adapter.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%E2%89%A5%208.3-777bb4.svg)](https://www.php.net/)

**A verified WebAuthn assertion mints a session — it is never a per-request transport.**

`milpa/auth-webauthn` sits one tier above [`milpa/auth`](https://github.com/getmilpa/auth): it
consumes the identity vocabulary `milpa/auth` defines (`Actor`, `AuthContext`, `CredentialType::Passkey`)
and adds what a WebAuthn/FIDO2 registration-and-authentication ceremony needs on top — the relying
party, the ceremony type, the challenge lifecycle, and the credential store contracts a real
authenticator adapter (`lbuchs/webauthn`) implements against. Zero framework, zero ORM.

## Install

```bash
composer require milpa/auth-webauthn
```

## What this package is

`milpa/auth-webauthn` is the contracts-plus-defaults layer for a WebAuthn/FIDO2 ceremony: the
`WebAuthnVerifier` port a real authenticator adapter implements, the `ChallengeStore` and
`WebAuthnCredentialStore` seams a host wires to its own storage, the ceremony value objects
(`RelyingParty`, `CeremonyType`, the options/response/context shapes), in-memory reference
implementations for tests and zero-file consumers, and a `lbuchs/webauthn`-backed adapter
(`Adapter\LbuchsWebAuthnVerifier`) that does the actual cryptography. See
[ADR 0001](docs/adr/0001-webauthn-mints-a-session.md) for the three decisions this shape commits to.

**A verified assertion mints a session — it is never a per-request transport**, so `WebAuthnVerifier`
is deliberately not a `Milpa\Auth\Contracts\CredentialVerifier`. `verifyAuthentication()` returns proof
(`WebAuthnAssertionResult`), and the host — not this package — turns that proof into a
`Milpa\Auth\SessionRecord` a later request resolves via `Milpa\Auth\Http\StartSession`.

## The shape

```php
use Milpa\Auth\WebAuthn\Adapter\LbuchsWebAuthnVerifier;
use Milpa\Auth\WebAuthn\RelyingParty;
use Milpa\Auth\WebAuthn\WebAuthnAuthenticationContext;

// The relying party a ceremony runs for — resolved per request/tenant by the host's
// RelyingPartyResolver, never read from a single env-static value.
$rp = new RelyingParty(
    id: 'crm.example',
    name: 'Acme CRM',
    allowedOrigins: ['https://crm.example'],
);

$verifier = new LbuchsWebAuthnVerifier($challengeStore, $credentialStore);

// 1. Begin: issue a single-use challenge, hand the browser its options.
$options = $verifier->createAuthenticationOptions($rp, new WebAuthnAuthenticationContext());
// $options->toArray() is the JSON body for navigator.credentials.get()

// 2. The browser runs the ceremony; the host relays the raw response back as a
//    WebAuthnAuthenticationResponse (credentialId, clientDataJSON, authenticatorData,
//    signature, userHandle) — none of this is verified yet.

// 3. Finish: verify the assertion fail-closed. This returns PROOF, never a session.
$result = $verifier->verifyAuthentication($response, $rp);

// The host — not this package — mints the trusted session from that proof:
$sessionStore->write(new Milpa\Auth\SessionRecord(
    id: $newSessionId,
    actorId: $result->actorId,
    actorType: Milpa\Auth\ActorType::User,
    createdAt: $now,
    expiresAt: $now->modify('+8 hours'),
));
```

Registration is the mirror image: `createRegistrationOptions(Actor, RelyingParty, WebAuthnRegistrationContext)`
issues a challenge and creation options; `verifyRegistration(WebAuthnRegistrationResponse, RelyingParty)`
verifies the (`'none'`) attestation and returns a `WebAuthnCredentialRecord` for the host to `save()`.

## The three seams a host implements

| Contract | Its one job |
|---|---|
| `ChallengeStore` | `issue`/`consume` a single-use, expiring `ChallengeRecord` between a ceremony's two round-trips. |
| `WebAuthnCredentialStore` | `save`/`findByCredentialId`/`listForActor`/`updateSignCount` — the registered-passkey registry. |
| `RelyingPartyResolver` | `resolve(ServerRequestInterface): RelyingParty` — which RP a request's ceremony runs under (host-header, tenant path, …), never a single env-static value. |

`InMemoryChallengeStore` and `InMemoryWebAuthnCredentialStore` are the reference implementations —
array-backed, with an injectable clock, good for tests and zero-file consumers. Neither is safe for a
clustered production deployment: **`ChallengeStore::consume()` MUST be atomic (delete-on-read) in any
production implementation**, or a challenge issued once could be read and reused by two concurrent
requests before either commits its removal. A host ships its own store (Doctrine, Redis, …) behind the
same contract for that guarantee.

## Non-goals, stated on purpose

- **No enterprise attestation.** The shipped adapter fixes attestation to `'none'` — it proves
  possession of a key bound to the RP, not the authenticator's make/model/manufacturer chain.
  Verifying a specific authenticator's provenance is a **future adapter** behind the same
  `WebAuthnVerifier` port (see [ADR 0001](docs/adr/0001-webauthn-mints-a-session.md)), not a mode
  flag on this one.
- **No auth-strength on `Actor`.** This package does not add a "how strongly was this actor
  authenticated" field to `milpa/auth`'s `Actor` or `AuthContext`. `CredentialType::Passkey` is a
  vocabulary marker for logs, UI, and reports — not a policy input `milpa/auth` exposes today.
- **No `Credential::passkey()` factory.** A passkey ceremony is stateful and two-round-trip, never a
  single-shot secret a `CredentialVerifier` checks. Passkey exists as a credential type in the
  vocabulary, not as a per-request `Credential` factory.

## Requirements

- PHP **≥ 8.3**
- `milpa/auth` (the identity vocabulary this package builds on)
- `lbuchs/webauthn` `^2` (the shipped cryptography adapter)
- `psr/http-message` (the `RelyingPartyResolver` seam)
- `ext-openssl`, `ext-mbstring`, `ext-sodium`

## License

[Apache-2.0](LICENSE) © Rodrigo Vicente - TeamX Agency.

---

Milpa is developed and maintained by [TeamX Agency](https://teamx.agency).
