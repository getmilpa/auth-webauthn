# ADR 0001 — WebAuthn mints a session

**Status:** Accepted (Rod, 2026-07-14)
**Context:** `milpa/auth-webauthn` sits one tier above [`milpa/auth`](https://github.com/getmilpa/auth):
it consumes the identity vocabulary the leaf defines (`Actor`, `AuthContext`, `CredentialType::Passkey`)
and adds what a WebAuthn/FIDO2 registration-and-authentication ceremony needs — the relying party, the
ceremony type, the challenge lifecycle, and the credential store a real authenticator adapter implements
against. Three questions had to be settled before a single line of contract code: what a verified
assertion actually *produces*, which attestation conveyance to ship first, and how far to trust the one
third-party library doing the cryptography.

## Decision

**(a) WebAuthn mints a session, not a per-request transport.** `WebAuthnVerifier` is deliberately
**NOT** a `Milpa\Auth\Contracts\CredentialVerifier` — a passkey ceremony is stateful and two-round-trip
(`create*` issues a challenge and returns browser options; `verify*` consumes it and checks the
ceremony), never a single-shot credential a request re-proves on every call. `verifyAuthentication()`
returns `WebAuthnAssertionResult` — the cryptographic proof (which credential/actor, the reported sign
counter, the clone signal) — and nothing more. It is not a session and not an `AuthContext`. Minting
either is the **host's** job: the two-hop is *assertion verified → `WebAuthnAssertionResult` → host
builds a `Milpa\Auth\SessionRecord` and writes it to a `SessionStore` → a later request's
`Milpa\Auth\Http\StartSession` middleware resolves that session into `AuthContext::authenticated()`*.
This package never touches `SessionStore` or `AuthContext` directly, and the red line is enforced by a
test: `WebAuthnVerifier` must not be a subclass of `CredentialVerifier`.

**(b) Attestation is `'none'`.** The shipped adapter fixes attestation to `'none'` unconditionally — it
proves possession of a key bound to the relying party, not the authenticator's make, model, or
manufacturer chain. This is the passkey-first posture: synced platform passkeys generally carry no
attestation chain worth verifying, and demanding one would reject the exact credentials this package
exists to support. **Enterprise attestation — verifying a specific authenticator's provenance — is a
future adapter behind the same `WebAuthnVerifier` port, not a variant of this one.** Nothing here rules
it out; nothing here builds it before a real host needs it.

**(c) `lbuchs/webauthn` sits behind the `WebAuthnVerifier` port.** `Adapter\LbuchsWebAuthnVerifier` is
the only place in this package that does cryptography, and today it is the only implementation wired
to anything. The port exists precisely so this is replaceable: **the port protects Milpa from the
library; do not swap the library until the port exists and the dogfood asks.** It already does — this
package depends on the interface, and any consumer that needs a different implementation supplies one
against `WebAuthnVerifier`, not by forking or monkey-patching the adapter.

**The sign-counter-as-signal rule.** `lbuchs/webauthn`'s native posture throws on a non-incrementing
signature counter (`prevSignatureCnt`) — a model that fits roaming hardware keys but breaks for synced
passkeys, whose counter is routinely `0` or non-monotonic across devices. `LbuchsWebAuthnVerifier`
deliberately runs lbuchs with `prevSignatureCnt = null` (signature/origin/rpId/challenge are still
fully verified) and computes `WebAuthnAssertionResult::$cloneWarning` itself: a zero or absent reported
counter is a synced passkey — no warning; a non-zero counter that failed to advance past the stored one
is the clone-detection tell — a warning surfaces, but **the ceremony still succeeds.** `cloneWarning`
is a signal a host may act on (log, alert, prompt re-registration); it is never, in this package, a
rejection gate. The same rule governs `WebAuthnCredentialStore::updateSignCount()`: recording, never
gating.

**Decision phrase:** *Passkey no autoriza requests. Passkey acuña una sesión confiable. La sesión produce el AuthContext.
El AuthContext alimenta las policies.*

## Rationale

Treating `WebAuthnVerifier` as just another `CredentialVerifier` would force a two-round-trip ceremony
into a single-shot contract designed for bearer tokens and cookies — either faking statelessness with
hidden server-side state, or making every protected request re-run a WebAuthn handshake it was never
built for. Keeping the ceremony's output as plain proof, and letting the host decide how a session gets
minted from it, is what lets `milpa/auth-webauthn` stay a leaf: it knows nothing about cookies,
storage, or how long a session should live, exactly as `milpa/auth` itself knows nothing about *how*
sessions are persisted.

Fixing attestation to `'none'` is an honest scoping decision, not a security shortcut: attestation
answers "what authenticator is this," a question most consumer passkey flows do not need answered to
be secure, since the ceremony already proves possession of a private key bound to the relying party.
Enterprise deployments that *do* need to restrict which authenticator models may register have a real,
different requirement — a future adapter, informed by an actual deployment, is a better answer than a
speculative attestation-mode flag no one has asked for yet.

The sign-counter rule follows directly from what passkeys are: a physical roaming key increments a
counter on every use, so a stall or rollback is a strong clone signal; a synced passkey (iCloud
Keychain, Google Password Manager, …) may report `0` forever or reset across a device migration,
which is *expected*, not an attack. Rejecting on that basis would lock out legitimate users on the
exact credential family this package is built for. Surfacing it as a signal — never a gate — keeps the
information available to a host that wants to act on it, without turning a false positive into a
lockout. This is a design commitment reflecting the current state of passkey ecosystems, not a claim
that clone detection is solved.

## Policy (the WebAuthn-mints-a-session contract)

1. `WebAuthnVerifier` MUST NOT extend or implement `Milpa\Auth\Contracts\CredentialVerifier` —
   pinned by a characterization test, not just documented.
2. `WebAuthnVerifier::verifyAuthentication()` MUST return only `WebAuthnAssertionResult` (proof). No
   method on this contract may return a `SessionRecord` or an `AuthContext` — minting either is a host
   concern, never this package's.
3. The shipped adapter (`LbuchsWebAuthnVerifier`) fixes attestation to `'none'`. A different
   attestation conveyance (enterprise attestation, MDS-backed metadata checks, …) ships as a **new**
   `WebAuthnVerifier` implementation, never as a mode flag on this one.
4. `lbuchs/webauthn` remains the only implementation this package ships until a real consumer's dogfood
   need — not a speculative preference — justifies a second one behind the same port.
5. A ceremony's reported signature counter MUST be surfaced via `WebAuthnAssertionResult::$cloneWarning`
   and MUST NEVER be used, by any implementation this package ships, to reject an otherwise-valid
   assertion. A zero or absent counter is treated as a synced passkey, not an anomaly.
6. `WebAuthnCredentialStore::updateSignCount()` records the latest counter; it is a recorder, never a
   gate, for every implementation this package ships or documents.

---

[Apache-2.0](LICENSE) © Rodrigo Vicente - TeamX Agency.
