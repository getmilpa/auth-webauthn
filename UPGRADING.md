# Upgrading

## 0.3.0 — user verification is required, and the options ask for it

*(This package is at v0.2.1; refusing ceremonies it used to accept makes the next release a breaking one.
It ships together with `milpa/auth` 0.11.0, which has the same change for its own verifiers.)*

`LbuchsWebAuthnVerifier` told lbuchs not to require user verification, so a passkey that was touched but
never verified its user (no PIN, no biometric) registered and logged in. It is now required by default.

**What changed:**

| Before | After |
|---|---|
| UV flag ignored at registration and login | refused without UV, unless the verifier is built with `UserVerificationRequirement::Preferred` or `::Discouraged` |
| options advertised `WebAuthnRegistrationContext::$userVerification` / `WebAuthnAuthenticationContext::$userVerification` (default `'preferred'`) | options advertise `'required'` while the verifier demands UV; a relaxed verifier still advertises the context's value |
| a credential of actor B could answer a challenge issued for actor A when no `userHandle` came back | refused: `credential not allowed` |
| a credential id already in the store could be registered again | refused: `credential already registered` |
| origin checked with `in_array(..., $rp->allowedOrigins, true)` | `$rp->allowsOrigin()` — same exact-string rule, now owned by `milpa/auth` |
| `milpa/auth` `>=0.9 <1.0` | `milpa/auth` `>=0.11 <1.0` |

**To migrate:** most hosts change nothing. Build the `RelyingParty` so it passes `milpa/auth` 0.11's
validation (see its UPGRADING), and make sure the browser does not override the `userVerification`
the options carry. A house that admits authenticators without UV on purpose passes the requirement
explicitly:

```php
$verifier = new LbuchsWebAuthnVerifier(
    $challengeStore,
    $credentialStore,
    userVerification: UserVerificationRequirement::Preferred,
);
```

Credentials already registered keep working: nothing stored changes. What stops working is a ceremony
from an authenticator that does not verify its user, or a host that relied on one actor's challenge
being answered by another actor's credential.
