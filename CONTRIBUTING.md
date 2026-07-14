# Contributing to Milpa Auth-WebAuthn

Thanks for your interest in contributing! Milpa Auth-WebAuthn is passkey/WebAuthn for the Milpa
framework — the `WebAuthnVerifier`, `ChallengeStore` and `WebAuthnCredentialStore` contracts, the
ceremony value objects (`RelyingParty`, `CeremonyType`), in-memory defaults, and a `lbuchs/webauthn`
adapter. It sits one tier above `milpa/auth`: it depends on `milpa/auth` (the identity vocabulary)
and `lbuchs/webauthn` (the WebAuthn/FIDO2 protocol implementation), but zero framework, zero ORM.

## Getting started

```bash
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse src
php tools/validate-docblocks.php
```

These run in CI on PHP 8.3 and 8.4 (alongside `composer validate --strict` and a
`php -l` syntax pass); run them locally before opening a PR.

## Guidelines

- **PHP >= 8.3**, with `declare(strict_types=1);` in every file.
- **Document every public symbol.** A public class/interface/enum/trait or public
  method without a DocBlock summary fails CI (`tools/validate-docblocks.php`).
  Trivial accessors and magic methods are exempt.
- **A verified assertion mints a session — it is never a per-request transport.** The
  ceremony is not a bearer-token substitute; it produces a `milpa/auth` session once, at
  registration/authentication time. A change that would let a ceremony re-verify per request
  is a design regression, not a feature.
- **Fail-closed always.** An unresolved relying party, an expired or reused challenge, or an
  unverified attestation/assertion must **deny** — never inherit a laxer policy.
- **Respect the tier boundary.** `milpa/auth-webauthn` depends only on `milpa/auth` and
  `lbuchs/webauthn` (plus the PSR HTTP message interfaces) — no framework, no ORM. A change
  that would pull in a runtime dependency beyond that belongs elsewhere.
- **[Conventional Commits](https://www.conventionalcommits.org/)** — releases and
  the CHANGELOG are generated automatically from commit messages. Use
  `feat:` / `fix:` / `docs:` / `chore:` etc.; a breaking change to a public
  interface or capability schema is a `feat!:` / `BREAKING CHANGE:` (bumps MINOR
  while the package is `0.x`, MAJOR once it reaches `1.0`).

## Code style

The whole Milpa family (`milpa/core`, `milpa/http`, `milpa/tool-runtime`,
`milpa/data`, `milpa/auth`) shares one coding standard, committed verbatim in
every repo as `.php-cs-fixer.dist.php` and enforced by CI. In short:

- **[PSR-12](https://www.php-fig.org/psr/psr-12/) base**: 4 spaces (never tabs);
  opening braces on the **next line** for classes and methods, on the **same line**
  for control structures; one statement per line.
- **Family deltas on top of PSR-12**: short array syntax (`[]`), one space around
  string concatenation (`$a . $b`), fully-multiline method arguments when split,
  no unused imports, aligned/separated/trimmed PHPDoc tags, trailing commas in
  multiline constructs.

Check and fix locally before pushing:

```bash
vendor/bin/php-cs-fixer fix --dry-run --diff   # what CI runs
vendor/bin/php-cs-fixer fix                    # apply
```

Do not tweak `.php-cs-fixer.dist.php` in one package alone — the standard changes
in lockstep across the family or not at all.

## Pull requests

Keep PRs focused, add tests for behavior changes, and make sure the four commands
above are green. A maintainer will review and, once merged to `main`,
release-please will handle versioning.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).

---

Milpa is developed and maintained by [TeamX Agency](https://teamx.agency).
