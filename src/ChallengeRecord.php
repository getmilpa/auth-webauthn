<?php

/**
 * This file is part of Milpa Auth-WebAuthn — passkey/WebAuthn for the Milpa PHP framework.
 *
 * (c) Rodrigo Vicente - TeamX Agency — https://teamx.agency <hola@teamx.agency>
 *
 * @license Apache-2.0
 *
 * @link    https://github.com/getmilpa/auth-webauthn
 */

declare(strict_types=1);

namespace Milpa\Auth\WebAuthn;

/**
 * A single-use, expiring WebAuthn challenge, bound to a ceremony (and, for registration, to the target
 * actor). The challenge bytes are the secret the ceremony proves knowledge of, so they follow the
 * secret-bearing contract: private, redacted in dumps, non-serializable, non-clonable, one `value()`
 * exit. Compared in constant time. A {@see Contracts\ChallengeStore} holds it; the host store enforces
 * single use.
 */
final class ChallengeRecord
{
    public function __construct(
        public readonly string $id,
        #[\SensitiveParameter]
        private readonly string $challenge,
        public readonly CeremonyType $ceremonyType,
        public readonly \DateTimeImmutable $issuedAt,
        public readonly int $ttlSeconds,
        public readonly ?string $actorId = null,
    ) {
    }

    /** The one deliberate way to read the challenge bytes — for the verifier to match the ceremony. */
    public function value(): string
    {
        return $this->challenge;
    }

    /** Whether $candidate equals the challenge, compared in constant time (no early-exit leak). */
    public function matches(string $candidate): bool
    {
        return hash_equals($this->challenge, $candidate);
    }

    /** Whether this challenge has expired as of $now (issuedAt + ttl). Fail-closed: expired ⇒ unusable. */
    public function isExpired(\DateTimeImmutable $now): bool
    {
        return $now->getTimestamp() >= $this->issuedAt->getTimestamp() + $this->ttlSeconds;
    }

    /** @return array{id: string, ceremonyType: string, challenge: string} redacted for safe dumping */
    public function __debugInfo(): array
    {
        return ['id' => $this->id, 'ceremonyType' => $this->ceremonyType->value, 'challenge' => '[redacted]'];
    }

    public function __serialize(): array
    {
        throw new \LogicException('ChallengeRecord must not be serialized — it carries a one-time secret.');
    }

    public function __clone(): void
    {
        throw new \LogicException('ChallengeRecord must not be cloned — a challenge is single-use.');
    }
}
