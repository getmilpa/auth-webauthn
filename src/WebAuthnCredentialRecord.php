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
 * The storage-agnostic record of a registered passkey — a credential's public key and metadata, owned
 * by an actor. Mirrors {@see \Milpa\Auth\SessionRecord}: the leaf-clean shape a
 * {@see Contracts\WebAuthnCredentialStore} moves, knowing nothing about where it is kept. The public
 * key is not a secret; `signCount` is a clone-detection SIGNAL, not an authorization gate.
 */
final readonly class WebAuthnCredentialRecord
{
    /** @param list<string> $transports the authenticator transports the browser reported */
    public function __construct(
        public string $credentialId,
        public string $publicKeyCose,
        public int $signCount,
        public string $actorId,
        public ?string $aaguid,
        public array $transports,
        public \DateTimeImmutable $createdAt,
        public ?\DateTimeImmutable $lastUsedAt = null,
    ) {
    }

    /** A copy with an updated sign counter (recorded on each assertion; never used to reject). */
    public function withSignCount(int $signCount): self
    {
        return new self($this->credentialId, $this->publicKeyCose, $signCount, $this->actorId, $this->aaguid, $this->transports, $this->createdAt, $this->lastUsedAt);
    }

    /** A copy stamped as just used at $now. */
    public function touch(\DateTimeImmutable $now): self
    {
        return new self($this->credentialId, $this->publicKeyCose, $this->signCount, $this->actorId, $this->aaguid, $this->transports, $this->createdAt, $now);
    }
}
