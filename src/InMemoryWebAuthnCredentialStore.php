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

use Milpa\Auth\WebAuthn\Contracts\WebAuthnCredentialStore;

/**
 * The array-backed default {@see WebAuthnCredentialStore} — the `InMemorySessionStore` analog for
 * registered passkeys. Enforces global `credentialId` uniqueness on save and treats `updateSignCount`
 * as a plain recorder, never a gate. Not for production clustering (no cross-process atomicity) — a
 * host supplies a DB-backed store there.
 */
final class InMemoryWebAuthnCredentialStore implements WebAuthnCredentialStore
{
    /** @var array<string, WebAuthnCredentialRecord> */
    private array $records = [];

    /** Persist a newly registered credential. Rejects a duplicate credentialId (global uniqueness). */
    public function save(WebAuthnCredentialRecord $record): void
    {
        if (isset($this->records[$record->credentialId])) {
            throw new \InvalidArgumentException("Duplicate credentialId: {$record->credentialId}");
        }
        $this->records[$record->credentialId] = $record;
    }

    /** The credential with this id, or null if unknown (the usernameless/discoverable lookup). */
    public function findByCredentialId(string $credentialId): ?WebAuthnCredentialRecord
    {
        return $this->records[$credentialId] ?? null;
    }

    /**
     * The actor's credentials — builds a ceremony's allowCredentials.
     *
     * @return list<WebAuthnCredentialRecord>
     */
    public function listForActor(string $actorId): array
    {
        return array_values(array_filter(
            $this->records,
            static fn (WebAuthnCredentialRecord $r): bool => $r->actorId === $actorId,
        ));
    }

    /** Record the latest sign counter for a credential after an assertion (a signal, not a gate); no-op if absent. */
    public function updateSignCount(string $credentialId, int $signCount): void
    {
        $record = $this->records[$credentialId] ?? null;
        if ($record === null) {
            return;
        }
        $this->records[$credentialId] = $record->withSignCount($signCount);
    }
}
