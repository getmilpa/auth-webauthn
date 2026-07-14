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

namespace Milpa\Auth\WebAuthn\Contracts;

use Milpa\Auth\WebAuthn\WebAuthnCredentialRecord;

/**
 * The registry of registered passkeys — the WebAuthn public-key store. Mirrors
 * {@see \Milpa\Auth\Contracts\SessionStore}: the leaf declares WHAT it needs, the host implements HOW
 * (Doctrine, etc.). Two invariants the contract REQUIRES and the implementation MUST enforce: global
 * `credentialId` uniqueness (usernameless login resolves a user by credential id alone), and that
 * `updateSignCount` records the latest counter — which is a clone-detection SIGNAL, never an
 * authorization gate.
 */
interface WebAuthnCredentialStore
{
    /** Persist a newly registered credential. MUST reject a duplicate credentialId (global uniqueness). */
    public function save(WebAuthnCredentialRecord $record): void;

    /** The credential with this id, or null if unknown (the usernameless/discoverable lookup). */
    public function findByCredentialId(string $credentialId): ?WebAuthnCredentialRecord;

    /**
     * The actor's credentials — builds a ceremony's allowCredentials.
     *
     * @return list<WebAuthnCredentialRecord>
     */
    public function listForActor(string $actorId): array;

    /** Record the latest sign counter for a credential after an assertion (a signal, not a gate). */
    public function updateSignCount(string $credentialId, int $signCount): void;
}
