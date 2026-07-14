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

use Milpa\Auth\WebAuthn\ChallengeRecord;

/**
 * Where a single-use, expiring {@see ChallengeRecord} is held between the two round-trips of a WebAuthn
 * ceremony. Mirrors {@see \Milpa\Auth\Contracts\SessionStore}: the leaf declares WHAT the store does,
 * the host decides HOW. `consume` is fail-closed and single-use — a real (clustered) implementation
 * MUST make it atomic (delete-on-read) so a challenge cannot be replayed.
 */
interface ChallengeStore
{
    /** Store a freshly issued challenge for later single-use consumption. */
    public function issue(ChallengeRecord $record): void;

    /** Consume the challenge by id: return it once and invalidate it, or null if absent, expired, or already consumed. */
    public function consume(string $challengeId): ?ChallengeRecord;
}
