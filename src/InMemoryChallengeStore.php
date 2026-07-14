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

use Milpa\Auth\WebAuthn\Contracts\ChallengeStore;

/**
 * The array-backed default {@see ChallengeStore} — the `InMemorySessionStore` analog for challenges.
 * Single-use (a consumed id is removed) and fail-closed on expiry, with an injectable clock for
 * deterministic tests. Not for production clustering (no cross-process atomicity) — a host supplies a
 * DB-backed store there.
 */
final class InMemoryChallengeStore implements ChallengeStore
{
    /** @var array<string, ChallengeRecord> */
    private array $records = [];
    /** @var callable(): \DateTimeImmutable */
    private $clock;

    /** @param (callable(): \DateTimeImmutable)|null $clock defaults to a real "now" */
    public function __construct(?callable $clock = null)
    {
        $this->clock = $clock ?? static fn (): \DateTimeImmutable => new \DateTimeImmutable();
    }

    /** Store a freshly issued challenge for later single-use consumption. */
    public function issue(ChallengeRecord $record): void
    {
        $this->records[$record->id] = $record;
    }

    /** Consume the challenge by id: return it once and invalidate it, or null if absent, expired, or already consumed. */
    public function consume(string $challengeId): ?ChallengeRecord
    {
        $record = $this->records[$challengeId] ?? null;
        if ($record === null) {
            return null;
        }
        unset($this->records[$challengeId]); // single-use: gone whether or not it was still valid
        if ($record->isExpired(($this->clock)())) {
            return null;
        }

        return $record;
    }
}
