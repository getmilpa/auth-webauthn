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

namespace Milpa\Auth\WebAuthn\Tests\Support;

use Milpa\Auth\WebAuthn\ChallengeRecord;
use Milpa\Auth\WebAuthn\Contracts\ChallengeStore;
use Milpa\Auth\WebAuthn\InMemoryChallengeStore;

/**
 * A {@see ChallengeStore} that captures every issued {@see ChallengeRecord} for inspection while delegating
 * real single-use / expiry semantics to an inner {@see InMemoryChallengeStore}. Test-only.
 */
final class RecordingChallengeStore implements ChallengeStore
{
    /** @var list<ChallengeRecord> */
    public array $issued = [];

    public function __construct(private readonly InMemoryChallengeStore $inner = new InMemoryChallengeStore())
    {
    }

    public function issue(ChallengeRecord $record): void
    {
        $this->issued[] = $record;
        $this->inner->issue($record);
    }

    public function consume(string $challengeId): ?ChallengeRecord
    {
        return $this->inner->consume($challengeId);
    }
}
