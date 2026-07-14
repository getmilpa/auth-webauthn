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

namespace Milpa\Auth\WebAuthn\Tests;

use Milpa\Auth\WebAuthn\CeremonyType;
use Milpa\Auth\WebAuthn\ChallengeRecord;
use PHPUnit\Framework\TestCase;

final class ChallengeRecordTest extends TestCase
{
    private function record(int $ttl = 120): ChallengeRecord
    {
        return new ChallengeRecord('ch-1', "\x01\x02\x03secret", CeremonyType::Authentication, new \DateTimeImmutable('2026-01-01T00:00:00Z'), $ttl);
    }

    public function testValueReturnsChallenge(): void
    {
        self::assertSame("\x01\x02\x03secret", $this->record()->value());
    }

    public function testDebugInfoRedacts(): void
    {
        self::assertSame('[redacted]', $this->record()->__debugInfo()['challenge']);
    }

    public function testSerializeThrows(): void
    {
        $this->expectException(\LogicException::class);
        serialize($this->record());
    }

    public function testCloneThrows(): void
    {
        $this->expectException(\LogicException::class);
        clone $this->record();
    }

    public function testMatchesIsConstantTime(): void
    {
        self::assertTrue($this->record()->matches("\x01\x02\x03secret"));
        self::assertFalse($this->record()->matches("wrong"));
    }

    public function testIsExpired(): void
    {
        $r = $this->record(120);
        self::assertFalse($r->isExpired(new \DateTimeImmutable('2026-01-01T00:01:00Z')));
        self::assertTrue($r->isExpired(new \DateTimeImmutable('2026-01-01T00:03:00Z')));
    }
}
