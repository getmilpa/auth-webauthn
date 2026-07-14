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
use Milpa\Auth\WebAuthn\Contracts\ChallengeStore;
use Milpa\Auth\WebAuthn\InMemoryChallengeStore;
use PHPUnit\Framework\TestCase;

final class InMemoryChallengeStoreTest extends TestCase
{
    private \DateTimeImmutable $now;

    protected function setUp(): void
    {
        $this->now = new \DateTimeImmutable('2026-01-01T00:00:00Z');
    }

    private function store(): InMemoryChallengeStore
    {
        return new InMemoryChallengeStore(fn (): \DateTimeImmutable => $this->now);
    }

    private function rec(string $id, int $ttl = 120): ChallengeRecord
    {
        return new ChallengeRecord($id, "\x01secret{$id}", CeremonyType::Authentication, $this->now, $ttl);
    }

    public function testIsAChallengeStore(): void
    {
        self::assertInstanceOf(ChallengeStore::class, $this->store());
    }

    public function testConsumeReturnsThenIsSingleUse(): void
    {
        $s = $this->store();
        $s->issue($this->rec('a'));
        self::assertSame('a', $s->consume('a')?->id);
        self::assertNull($s->consume('a')); // single-use: gone on second consume
    }

    public function testConsumeAbsentIsNull(): void
    {
        self::assertNull($this->store()->consume('nope'));
    }

    public function testConsumeExpiredIsNull(): void
    {
        $s = $this->store();
        $s->issue($this->rec('e', 60));
        $this->now = new \DateTimeImmutable('2026-01-01T00:02:00Z'); // past ttl
        self::assertNull($s->consume('e')); // fail-closed on expiry
    }
}
