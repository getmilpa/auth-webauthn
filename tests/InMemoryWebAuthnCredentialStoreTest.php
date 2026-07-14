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

use Milpa\Auth\WebAuthn\Contracts\WebAuthnCredentialStore;
use Milpa\Auth\WebAuthn\InMemoryWebAuthnCredentialStore;
use Milpa\Auth\WebAuthn\WebAuthnCredentialRecord;
use PHPUnit\Framework\TestCase;

final class InMemoryWebAuthnCredentialStoreTest extends TestCase
{
    private \DateTimeImmutable $now;

    protected function setUp(): void
    {
        $this->now = new \DateTimeImmutable('2026-01-01T00:00:00Z');
    }

    private function rec(string $credentialId, string $actorId, int $signCount = 0): WebAuthnCredentialRecord
    {
        return new WebAuthnCredentialRecord($credentialId, "\x01key{$credentialId}", $signCount, $actorId, null, [], $this->now);
    }

    public function testIsAWebAuthnCredentialStore(): void
    {
        self::assertInstanceOf(WebAuthnCredentialStore::class, new InMemoryWebAuthnCredentialStore());
    }

    public function testSaveThenFindByCredentialIdRoundTrips(): void
    {
        $s = new InMemoryWebAuthnCredentialStore();
        $s->save($this->rec('cred-1', 'actor-a'));
        self::assertSame('cred-1', $s->findByCredentialId('cred-1')?->credentialId);
    }

    public function testFindByCredentialIdUnknownIsNull(): void
    {
        self::assertNull((new InMemoryWebAuthnCredentialStore())->findByCredentialId('nope'));
    }

    public function testListForActorReturnsOnlyThatActorsRecords(): void
    {
        $s = new InMemoryWebAuthnCredentialStore();
        $s->save($this->rec('cred-a1', 'actor-a'));
        $s->save($this->rec('cred-a2', 'actor-a'));
        $s->save($this->rec('cred-b1', 'actor-b'));

        $list = $s->listForActor('actor-a');
        self::assertCount(2, $list);
        self::assertSame(['cred-a1', 'cred-a2'], array_map(static fn (WebAuthnCredentialRecord $r): string => $r->credentialId, $list));
    }

    public function testUpdateSignCountChangesTheStoredCount(): void
    {
        $s = new InMemoryWebAuthnCredentialStore();
        $s->save($this->rec('cred-1', 'actor-a', 0));
        $s->updateSignCount('cred-1', 7);
        self::assertSame(7, $s->findByCredentialId('cred-1')?->signCount);
    }

    public function testUpdateSignCountIsANoOpWhenCredentialIdIsAbsent(): void
    {
        $s = new InMemoryWebAuthnCredentialStore();
        $s->updateSignCount('nope', 7);
        self::assertNull($s->findByCredentialId('nope'));
    }

    public function testUpdateSignCountRecordsANonMonotonicCountWithoutRejecting(): void
    {
        $s = new InMemoryWebAuthnCredentialStore();
        $s->save($this->rec('cred-1', 'actor-a', 10));
        $s->updateSignCount('cred-1', 3); // lower than before — a signal, never a gate
        self::assertSame(3, $s->findByCredentialId('cred-1')?->signCount);
    }

    public function testDuplicateCredentialIdRejected(): void
    {
        $s = new InMemoryWebAuthnCredentialStore();
        $s->save(new WebAuthnCredentialRecord('dup', 'k', 0, 'a1', null, [], new \DateTimeImmutable()));
        $this->expectException(\InvalidArgumentException::class);
        $s->save(new WebAuthnCredentialRecord('dup', 'k2', 0, 'a2', null, [], new \DateTimeImmutable()));
    }
}
