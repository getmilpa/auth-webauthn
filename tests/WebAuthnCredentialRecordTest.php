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

use Milpa\Auth\WebAuthn\WebAuthnCredentialRecord;
use PHPUnit\Framework\TestCase;

final class WebAuthnCredentialRecordTest extends TestCase
{
    private function record(): WebAuthnCredentialRecord
    {
        return new WebAuthnCredentialRecord('cred-b64', 'cose-bytes', 5, 'actor-uuid', 'aa-guid', ['internal'], new \DateTimeImmutable('2026-01-01T00:00:00Z'));
    }

    public function testHoldsFields(): void
    {
        $r = $this->record();
        self::assertSame('cred-b64', $r->credentialId);
        self::assertSame('actor-uuid', $r->actorId);
        self::assertSame(5, $r->signCount);
        self::assertContains('internal', $r->transports);
    }

    public function testWithSignCountIsImmutable(): void
    {
        $r = $this->record();
        $r2 = $r->withSignCount(9);
        self::assertSame(5, $r->signCount);
        self::assertSame(9, $r2->signCount);
        self::assertSame('cred-b64', $r2->credentialId);
    }
}
