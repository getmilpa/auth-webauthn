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
use Milpa\Auth\WebAuthn\RelyingParty;
use PHPUnit\Framework\TestCase;

final class RelyingPartyTest extends TestCase
{
    public function testHoldsIdNameOrigins(): void
    {
        $rp = new RelyingParty('acme.example', 'Acme', ['https://app.acme.example']);
        self::assertSame('acme.example', $rp->id);
        self::assertSame('Acme', $rp->name);
        self::assertContains('https://app.acme.example', $rp->allowedOrigins);
    }

    public function testCeremonyType(): void
    {
        self::assertSame('registration', CeremonyType::Registration->value);
        self::assertSame('authentication', CeremonyType::Authentication->value);
    }
}
