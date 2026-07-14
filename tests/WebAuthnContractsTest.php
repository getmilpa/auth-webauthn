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

use Milpa\Auth\Contracts\CredentialVerifier;
use Milpa\Auth\WebAuthn\Contracts\RelyingPartyResolver;
use Milpa\Auth\WebAuthn\Contracts\WebAuthnVerifier;
use Milpa\Auth\WebAuthn\Exceptions\WebAuthnCeremonyException;
use Milpa\Auth\WebAuthn\PublicKeyCredentialCreationOptions;
use Milpa\Auth\WebAuthn\PublicKeyCredentialRequestOptions;
use Milpa\Auth\WebAuthn\RelyingParty;
use Milpa\Auth\WebAuthn\WebAuthnAssertionResult;
use Milpa\Auth\WebAuthn\WebAuthnCredentialRecord;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class WebAuthnContractsTest extends TestCase
{
    public function testWebAuthnVerifierIsAnInterface(): void
    {
        self::assertTrue((new \ReflectionClass(WebAuthnVerifier::class))->isInterface());
    }

    /**
     * RED LINE: a passkey ceremony is stateful and two-round-trip — never a single-shot
     * per-request credential — so WebAuthnVerifier must NOT extend CredentialVerifier.
     */
    public function testWebAuthnVerifierDoesNotExtendCredentialVerifier(): void
    {
        self::assertFalse((new \ReflectionClass(WebAuthnVerifier::class))->isSubclassOf(CredentialVerifier::class));
    }

    public function testWebAuthnVerifierHasExactlyFourMethodsWithExactReturnTypes(): void
    {
        $reflection = new \ReflectionClass(WebAuthnVerifier::class);
        $methods = $reflection->getMethods();

        self::assertCount(4, $methods);

        $returnTypes = [];
        foreach ($methods as $method) {
            $returnTypes[$method->getName()] = (string) $method->getReturnType();
        }

        self::assertSame([
            'createRegistrationOptions' => PublicKeyCredentialCreationOptions::class,
            'verifyRegistration' => WebAuthnCredentialRecord::class,
            'createAuthenticationOptions' => PublicKeyCredentialRequestOptions::class,
            'verifyAuthentication' => WebAuthnAssertionResult::class,
        ], $returnTypes);
    }

    public function testRelyingPartyResolverResolvesToRelyingParty(): void
    {
        $reflection = new \ReflectionClass(RelyingPartyResolver::class);
        self::assertTrue($reflection->isInterface());

        $method = $reflection->getMethod('resolve');
        self::assertSame(RelyingParty::class, (string) $method->getReturnType());

        $parameters = $method->getParameters();
        self::assertCount(1, $parameters);
        self::assertSame(ServerRequestInterface::class, (string) $parameters[0]->getType());
    }

    public function testCeremonyExceptionRejectedNamesTheReasonNotASecret(): void
    {
        $exception = WebAuthnCeremonyException::rejected('bad origin');

        self::assertInstanceOf(\RuntimeException::class, $exception);
        self::assertStringContainsString('bad origin', $exception->getMessage());
    }
}
