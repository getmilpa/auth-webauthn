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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * This package is the lbuchs adapter + in-memory stores. The four symbols app-docentes imports
 * must resolve from milpa/auth, and this tree must not ship a second definition.
 */
final class NamespaceAuthorityTest extends TestCase
{
    /** @return list<array{0: class-string, 1: bool}> */
    public static function appDocentesSymbols(): array
    {
        return [
            ['Milpa\\Auth\\WebAuthn\\RelyingParty', false],
            ['Milpa\\Auth\\WebAuthn\\Contracts\\WebAuthnVerifier', true],
            ['Milpa\\Auth\\WebAuthn\\WebAuthnAssertionResult', false],
            ['Milpa\\Auth\\WebAuthn\\WebAuthnAuthenticationResponse', false],
        ];
    }

    /** @param class-string $fqcn */
    #[DataProvider('appDocentesSymbols')]
    public function testAppDocentesSymbolResolvesOnceFromMilpaAuth(string $fqcn, bool $isInterface): void
    {
        if ($isInterface) {
            self::assertTrue(interface_exists($fqcn), $fqcn . ' must exist');
        } else {
            self::assertTrue(class_exists($fqcn), $fqcn . ' must exist');
        }

        $file = (new \ReflectionClass($fqcn))->getFileName();
        self::assertNotFalse($file);
        $real = realpath($file);
        self::assertNotFalse($real);

        $thisSrc = realpath(dirname(__DIR__) . '/src');
        self::assertNotFalse($thisSrc);
        self::assertFalse(
            str_starts_with($real, $thisSrc . DIRECTORY_SEPARATOR) || $real === $thisSrc,
            $fqcn . ' must not be defined in milpa/auth-webauthn (found ' . $real . ')',
        );
        self::assertStringContainsString(
            '/src/WebAuthn/',
            str_replace('\\', '/', $real),
            $fqcn . ' must resolve from milpa/auth src/WebAuthn (found ' . $real . ')',
        );
    }

    public function testThisPackageDoesNotShipTheCeremonyTypes(): void
    {
        $src = dirname(__DIR__) . '/src';
        foreach ([
            'RelyingParty.php',
            'WebAuthnAssertionResult.php',
            'WebAuthnAuthenticationResponse.php',
            'Contracts/WebAuthnVerifier.php',
        ] as $relative) {
            self::assertFileDoesNotExist($src . '/' . $relative, $relative . ' must live in milpa/auth, not here');
        }
    }

    public function testTheFourSymbolsAreInstantiableOrInterfaces(): void
    {
        $rp = new \Milpa\Auth\WebAuthn\RelyingParty('crm.example', 'Acme CRM', ['https://crm.example']);
        self::assertSame('crm.example', $rp->id);

        $response = new \Milpa\Auth\WebAuthn\WebAuthnAuthenticationResponse(
            'cred-b64',
            "\x01client",
            "\x02auth",
            "\x03sig",
            'user-handle',
        );
        self::assertSame('cred-b64', $response->credentialId);

        $result = new \Milpa\Auth\WebAuthn\WebAuthnAssertionResult('cred-b64', 'actor-1', 'user-handle', 1, false);
        self::assertSame('actor-1', $result->actorId);

        self::assertTrue((new \ReflectionClass(\Milpa\Auth\WebAuthn\Contracts\WebAuthnVerifier::class))->isInterface());
    }
}
