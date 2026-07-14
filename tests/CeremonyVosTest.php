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

use Milpa\Auth\WebAuthn\PublicKeyCredentialCreationOptions;
use Milpa\Auth\WebAuthn\PublicKeyCredentialRequestOptions;
use Milpa\Auth\WebAuthn\WebAuthnAssertionResult;
use Milpa\Auth\WebAuthn\WebAuthnAuthenticationContext;
use Milpa\Auth\WebAuthn\WebAuthnAuthenticationResponse;
use Milpa\Auth\WebAuthn\WebAuthnRegistrationContext;
use Milpa\Auth\WebAuthn\WebAuthnRegistrationResponse;
use PHPUnit\Framework\TestCase;

final class CeremonyVosTest extends TestCase
{
    private function authenticationResponse(?string $userHandle = 'user-handle-b64-acme'): WebAuthnAuthenticationResponse
    {
        return new WebAuthnAuthenticationResponse(
            'cred-b64-acme',
            "\x01client-data-bytes",
            "\x02authenticator-data-bytes",
            "\x03\x04signature-bytes",
            $userHandle,
        );
    }

    public function testCreationOptionsRoundTripsPublicKey(): void
    {
        $publicKey = ['rp' => ['id' => 'acme.example', 'name' => 'Acme'], 'challenge' => 'ch-b64'];
        $options = new PublicKeyCredentialCreationOptions($publicKey);

        self::assertSame($publicKey, $options->publicKey);
        self::assertSame(['publicKey' => $publicKey], $options->toArray());
    }

    public function testRequestOptionsRoundTripsPublicKey(): void
    {
        $publicKey = ['rpId' => 'acme.example', 'challenge' => 'ch-b64', 'allowCredentials' => []];
        $options = new PublicKeyCredentialRequestOptions($publicKey);

        self::assertSame($publicKey, $options->publicKey);
        self::assertSame(['publicKey' => $publicKey], $options->toArray());
    }

    public function testRegistrationResponseHoldsRawBytesByteExact(): void
    {
        $response = new WebAuthnRegistrationResponse(
            'cred-b64-acme',
            "\x01\x02client-data-bytes",
            "\x03\x04attestation-object-bytes",
            ['internal', 'hybrid'],
        );

        self::assertSame('cred-b64-acme', $response->credentialId);
        self::assertSame("\x01\x02client-data-bytes", $response->clientDataJSON);
        self::assertSame("\x03\x04attestation-object-bytes", $response->attestationObject);
        self::assertSame(['internal', 'hybrid'], $response->transports);
    }

    public function testAuthenticationResponseHoldsRawFieldsAndSignatureIsReadable(): void
    {
        $response = $this->authenticationResponse();

        self::assertSame('cred-b64-acme', $response->credentialId);
        self::assertSame("\x01client-data-bytes", $response->clientDataJSON);
        self::assertSame("\x02authenticator-data-bytes", $response->authenticatorData);
        self::assertSame('user-handle-b64-acme', $response->userHandle);
        self::assertSame("\x03\x04signature-bytes", $response->signature());
    }

    public function testAuthenticationResponseDebugInfoRedactsSignature(): void
    {
        $debug = $this->authenticationResponse(null)->__debugInfo();

        self::assertSame('[redacted]', $debug['signature']);
        self::assertSame('cred-b64-acme', $debug['credentialId']);
        self::assertNull($debug['userHandle']);
    }

    public function testAuthenticationResponseSerializeThrows(): void
    {
        $this->expectException(\LogicException::class);
        serialize($this->authenticationResponse(null));
    }

    public function testAuthenticationResponseCloneThrows(): void
    {
        $this->expectException(\LogicException::class);
        clone $this->authenticationResponse(null);
    }

    public function testRegistrationContextHoldsFields(): void
    {
        $context = new WebAuthnRegistrationContext('user-handle-b64-acme', 'acme-user', 'Acme User');

        self::assertSame('user-handle-b64-acme', $context->userHandle);
        self::assertSame('acme-user', $context->userName);
        self::assertSame('Acme User', $context->userDisplayName);
        self::assertSame('preferred', $context->userVerification);
    }

    public function testAuthenticationContextHoldsFieldsAndDefaults(): void
    {
        $context = new WebAuthnAuthenticationContext('actor-uuid-acme', 'required');
        self::assertSame('actor-uuid-acme', $context->actorId);
        self::assertSame('required', $context->userVerification);

        $default = new WebAuthnAuthenticationContext();
        self::assertNull($default->actorId);
        self::assertSame('preferred', $default->userVerification);
    }

    public function testAssertionResultHoldsFields(): void
    {
        $result = new WebAuthnAssertionResult('cred-b64-acme', 'actor-uuid-acme', 'user-handle-b64-acme', 7, false);

        self::assertSame('cred-b64-acme', $result->credentialId);
        self::assertSame('actor-uuid-acme', $result->actorId);
        self::assertSame('user-handle-b64-acme', $result->userHandle);
        self::assertSame(7, $result->newSignCount);
        self::assertFalse($result->cloneWarning);
    }

    public function testAssertionResultCloneWarningSignalsAnomaly(): void
    {
        $result = new WebAuthnAssertionResult('cred-b64-acme', 'actor-uuid-acme', null, 3, true);

        self::assertTrue($result->cloneWarning);
        self::assertNull($result->userHandle);
    }
}
