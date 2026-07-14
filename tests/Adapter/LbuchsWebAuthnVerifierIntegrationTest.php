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

namespace Milpa\Auth\WebAuthn\Tests\Adapter;

use Milpa\Auth\Actor;
use Milpa\Auth\ActorType;
use Milpa\Auth\WebAuthn\Adapter\LbuchsWebAuthnVerifier;
use Milpa\Auth\WebAuthn\Exceptions\WebAuthnCeremonyException;
use Milpa\Auth\WebAuthn\InMemoryChallengeStore;
use Milpa\Auth\WebAuthn\InMemoryWebAuthnCredentialStore;
use Milpa\Auth\WebAuthn\RelyingParty;
use Milpa\Auth\WebAuthn\Tests\Support\TestAuthenticator;
use Milpa\Auth\WebAuthn\WebAuthnAuthenticationContext;
use Milpa\Auth\WebAuthn\WebAuthnAuthenticationResponse;
use Milpa\Auth\WebAuthn\WebAuthnCredentialRecord;
use Milpa\Auth\WebAuthn\WebAuthnRegistrationContext;
use Milpa\Auth\WebAuthn\WebAuthnRegistrationResponse;
use PHPUnit\Framework\TestCase;

/**
 * Tier 2 (INTEGRATION) — THE crypto-verification gate. Every test here drives the real
 * `lbuchs\WebAuthn\WebAuthn` end-to-end. The vectors are produced in-test by a genuine software
 * authenticator ({@see TestAuthenticator}) holding a REAL ES256/P-256 key pair: a real fmt-`'none'`
 * attestation object (with a real COSE public key derived from that key) and a real ECDSA/SHA-256
 * assertion signature over `authenticatorData || SHA-256(clientDataJSON)`. lbuchs performs the CBOR
 * decode, the COSE→PEM conversion, and the signature verification — no seam, no mock stands in for the
 * cryptographic boundary. The tamper test proves the boundary actually rejects.
 */
final class LbuchsWebAuthnVerifierIntegrationTest extends TestCase
{
    private const ORIGIN = 'https://acme.example';
    private const AAGUID_RAW = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10";

    public function testRealAttestationThenRealAssertionAreVerifiedByLbuchs(): void
    {
        $rp = $this->rp();
        $challenges = new InMemoryChallengeStore();
        $credentials = new InMemoryWebAuthnCredentialStore();
        $authenticator = new TestAuthenticator(random_bytes(24), self::AAGUID_RAW);

        // ---- Registration: real attestation object verified by lbuchs::processCreate ----
        $regAdapter = $this->adapter($challenges, $credentials, 'integration-registration-nonce');
        $regAdapter->createRegistrationOptions(
            new Actor('actor-42', ActorType::User),
            $rp,
            new WebAuthnRegistrationContext('actor-42', 'user@acme.example', 'Grace Hopper'),
        );

        $record = $regAdapter->verifyRegistration(
            new WebAuthnRegistrationResponse(
                $authenticator->credentialIdBase64Url(),
                $authenticator->clientDataJSON('webauthn.create', 'integration-registration-nonce', self::ORIGIN),
                $authenticator->attestationObject($rp->id, signCount: 0),
                ['internal', 'hybrid'],
            ),
            $rp,
        );

        self::assertSame($authenticator->credentialIdBase64Url(), $record->credentialId);
        self::assertSame('actor-42', $record->actorId);
        self::assertSame($authenticator->aaguidUuid(), $record->aaguid);
        self::assertSame(0, $record->signCount);
        self::assertStringContainsString('BEGIN PUBLIC KEY', $record->publicKeyCose);
        // The PEM lbuchs derived from the COSE key must be a usable EC public key.
        self::assertNotFalse(openssl_pkey_get_public($record->publicKeyCose));

        $credentials->save($record);

        // ---- Authentication: real assertion signature verified by lbuchs::processGet ----
        $authAdapter = $this->adapter($challenges, $credentials, 'integration-authentication-nonce');
        $authAdapter->createAuthenticationOptions($rp, new WebAuthnAuthenticationContext('actor-42'));

        $authData = $authenticator->assertionAuthData($rp->id, signCount: 1);
        $clientDataJSON = $authenticator->clientDataJSON('webauthn.get', 'integration-authentication-nonce', self::ORIGIN);
        $signature = $authenticator->sign($authData, $clientDataJSON);

        $result = $authAdapter->verifyAuthentication(
            new WebAuthnAuthenticationResponse($authenticator->credentialIdBase64Url(), $clientDataJSON, $authData, $signature, 'actor-42'),
            $rp,
        );

        self::assertSame($authenticator->credentialIdBase64Url(), $result->credentialId);
        self::assertSame('actor-42', $result->actorId);
        self::assertSame('actor-42', $result->userHandle);
        self::assertSame(1, $result->newSignCount);
        self::assertFalse($result->cloneWarning);
    }

    public function testTamperedSignatureIsRejectedByTheCryptoBoundary(): void
    {
        $rp = $this->rp();
        $challenges = new InMemoryChallengeStore();
        $credentials = new InMemoryWebAuthnCredentialStore();
        $authenticator = new TestAuthenticator(random_bytes(24), self::AAGUID_RAW);

        $credentials->save($this->registerReal($challenges, $credentials, $authenticator, $rp));

        $authAdapter = $this->adapter($challenges, $credentials, 'tamper-authentication-nonce');
        $authAdapter->createAuthenticationOptions($rp, new WebAuthnAuthenticationContext('actor-42'));

        $authData = $authenticator->assertionAuthData($rp->id, signCount: 1);
        $clientDataJSON = $authenticator->clientDataJSON('webauthn.get', 'tamper-authentication-nonce', self::ORIGIN);
        $signature = $authenticator->sign($authData, $clientDataJSON);
        $tampered = $this->flipLastByte($signature);
        self::assertNotSame($signature, $tampered);

        // The challenge, origin, credential and user-handle all pass — only the signature is corrupted, so
        // lbuchs' real ECDSA verification is what rejects it.
        $this->expectException(WebAuthnCeremonyException::class);
        $this->expectExceptionMessage('rejected: assertion');
        $authAdapter->verifyAuthentication(
            new WebAuthnAuthenticationResponse($authenticator->credentialIdBase64Url(), $clientDataJSON, $authData, $tampered, 'actor-42'),
            $rp,
        );
    }

    public function testAssertionForADifferentChallengeIsRejected(): void
    {
        $rp = $this->rp();
        $challenges = new InMemoryChallengeStore();
        $credentials = new InMemoryWebAuthnCredentialStore();
        $authenticator = new TestAuthenticator(random_bytes(24), self::AAGUID_RAW);

        $credentials->save($this->registerReal($challenges, $credentials, $authenticator, $rp));

        $authAdapter = $this->adapter($challenges, $credentials, 'issued-authentication-nonce');
        $authAdapter->createAuthenticationOptions($rp, new WebAuthnAuthenticationContext('actor-42'));

        // A perfectly-signed assertion, but over a challenge that was never issued.
        $authData = $authenticator->assertionAuthData($rp->id, signCount: 1);
        $clientDataJSON = $authenticator->clientDataJSON('webauthn.get', 'a-challenge-never-issued', self::ORIGIN);
        $signature = $authenticator->sign($authData, $clientDataJSON);

        // Rejected at the adapter's single-use store gate: the derived id sha256('a-challenge-never-issued')
        // is absent from the store, so consume() returns null. This is strictly stronger than lbuchs' own
        // challenge check (which is unreachable here — because the id is sha256(nonce), an id-match already
        // implies a value-match, so a forged challenge can never reach processGet in the first place).
        $this->expectException(WebAuthnCeremonyException::class);
        $this->expectExceptionMessage('rejected: challenge');
        $authAdapter->verifyAuthentication(
            new WebAuthnAuthenticationResponse($authenticator->credentialIdBase64Url(), $clientDataJSON, $authData, $signature, 'actor-42'),
            $rp,
        );
    }

    public function testAssertionSignedForADifferentRpIdIsRejectedByLbuchs(): void
    {
        $rp = $this->rp(); // rpId 'acme.example'
        $challenges = new InMemoryChallengeStore();
        $credentials = new InMemoryWebAuthnCredentialStore();
        $authenticator = new TestAuthenticator(random_bytes(24), self::AAGUID_RAW);

        $credentials->save($this->registerReal($challenges, $credentials, $authenticator, $rp));

        $authAdapter = $this->adapter($challenges, $credentials, 'rpid-mismatch-nonce');
        $authAdapter->createAuthenticationOptions($rp, new WebAuthnAuthenticationContext('actor-42'));

        // A REAL signature, but over authenticatorData whose rpIdHash is for a DIFFERENT relying party. The
        // challenge, origin, credential and user-handle all pass the adapter gates, so lbuchs reaches — and
        // rejects at — its rpIdHash check (which runs before the signature check). Proves rpId binding is
        // load-bearing, not merely the origin allowlist.
        $foreignAuthData = $authenticator->assertionAuthData('evil-rp.example', signCount: 1);
        $clientDataJSON = $authenticator->clientDataJSON('webauthn.get', 'rpid-mismatch-nonce', self::ORIGIN);
        $signature = $authenticator->sign($foreignAuthData, $clientDataJSON);

        $this->expectException(WebAuthnCeremonyException::class);
        $this->expectExceptionMessage('rejected: assertion');
        $authAdapter->verifyAuthentication(
            new WebAuthnAuthenticationResponse($authenticator->credentialIdBase64Url(), $clientDataJSON, $foreignAuthData, $signature, 'actor-42'),
            $rp,
        );
    }

    private function rp(): RelyingParty
    {
        return new RelyingParty('acme.example', 'ACME Corp', [self::ORIGIN]);
    }

    private function adapter(InMemoryChallengeStore $challenges, InMemoryWebAuthnCredentialStore $credentials, string $nonce): LbuchsWebAuthnVerifier
    {
        return new LbuchsWebAuthnVerifier(
            $challenges,
            $credentials,
            static fn (): \DateTimeImmutable => new \DateTimeImmutable(),
            static fn (): string => $nonce,
        );
    }

    private function registerReal(InMemoryChallengeStore $challenges, InMemoryWebAuthnCredentialStore $credentials, TestAuthenticator $authenticator, RelyingParty $rp): WebAuthnCredentialRecord
    {
        $adapter = $this->adapter($challenges, $credentials, 'setup-registration-nonce');
        $adapter->createRegistrationOptions(
            new Actor('actor-42', ActorType::User),
            $rp,
            new WebAuthnRegistrationContext('actor-42', 'user@acme.example', 'Grace Hopper'),
        );

        return $adapter->verifyRegistration(
            new WebAuthnRegistrationResponse(
                $authenticator->credentialIdBase64Url(),
                $authenticator->clientDataJSON('webauthn.create', 'setup-registration-nonce', self::ORIGIN),
                $authenticator->attestationObject($rp->id, signCount: 0),
                ['internal'],
            ),
            $rp,
        );
    }

    private function flipLastByte(string $bytes): string
    {
        $last = strlen($bytes) - 1;
        $bytes[$last] = chr(ord($bytes[$last]) ^ 0xFF);

        return $bytes;
    }
}
