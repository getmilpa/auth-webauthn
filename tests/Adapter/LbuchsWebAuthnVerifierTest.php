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

use lbuchs\WebAuthn\Binary\ByteBuffer;
use Milpa\Auth\Actor;
use Milpa\Auth\ActorType;
use Milpa\Auth\WebAuthn\Adapter\LbuchsWebAuthnVerifier;
use Milpa\Auth\WebAuthn\CeremonyType;
use Milpa\Auth\WebAuthn\Contracts\ChallengeStore;
use Milpa\Auth\WebAuthn\Contracts\WebAuthnCredentialStore;
use Milpa\Auth\WebAuthn\Exceptions\WebAuthnCeremonyException;
use Milpa\Auth\WebAuthn\InMemoryChallengeStore;
use Milpa\Auth\WebAuthn\InMemoryWebAuthnCredentialStore;
use Milpa\Auth\WebAuthn\RelyingParty;
use Milpa\Auth\WebAuthn\Tests\Support\RecordingChallengeStore;
use Milpa\Auth\WebAuthn\Tests\Support\TestAuthenticator;
use Milpa\Auth\WebAuthn\WebAuthnAuthenticationContext;
use Milpa\Auth\WebAuthn\WebAuthnAuthenticationResponse;
use Milpa\Auth\WebAuthn\WebAuthnCredentialRecord;
use Milpa\Auth\WebAuthn\WebAuthnRegistrationContext;
use Milpa\Auth\WebAuthn\WebAuthnRegistrationResponse;
use PHPUnit\Framework\TestCase;

/**
 * Tier 1 (UNIT): option-generation, every fail-closed branch, and the sign-counter clone SIGNAL. The
 * fail-closed branches short-circuit before lbuchs (no crypto). The two counter cases and the "second use"
 * case run REAL crypto through the real lbuchs boundary (via {@see TestAuthenticator}); no mock ever
 * replaces the cryptographic verification. Tier 2 is the dedicated end-to-end integration proof.
 */
final class LbuchsWebAuthnVerifierTest extends TestCase
{
    private const ORIGIN = 'https://acme.example';

    // ---------------------------------------------------------------------
    // Option generation
    // ---------------------------------------------------------------------

    public function testCreateRegistrationOptionsIssuesChallengeAndReturnsCreationOptions(): void
    {
        $challenges = new RecordingChallengeStore();
        $adapter = $this->adapter($challenges, new InMemoryWebAuthnCredentialStore(), 'registration-nonce-01');

        $options = $adapter->createRegistrationOptions(
            $this->actor('actor-1'),
            $this->rp(),
            new WebAuthnRegistrationContext('actor-1', 'user@acme.example', 'Ada Lovelace'),
        );

        self::assertCount(1, $challenges->issued);
        self::assertSame(CeremonyType::Registration, $challenges->issued[0]->ceremonyType);
        self::assertSame('actor-1', $challenges->issued[0]->actorId);

        $publicKey = $options->toArray()['publicKey'];
        self::assertArrayHasKey('challenge', $publicKey);
        self::assertArrayHasKey('rp', $publicKey);
        self::assertArrayHasKey('user', $publicKey);
    }

    public function testCreateAuthenticationOptionsListsAllowCredentialsForActor(): void
    {
        $credentials = new InMemoryWebAuthnCredentialStore();
        $id1 = $this->b64url('credential-one-raw');
        $id2 = $this->b64url('credential-two-raw');
        $credentials->save($this->credential($id1, 'actor-1'));
        $credentials->save($this->credential($id2, 'actor-1'));
        $credentials->save($this->credential($this->b64url('other-actor-raw'), 'actor-2'));

        $adapter = $this->adapter(new InMemoryChallengeStore(), $credentials, 'authentication-nonce-01');

        $options = $adapter->createAuthenticationOptions($this->rp(), new WebAuthnAuthenticationContext('actor-1'));

        $publicKey = $options->toArray()['publicKey'];
        self::assertArrayHasKey('allowCredentials', $publicKey);
        $allow = $publicKey['allowCredentials'];
        if (!is_array($allow)) {
            self::fail('allowCredentials must be an array');
        }
        self::assertCount(2, $allow);

        $gotIds = [];
        foreach ($allow as $entry) {
            if (!$entry instanceof \stdClass || !isset($entry->id) || !$entry->id instanceof ByteBuffer) {
                self::fail('allowCredentials entry is malformed');
            }
            $gotIds[] = $this->b64url($entry->id->getBinaryString());
        }
        $expected = [$id1, $id2];
        sort($expected);
        sort($gotIds);
        self::assertSame($expected, $gotIds);
    }

    // ---------------------------------------------------------------------
    // Fail-closed branches (each its own test) — short-circuit before lbuchs
    // ---------------------------------------------------------------------

    public function testVerifyRegistrationRejectsAlreadyConsumedChallenge(): void
    {
        $challenges = new InMemoryChallengeStore();
        $credentials = new InMemoryWebAuthnCredentialStore();
        $adapter = $this->adapter($challenges, $credentials, 'registration-nonce-consumed');
        $authenticator = new TestAuthenticator();

        $adapter->createRegistrationOptions(
            $this->actor('actor-1'),
            $this->rp(),
            new WebAuthnRegistrationContext('actor-1', 'user@acme.example', 'Ada'),
        );

        $response = new WebAuthnRegistrationResponse(
            $authenticator->credentialIdBase64Url(),
            $authenticator->clientDataJSON('webauthn.create', 'registration-nonce-consumed', self::ORIGIN),
            $authenticator->attestationObject($this->rp()->id, 0),
            ['internal'],
        );

        // First use: a genuine, crypto-verified registration consumes the challenge.
        $adapter->verifyRegistration($response, $this->rp());

        // Second use of the same (now consumed) challenge must fail-closed.
        $this->expectCeremonyRejected('challenge');
        $adapter->verifyRegistration($response, $this->rp());
    }

    public function testVerifyAuthenticationRejectsExpiredChallenge(): void
    {
        $issuedAt = new \DateTimeImmutable('2026-01-01T00:00:00Z');
        $storeClock = static fn (): \DateTimeImmutable => new \DateTimeImmutable('2026-01-01T00:05:00Z'); // +300s > ttl
        $challenges = new InMemoryChallengeStore($storeClock);
        $adapter = new LbuchsWebAuthnVerifier(
            $challenges,
            new InMemoryWebAuthnCredentialStore(),
            static fn (): \DateTimeImmutable => $issuedAt,
            static fn (): string => 'authentication-nonce-expired',
        );

        $adapter->createAuthenticationOptions($this->rp(), new WebAuthnAuthenticationContext('actor-1'));

        $response = $this->assertionResponse('authentication-nonce-expired', 'cred', self::ORIGIN, null);

        $this->expectCeremonyRejected('challenge');
        $adapter->verifyAuthentication($response, $this->rp());
    }

    public function testVerifyAuthenticationRejectsUnknownCredential(): void
    {
        $adapter = $this->adapter(new InMemoryChallengeStore(), new InMemoryWebAuthnCredentialStore(), 'authentication-nonce-unknown');
        $adapter->createAuthenticationOptions($this->rp(), new WebAuthnAuthenticationContext(null));

        $response = $this->assertionResponse('authentication-nonce-unknown', 'no-such-credential', self::ORIGIN, null);

        $this->expectCeremonyRejected('unknown credential');
        $adapter->verifyAuthentication($response, $this->rp());
    }

    public function testVerifyAuthenticationRejectsOriginNotOnAllowlist(): void
    {
        $adapter = $this->adapter(new InMemoryChallengeStore(), new InMemoryWebAuthnCredentialStore(), 'authentication-nonce-origin');
        $adapter->createAuthenticationOptions($this->rp(), new WebAuthnAuthenticationContext(null));

        $response = $this->assertionResponse('authentication-nonce-origin', 'cred', 'https://evil.example', null);

        $this->expectCeremonyRejected('origin');
        $adapter->verifyAuthentication($response, $this->rp());
    }

    public function testVerifyAuthenticationRejectsUserHandleMismatch(): void
    {
        $credentials = new InMemoryWebAuthnCredentialStore();
        $credentialId = $this->b64url('credential-owned-by-actor-1');
        $credentials->save($this->credential($credentialId, 'actor-1'));

        $adapter = $this->adapter(new InMemoryChallengeStore(), $credentials, 'authentication-nonce-handle');
        $adapter->createAuthenticationOptions($this->rp(), new WebAuthnAuthenticationContext('actor-1'));

        $response = $this->assertionResponse('authentication-nonce-handle', $credentialId, self::ORIGIN, 'actor-999');

        $this->expectCeremonyRejected('user handle mismatch');
        $adapter->verifyAuthentication($response, $this->rp());
    }

    // ---------------------------------------------------------------------
    // Sign-counter clone SIGNAL (real crypto; both branches SUCCEED)
    // ---------------------------------------------------------------------

    public function testNonIncrementingCounterFlagsCloneWarningButStillSucceeds(): void
    {
        [$adapter, $authenticator, $credentials, $rp] = $this->ceremonyFixture(['reg-clone', 'auth-clone']);

        // Register with a stored counter of 10.
        $record = $this->register($adapter, $authenticator, $rp, 'reg-clone', signCount: 10);
        self::assertSame(10, $record->signCount);
        $credentials->save($record);

        // Assert with a NON-ZERO counter of 5 (<= stored) — the clone signal. lbuchs verifies the real
        // signature and does NOT throw (prevSignatureCnt is null); the adapter raises cloneWarning.
        $result = $this->authenticate($adapter, $authenticator, $rp, 'auth-clone', assertionSignCount: 5, userHandle: 'actor-1');

        self::assertTrue($result->cloneWarning);
        self::assertSame(5, $result->newSignCount);
        self::assertSame($authenticator->credentialIdBase64Url(), $result->credentialId);
        self::assertSame('actor-1', $result->actorId);
    }

    public function testZeroCounterIsSyncedPasskeyWithoutCloneWarning(): void
    {
        [$adapter, $authenticator, $credentials, $rp] = $this->ceremonyFixture(['reg-synced', 'auth-synced']);

        $record = $this->register($adapter, $authenticator, $rp, 'reg-synced', signCount: 0);
        self::assertSame(0, $record->signCount);
        $credentials->save($record);

        // A synced passkey reports counter 0 on every assertion — never a clone, never a warning, no throw.
        $result = $this->authenticate($adapter, $authenticator, $rp, 'auth-synced', assertionSignCount: 0, userHandle: 'actor-1');

        self::assertFalse($result->cloneWarning);
        self::assertSame(0, $result->newSignCount);
    }

    public function testNonZeroStoredThenZeroReportedCounterDoesNotFalsePositive(): void
    {
        [$adapter, $authenticator, $credentials, $rp] = $this->ceremonyFixture(['reg-nz-sync', 'auth-nz-sync']);

        // Stored counter is a non-zero 7.
        $record = $this->register($adapter, $authenticator, $rp, 'reg-nz-sync', signCount: 7);
        self::assertSame(7, $record->signCount);
        $credentials->save($record);

        // The authenticator now reports a ZERO counter (e.g. it became a synced passkey). lbuchs returns a
        // null counter — the clone signal must be judged on the REPORTED value, not the stored fallback, so
        // there is NO spurious warning, and the recorded count falls back to the stored 7.
        $result = $this->authenticate($adapter, $authenticator, $rp, 'auth-nz-sync', assertionSignCount: 0, userHandle: 'actor-1');

        self::assertFalse($result->cloneWarning);
        self::assertSame(7, $result->newSignCount);
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private function rp(): RelyingParty
    {
        return new RelyingParty('acme.example', 'ACME Corp', [self::ORIGIN]);
    }

    private function actor(string $id): Actor
    {
        return new Actor($id, ActorType::User);
    }

    private function adapter(ChallengeStore $challenges, WebAuthnCredentialStore $credentials, string $nonce): LbuchsWebAuthnVerifier
    {
        return new LbuchsWebAuthnVerifier(
            $challenges,
            $credentials,
            static fn (): \DateTimeImmutable => new \DateTimeImmutable(),
            static fn (): string => $nonce,
        );
    }

    private function credential(string $credentialId, string $actorId): WebAuthnCredentialRecord
    {
        return new WebAuthnCredentialRecord(
            $credentialId,
            '-----BEGIN PUBLIC KEY-----\nunused-for-this-path\n-----END PUBLIC KEY-----',
            0,
            $actorId,
            null,
            ['internal'],
            new \DateTimeImmutable('2026-01-01T00:00:00Z'),
        );
    }

    private function assertionResponse(string $nonce, string $credentialId, string $origin, ?string $userHandle): WebAuthnAuthenticationResponse
    {
        $clientDataJSON = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $this->b64url($nonce),
            'origin' => $origin,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return new WebAuthnAuthenticationResponse($credentialId, $clientDataJSON, 'authenticator-data', 'signature-bytes', $userHandle);
    }

    /**
     * @param list<string> $nonces
     *
     * @return array{0: LbuchsWebAuthnVerifier, 1: TestAuthenticator, 2: InMemoryWebAuthnCredentialStore, 3: RelyingParty}
     */
    private function ceremonyFixture(array $nonces): array
    {
        $credentials = new InMemoryWebAuthnCredentialStore();
        $index = 0;
        $adapter = new LbuchsWebAuthnVerifier(
            new InMemoryChallengeStore(),
            $credentials,
            static fn (): \DateTimeImmutable => new \DateTimeImmutable(),
            static function () use (&$index, $nonces): string {
                $nonce = $nonces[$index] ?? throw new \LogicException('nonce queue exhausted');
                ++$index;

                return $nonce;
            },
        );

        return [$adapter, new TestAuthenticator(), $credentials, $this->rp()];
    }

    private function register(LbuchsWebAuthnVerifier $adapter, TestAuthenticator $authenticator, RelyingParty $rp, string $nonce, int $signCount): WebAuthnCredentialRecord
    {
        $adapter->createRegistrationOptions(
            $this->actor('actor-1'),
            $rp,
            new WebAuthnRegistrationContext('actor-1', 'user@acme.example', 'Ada'),
        );

        return $adapter->verifyRegistration(
            new WebAuthnRegistrationResponse(
                $authenticator->credentialIdBase64Url(),
                $authenticator->clientDataJSON('webauthn.create', $nonce, self::ORIGIN),
                $authenticator->attestationObject($rp->id, $signCount),
                ['internal'],
            ),
            $rp,
        );
    }

    private function authenticate(LbuchsWebAuthnVerifier $adapter, TestAuthenticator $authenticator, RelyingParty $rp, string $nonce, int $assertionSignCount, ?string $userHandle): \Milpa\Auth\WebAuthn\WebAuthnAssertionResult
    {
        $adapter->createAuthenticationOptions($rp, new WebAuthnAuthenticationContext('actor-1'));

        $authData = $authenticator->assertionAuthData($rp->id, $assertionSignCount);
        $clientDataJSON = $authenticator->clientDataJSON('webauthn.get', $nonce, self::ORIGIN);
        $signature = $authenticator->sign($authData, $clientDataJSON);

        return $adapter->verifyAuthentication(
            new WebAuthnAuthenticationResponse($authenticator->credentialIdBase64Url(), $clientDataJSON, $authData, $signature, $userHandle),
            $rp,
        );
    }

    private function expectCeremonyRejected(string $reason): void
    {
        $this->expectException(WebAuthnCeremonyException::class);
        $this->expectExceptionMessage('rejected: ' . $reason);
    }

    private function b64url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
