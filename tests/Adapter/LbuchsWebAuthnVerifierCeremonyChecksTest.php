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
 * The WebAuthn L2 §7.1 (registration) and §7.2 (assertion) checks, one at a time, through REAL crypto. Each
 * test builds a ceremony that is valid in every respect but one, so the rejection can only come from the
 * check under test — whether the adapter makes it or lbuchs makes it on the adapter's behalf.
 */
final class LbuchsWebAuthnVerifierCeremonyChecksTest extends TestCase
{
    private const ORIGIN = 'https://acme.example';

    // ---------------------------------------------------------------------
    // User verification (§7.1 step 15, §7.2 step 17)
    // ---------------------------------------------------------------------

    public function testAssertionWithoutUserVerificationIsRejected(): void
    {
        [$adapter, $authenticator, $rp] = $this->registered(['reg-no-uv', 'auth-no-uv']);

        $this->expectCeremonyRejected('assertion');
        $this->assertWith($adapter, $authenticator, $rp, 'auth-no-uv', flags: TestAuthenticator::FLAG_UP);
    }

    public function testRegistrationWithoutUserVerificationIsRejected(): void
    {
        $adapter = $this->adapter(['reg-no-uv']);
        $authenticator = new TestAuthenticator();

        $this->expectCeremonyRejected('attestation');
        $this->registerWith($adapter, $authenticator, $this->rp(), 'reg-no-uv', flags: TestAuthenticator::FLAG_UP);
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private function rp(): RelyingParty
    {
        return new RelyingParty('acme.example', 'ACME Corp', [self::ORIGIN]);
    }

    /**
     * An adapter whose nonce source hands out the given nonces in order, sharing one store per test.
     *
     * @param list<string> $nonces
     */
    private function adapter(array $nonces, ?InMemoryWebAuthnCredentialStore $credentials = null): LbuchsWebAuthnVerifier
    {
        $index = 0;

        return new LbuchsWebAuthnVerifier(
            new InMemoryChallengeStore(),
            $credentials ?? new InMemoryWebAuthnCredentialStore(),
            static fn (): \DateTimeImmutable => new \DateTimeImmutable(),
            static function () use (&$index, $nonces): string {
                $nonce = $nonces[$index] ?? throw new \LogicException('nonce queue exhausted');
                ++$index;

                return $nonce;
            },
        );
    }

    /**
     * An adapter with one genuinely registered credential (UP|UV), ready for its authentication ceremony.
     *
     * @param array{0: string, 1: string} $nonces registration nonce, then authentication nonce
     *
     * @return array{0: LbuchsWebAuthnVerifier, 1: TestAuthenticator, 2: RelyingParty}
     */
    private function registered(array $nonces): array
    {
        $credentials = new InMemoryWebAuthnCredentialStore();
        $adapter = $this->adapter($nonces, $credentials);
        $authenticator = new TestAuthenticator();
        $rp = $this->rp();

        $credentials->save($this->registerWith($adapter, $authenticator, $rp, $nonces[0]));

        return [$adapter, $authenticator, $rp];
    }

    private function registerWith(
        LbuchsWebAuthnVerifier $adapter,
        TestAuthenticator $authenticator,
        RelyingParty $rp,
        string $nonce,
        int $flags = TestAuthenticator::FLAG_UP | TestAuthenticator::FLAG_UV,
        string $type = 'webauthn.create',
        ?string $origin = null,
        ?string $authenticatorRpId = null,
    ): WebAuthnCredentialRecord {
        $adapter->createRegistrationOptions(
            new Actor('actor-1', ActorType::User),
            $rp,
            new WebAuthnRegistrationContext('actor-1', 'user@acme.example', 'Ada'),
        );

        return $adapter->verifyRegistration(
            new WebAuthnRegistrationResponse(
                $authenticator->credentialIdBase64Url(),
                $authenticator->clientDataJSON($type, $nonce, $origin ?? self::ORIGIN),
                $authenticator->attestationObject($authenticatorRpId ?? $rp->id, 0, $flags),
                ['internal'],
            ),
            $rp,
        );
    }

    private function assertWith(
        LbuchsWebAuthnVerifier $adapter,
        TestAuthenticator $authenticator,
        RelyingParty $rp,
        string $nonce,
        int $flags = TestAuthenticator::FLAG_UP | TestAuthenticator::FLAG_UV,
        string $type = 'webauthn.get',
        ?string $origin = null,
    ): \Milpa\Auth\WebAuthn\WebAuthnAssertionResult {
        $adapter->createAuthenticationOptions($rp, new WebAuthnAuthenticationContext('actor-1'));

        $authData = $authenticator->assertionAuthData($rp->id, 1, $flags);
        $clientDataJSON = $authenticator->clientDataJSON($type, $nonce, $origin ?? self::ORIGIN);

        return $adapter->verifyAuthentication(
            new WebAuthnAuthenticationResponse(
                $authenticator->credentialIdBase64Url(),
                $clientDataJSON,
                $authData,
                $authenticator->sign($authData, $clientDataJSON),
                'actor-1',
            ),
            $rp,
        );
    }

    private function expectCeremonyRejected(string $reason): void
    {
        $this->expectException(WebAuthnCeremonyException::class);
        $this->expectExceptionMessage('rejected: ' . $reason);
    }
}
