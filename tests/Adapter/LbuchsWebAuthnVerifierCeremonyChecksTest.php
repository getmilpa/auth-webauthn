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
use Milpa\Auth\WebAuthn\UserVerificationRequirement;
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

    public function testUserVerifiedCeremoniesPassByDefault(): void
    {
        [$adapter, $authenticator, $rp] = $this->registered(['reg-uv', 'auth-uv']);

        $result = $this->assertWith($adapter, $authenticator, $rp, 'auth-uv');

        self::assertSame('actor-1', $result->actorId);
    }

    public function testAnExplicitlyRelaxedVerifierAcceptsPresenceAlone(): void
    {
        foreach ([UserVerificationRequirement::Preferred, UserVerificationRequirement::Discouraged] as $relaxed) {
            $credentials = new InMemoryWebAuthnCredentialStore();
            $adapter = $this->adapter(['reg-relaxed', 'auth-relaxed'], $credentials, $relaxed);
            $authenticator = new TestAuthenticator();
            $rp = $this->rp();

            $credentials->save($this->registerWith($adapter, $authenticator, $rp, 'reg-relaxed', flags: TestAuthenticator::FLAG_UP));
            $result = $this->assertWith($adapter, $authenticator, $rp, 'auth-relaxed', flags: TestAuthenticator::FLAG_UP);

            self::assertSame('actor-1', $result->actorId, $relaxed->value);
        }
    }

    public function testOptionsAskTheBrowserForUserVerificationByDefault(): void
    {
        $adapter = $this->adapter(['reg-options', 'auth-options']);

        // The contexts default to 'preferred'; a verifier that demands UV must not advertise less.
        $creation = $adapter->createRegistrationOptions(
            new Actor('actor-1', ActorType::User),
            $this->rp(),
            new WebAuthnRegistrationContext('actor-1', 'user@acme.example', 'Ada'),
        )->toArray()['publicKey'];
        $request = $adapter->createAuthenticationOptions($this->rp(), new WebAuthnAuthenticationContext('actor-1'))->toArray()['publicKey'];

        self::assertIsArray($creation);
        self::assertIsArray($request);
        $selection = $creation['authenticatorSelection'] ?? null;
        self::assertInstanceOf(\stdClass::class, $selection);
        self::assertSame('required', $selection->userVerification ?? null);
        self::assertSame('required', $request['userVerification'] ?? null);
    }

    public function testARelaxedVerifierAdvertisesWhatTheHostAskedFor(): void
    {
        $adapter = $this->adapter(['reg-options', 'auth-options'], null, UserVerificationRequirement::Preferred);

        $creation = $adapter->createRegistrationOptions(
            new Actor('actor-1', ActorType::User),
            $this->rp(),
            new WebAuthnRegistrationContext('actor-1', 'user@acme.example', 'Ada', 'discouraged'),
        )->toArray()['publicKey'];
        $request = $adapter->createAuthenticationOptions($this->rp(), new WebAuthnAuthenticationContext('actor-1', 'preferred'))->toArray()['publicKey'];

        self::assertIsArray($creation);
        self::assertIsArray($request);
        $selection = $creation['authenticatorSelection'] ?? null;
        self::assertInstanceOf(\stdClass::class, $selection);
        self::assertSame('discouraged', $selection->userVerification ?? null);
        self::assertSame('preferred', $request['userVerification'] ?? null);
    }

    // ---------------------------------------------------------------------
    // User presence (§7.1 step 14, §7.2 step 16) — made by lbuchs
    // ---------------------------------------------------------------------

    public function testAssertionWithoutUserPresenceIsRejected(): void
    {
        [$adapter, $authenticator, $rp] = $this->registered(['reg-no-up', 'auth-no-up']);

        $this->expectCeremonyRejected('assertion');
        $this->assertWith($adapter, $authenticator, $rp, 'auth-no-up', flags: TestAuthenticator::FLAG_UV);
    }

    public function testRegistrationWithoutUserPresenceIsRejected(): void
    {
        $this->expectCeremonyRejected('attestation');
        $this->registerWith($this->adapter(['reg-no-up']), new TestAuthenticator(), $this->rp(), 'reg-no-up', flags: TestAuthenticator::FLAG_UV);
    }

    // ---------------------------------------------------------------------
    // clientData type (§7.1 step 7, §7.2 step 11) — made by lbuchs
    // ---------------------------------------------------------------------

    public function testAssertionWithACreateTypeIsRejected(): void
    {
        [$adapter, $authenticator, $rp] = $this->registered(['reg-type', 'auth-type']);

        // Signed correctly over a clientDataJSON that says it is a registration.
        $this->expectCeremonyRejected('assertion');
        $this->assertWith($adapter, $authenticator, $rp, 'auth-type', type: 'webauthn.create');
    }

    public function testRegistrationWithAGetTypeIsRejected(): void
    {
        $this->expectCeremonyRejected('attestation');
        $this->registerWith($this->adapter(['reg-type']), new TestAuthenticator(), $this->rp(), 'reg-type', type: 'webauthn.get');
    }

    // ---------------------------------------------------------------------
    // Origin (§7.1 step 9, §7.2 step 13) — the RP's allowlist, not just the rpId
    // ---------------------------------------------------------------------

    public function testAssertionFromASubdomainOffTheAllowlistIsRejected(): void
    {
        [$adapter, $authenticator, $rp] = $this->registered(['reg-sub', 'auth-sub']);

        // lbuchs alone would accept this: its host ends with the rpId. The RP never listed it.
        $this->expectCeremonyRejected('origin');
        $this->assertWith($adapter, $authenticator, $rp, 'auth-sub', origin: 'https://evil.acme.example');
    }

    public function testRegistrationFromASubdomainOffTheAllowlistIsRejected(): void
    {
        $this->expectCeremonyRejected('origin');
        $this->registerWith($this->adapter(['reg-sub']), new TestAuthenticator(), $this->rp(), 'reg-sub', origin: 'https://evil.acme.example');
    }

    public function testEveryListedOriginIsAccepted(): void
    {
        $rp = new RelyingParty('acme.example', 'ACME Corp', [self::ORIGIN, 'https://login.acme.example']);
        $credentials = new InMemoryWebAuthnCredentialStore();
        $adapter = $this->adapter(['reg-listed', 'auth-listed'], $credentials);
        $authenticator = new TestAuthenticator();

        $credentials->save($this->registerWith($adapter, $authenticator, $rp, 'reg-listed', origin: 'https://login.acme.example'));
        $result = $this->assertWith($adapter, $authenticator, $rp, 'auth-listed', origin: 'https://login.acme.example');

        self::assertSame('actor-1', $result->actorId);
    }

    // ---------------------------------------------------------------------
    // rpIdHash (§7.1 step 13) — made by lbuchs; the assertion side is in the integration test
    // ---------------------------------------------------------------------

    public function testRegistrationForAnotherRpIdIsRejected(): void
    {
        $this->expectCeremonyRejected('attestation');
        $this->registerWith($this->adapter(['reg-rpid']), new TestAuthenticator(), $this->rp(), 'reg-rpid', authenticatorRpId: 'evil-rp.example');
    }

    // ---------------------------------------------------------------------
    // Credential ownership (§7.1 step 22, §7.2 step 6)
    // ---------------------------------------------------------------------

    public function testAnotherActorsCredentialCannotAnswerAChallengeIssuedForThisActor(): void
    {
        [$adapter, $authenticator, $rp] = $this->registered(['reg-owner', 'auth-owner']);

        // A genuine, UV'd assertion from actor-1's credential — but the challenge was issued for actor-2,
        // and the browser sent no userHandle to catch it.
        $adapter->createAuthenticationOptions($rp, new WebAuthnAuthenticationContext('actor-2'));
        $authData = $authenticator->assertionAuthData($rp->id, 1);
        $clientDataJSON = $authenticator->clientDataJSON('webauthn.get', 'auth-owner', self::ORIGIN);

        $this->expectCeremonyRejected('credential not allowed');
        $adapter->verifyAuthentication(
            new WebAuthnAuthenticationResponse($authenticator->credentialIdBase64Url(), $clientDataJSON, $authData, $authenticator->sign($authData, $clientDataJSON), null),
            $rp,
        );
    }

    public function testADiscoverableChallengeAcceptsAnyKnownCredential(): void
    {
        [$adapter, $authenticator, $rp] = $this->registered(['reg-disc', 'auth-disc']);

        $adapter->createAuthenticationOptions($rp, new WebAuthnAuthenticationContext(null));
        $authData = $authenticator->assertionAuthData($rp->id, 1);
        $clientDataJSON = $authenticator->clientDataJSON('webauthn.get', 'auth-disc', self::ORIGIN);

        $result = $adapter->verifyAuthentication(
            new WebAuthnAuthenticationResponse($authenticator->credentialIdBase64Url(), $clientDataJSON, $authData, $authenticator->sign($authData, $clientDataJSON), 'actor-1'),
            $rp,
        );

        self::assertSame('actor-1', $result->actorId);
    }

    public function testACredentialIdAlreadyRegisteredIsNotRegisteredAgain(): void
    {
        $credentials = new InMemoryWebAuthnCredentialStore();
        $adapter = $this->adapter(['reg-first', 'reg-again'], $credentials);
        $authenticator = new TestAuthenticator();

        $credentials->save($this->registerWith($adapter, $authenticator, $this->rp(), 'reg-first'));

        $this->expectCeremonyRejected('credential already registered');
        $this->registerWith($adapter, $authenticator, $this->rp(), 'reg-again');
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
    private function adapter(
        array $nonces,
        ?InMemoryWebAuthnCredentialStore $credentials = null,
        UserVerificationRequirement $userVerification = UserVerificationRequirement::Required,
    ): LbuchsWebAuthnVerifier {
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
            $userVerification,
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
