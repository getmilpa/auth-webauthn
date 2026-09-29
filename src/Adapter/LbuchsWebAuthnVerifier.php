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

namespace Milpa\Auth\WebAuthn\Adapter;

use lbuchs\WebAuthn\Binary\ByteBuffer;
use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\WebAuthnException;
use Milpa\Auth\Actor;
use Milpa\Auth\WebAuthn\CeremonyType;
use Milpa\Auth\WebAuthn\ChallengeRecord;
use Milpa\Auth\WebAuthn\Contracts\ChallengeStore;
use Milpa\Auth\WebAuthn\Contracts\WebAuthnCredentialStore;
use Milpa\Auth\WebAuthn\Contracts\WebAuthnVerifier;
use Milpa\Auth\WebAuthn\Exceptions\WebAuthnCeremonyException;
use Milpa\Auth\WebAuthn\PublicKeyCredentialCreationOptions;
use Milpa\Auth\WebAuthn\PublicKeyCredentialRequestOptions;
use Milpa\Auth\WebAuthn\RelyingParty;
use Milpa\Auth\WebAuthn\UserVerificationRequirement;
use Milpa\Auth\WebAuthn\WebAuthnAssertionResult;
use Milpa\Auth\WebAuthn\WebAuthnAuthenticationContext;
use Milpa\Auth\WebAuthn\WebAuthnAuthenticationResponse;
use Milpa\Auth\WebAuthn\WebAuthnCredentialRecord;
use Milpa\Auth\WebAuthn\WebAuthnRegistrationContext;
use Milpa\Auth\WebAuthn\WebAuthnRegistrationResponse;

/**
 * The one place this package does cryptography — the {@see WebAuthnVerifier} backed by the `lbuchs/webauthn`
 * library. It owns the two-round-trip ceremony bookkeeping (issue a {@see ChallengeRecord}, consume it
 * single-use, check origin/actor fail-closed) and delegates EVERY signature/CBOR/COSE check to lbuchs. A
 * fresh `lbuchs\WebAuthn\WebAuthn` is built per ceremony from the resolved {@see RelyingParty} (lbuchs
 * takes a static rpId, so it cannot be shared across tenants). Attestation is fixed to `'none'`: this leaf
 * proves possession of a key bound to the RP, not the authenticator's provenance.
 *
 * User verification is REQUIRED by default, as in milpa/auth's own verifiers: a ceremony whose
 * authenticatorData lacks the UV flag proves someone touched the authenticator, not who. The options this
 * adapter emits advertise `userVerification: 'required'` so the browser asks for it; a house that admits
 * authenticators without a PIN or biometric passes {@see UserVerificationRequirement::Preferred} or
 * `::Discouraged` to the constructor, explicitly — it is never inferred from the request context.
 *
 * Which WebAuthn L2 check is made where (§7.1 registration, §7.2 assertion):
 *  - here: the challenge is one this adapter issued, unexpired, unused and for this ceremony; the origin is
 *    one of {@see RelyingParty::$allowedOrigins} (exact string); the credential is known, belongs to the
 *    actor the challenge was issued for, and matches the userHandle; a new credential id is not already
 *    registered; the signature counter (as a signal, see below).
 *  - in lbuchs: clientData `type`, challenge, origin (against the rpId), rpIdHash, UP, UV, the attestation
 *    format and the signature.
 *
 * Two deliberate design points, both load-bearing:
 *  - The shipped response value objects carry no opaque challenge-id, so the ONLY value the browser
 *    round-trips is the challenge itself. The {@see ChallengeRecord} id is therefore derived
 *    deterministically from the challenge nonce ({@see self::challengeId()}) — a one-way hash that
 *    `verify*` recomputes from the browser-echoed `clientDataJSON.challenge`. The `idFactory` supplies the
 *    per-ceremony nonce.
 *  - The signature counter is a clone-detection SIGNAL, never an authorization gate. lbuchs would THROW on a
 *    non-incrementing counter if handed `prevSignatureCnt`; that is the wrong contract here, so lbuchs runs
 *    with `prevSignatureCnt = null` (it still verifies the signature, origin, rpId and challenge) and this
 *    adapter computes {@see WebAuthnAssertionResult::$cloneWarning} itself. A zero counter is a synced
 *    passkey (no warning, no throw); a non-zero non-increment is the clone signal (warning, still succeeds).
 */
final class LbuchsWebAuthnVerifier implements WebAuthnVerifier
{
    /** Seconds a challenge stays usable between the two round-trips of a ceremony. */
    private const CHALLENGE_TTL_SECONDS = 120;

    /** Client-side ceremony timeout advertised in the options, in seconds. */
    private const CEREMONY_TIMEOUT_SECONDS = 60;

    /** @var callable(): \DateTimeImmutable */
    private $clock;

    /** @var callable(): string produces the per-ceremony challenge nonce; its hash is the store id */
    private $nonceFactory;

    /**
     * @param callable(): \DateTimeImmutable|null $clock            defaults to a real "now"
     * @param callable(): string|null             $idFactory        the per-ceremony challenge nonce source
     *                                                              (default: `bin2hex(random_bytes(16))`)
     * @param UserVerificationRequirement         $userVerification `Required` by default; relax it only on
     *                                                              purpose, for a house that admits
     *                                                              authenticators without a PIN or biometric
     */
    public function __construct(
        private readonly ChallengeStore $challenges,
        private readonly WebAuthnCredentialStore $credentials,
        ?callable $clock = null,
        ?callable $idFactory = null,
        private readonly UserVerificationRequirement $userVerification = UserVerificationRequirement::Required,
    ) {
        $this->clock = $clock ?? static fn (): \DateTimeImmutable => new \DateTimeImmutable();
        $this->nonceFactory = $idFactory ?? static fn (): string => bin2hex(random_bytes(16));
    }

    /**
     * Begin registration for a known actor: build the creation options via lbuchs, issue a single-use
     * Registration {@see ChallengeRecord} bound to the actor, and return the options for the browser.
     */
    public function createRegistrationOptions(Actor $actor, RelyingParty $rp, WebAuthnRegistrationContext $context): PublicKeyCredentialCreationOptions
    {
        $excludeIds = array_map(
            static fn (WebAuthnCredentialRecord $c): string => self::base64UrlDecode($c->credentialId),
            $this->credentials->listForActor($actor->id),
        );

        $args = $this->lbuchs($rp)->getCreateArgs(
            $context->userHandle,
            $context->userName,
            $context->userDisplayName,
            self::CEREMONY_TIMEOUT_SECONDS,
            'preferred',
            $this->advertisedUserVerification($context->userVerification),
            null,
            $excludeIds,
        );

        $nonce = ($this->nonceFactory)();
        $this->issueChallenge($nonce, CeremonyType::Registration, $actor->id);

        /** @var array<string, mixed> $publicKey */
        $publicKey = (array) $args->publicKey;
        $publicKey['challenge'] = new ByteBuffer($nonce);

        return new PublicKeyCredentialCreationOptions($publicKey);
    }

    /**
     * Finish registration: consume the challenge, enforce the origin allowlist, let lbuchs verify the
     * `'none'` attestation (and the UV flag unless relaxed), refuse a credential id that is already
     * registered, and return the {@see WebAuthnCredentialRecord} for the host to persist.
     */
    public function verifyRegistration(WebAuthnRegistrationResponse $response, RelyingParty $rp): WebAuthnCredentialRecord
    {
        $clientData = self::decodeClientData($response->clientDataJSON);
        $record = $this->consumeChallenge($clientData['challenge'], CeremonyType::Registration);
        $this->assertOriginAllowed($clientData['origin'], $rp);

        if ($record->actorId === null) {
            throw WebAuthnCeremonyException::rejected('challenge');
        }

        $webAuthn = $this->lbuchs($rp);
        try {
            $data = $webAuthn->processCreate(
                $response->clientDataJSON,
                $response->attestationObject,
                $record->value(),
                $this->userVerification->demandsVerification(),
                true,  // requireUserPresent
                false, // failIfRootMismatch — 'none' carries no chain to a root
            );
        } catch (WebAuthnException) {
            throw WebAuthnCeremonyException::rejected('attestation');
        }

        // §7.1 step 22: a credential id already on file is never registered a second time — whether it is
        // another actor's (a hijack) or this actor's own (a replayed attestation).
        $credentialId = self::base64UrlEncode((string) $data->credentialId);
        if ($this->credentials->findByCredentialId($credentialId) !== null) {
            throw WebAuthnCeremonyException::rejected('credential already registered');
        }

        return new WebAuthnCredentialRecord(
            $credentialId,
            (string) $data->credentialPublicKey,
            $webAuthn->getSignatureCounter() ?? 0,
            $record->actorId,
            self::formatAaguid($data->AAGUID ?? null),
            $response->transports,
            ($this->clock)(),
        );
    }

    /**
     * Begin authentication: build the request options via lbuchs (allowCredentials for a known actor,
     * empty for a discoverable/usernameless flow), issue a single-use Authentication challenge, and return
     * the options for the browser.
     */
    public function createAuthenticationOptions(RelyingParty $rp, WebAuthnAuthenticationContext $context): PublicKeyCredentialRequestOptions
    {
        $credentialIds = [];
        if ($context->actorId !== null) {
            $credentialIds = array_map(
                static fn (WebAuthnCredentialRecord $c): string => self::base64UrlDecode($c->credentialId),
                $this->credentials->listForActor($context->actorId),
            );
        }

        $args = $this->lbuchs($rp)->getGetArgs(
            $credentialIds,
            self::CEREMONY_TIMEOUT_SECONDS,
            true,
            true,
            true,
            true,
            true,
            $this->advertisedUserVerification($context->userVerification),
        );

        $nonce = ($this->nonceFactory)();
        $this->issueChallenge($nonce, CeremonyType::Authentication, $context->actorId);

        /** @var array<string, mixed> $publicKey */
        $publicKey = (array) $args->publicKey;
        $publicKey['challenge'] = new ByteBuffer($nonce);

        return new PublicKeyCredentialRequestOptions($publicKey);
    }

    /**
     * Finish authentication: consume the challenge, enforce the origin allowlist, resolve the credential,
     * require it to belong to the actor the challenge was issued for (§7.2 step 6), check the user-handle
     * binding, let lbuchs verify the assertion (signature, UP, and UV unless relaxed), and return the proof. The
     * signature counter is reported as a clone SIGNAL — never used to reject (see the class doc).
     */
    public function verifyAuthentication(WebAuthnAuthenticationResponse $response, RelyingParty $rp): WebAuthnAssertionResult
    {
        $clientData = self::decodeClientData($response->clientDataJSON);
        $record = $this->consumeChallenge($clientData['challenge'], CeremonyType::Authentication);
        $this->assertOriginAllowed($clientData['origin'], $rp);

        $stored = $this->credentials->findByCredentialId($response->credentialId);
        if ($stored === null) {
            throw WebAuthnCeremonyException::rejected('unknown credential');
        }

        // A challenge issued for a known actor listed only that actor's credentials; another actor's
        // credential answering it would let a step-up for one person be satisfied by someone else.
        if ($record->actorId !== null && $record->actorId !== $stored->actorId) {
            throw WebAuthnCeremonyException::rejected('credential not allowed');
        }

        if ($response->userHandle !== null && $response->userHandle !== $stored->actorId) {
            throw WebAuthnCeremonyException::rejected('user handle mismatch');
        }

        $webAuthn = $this->lbuchs($rp);
        try {
            $webAuthn->processGet(
                $response->clientDataJSON,
                $response->authenticatorData,
                $response->signature(),
                $stored->publicKeyCose,
                $record->value(),
                null,  // prevSignatureCnt = null: the counter is our SIGNAL, not a gate lbuchs throws on
                $this->userVerification->demandsVerification(),
                true,  // requireUserPresent
            );
        } catch (WebAuthnException) {
            throw WebAuthnCeremonyException::rejected('assertion');
        }

        // The counter is a clone SIGNAL. Judge it on the REPORTED value before any fallback: a null
        // counter is a synced/zero passkey (no signal), and 0 is likewise no signal. Only a non-zero
        // counter that failed to advance past the stored one is the clone tell. Deriving the warning
        // from $newCount after the fallback would false-positive a non-zero→null (synced) transition,
        // because the fallback makes it trivially `<= $stored->signCount`.
        $reported = $webAuthn->getSignatureCounter();
        $cloneWarning = $reported !== null && $reported !== 0 && $reported <= $stored->signCount;
        $newCount = $reported ?? $stored->signCount;

        return new WebAuthnAssertionResult(
            $response->credentialId,
            $stored->actorId,
            $response->userHandle,
            $newCount,
            $cloneWarning,
        );
    }

    /** A fresh lbuchs server bound to this ceremony's relying party (rpId is static, so never shared). */
    private function lbuchs(RelyingParty $rp): WebAuthn
    {
        return new WebAuthn($rp->name, $rp->id, ['none'], true);
    }

    /** Issue a single-use challenge whose store id is the one-way hash of the nonce. */
    private function issueChallenge(string $nonce, CeremonyType $type, ?string $actorId): void
    {
        $this->challenges->issue(new ChallengeRecord(
            self::challengeId($nonce),
            $nonce,
            $type,
            ($this->clock)(),
            self::CHALLENGE_TTL_SECONDS,
            $actorId,
        ));
    }

    /**
     * Consume the challenge the browser echoed (by its derived id) and require it to be the expected
     * ceremony. Fail-closed: absent, expired, already-consumed, or wrong-ceremony ⇒ rejected.
     */
    private function consumeChallenge(string $echoedChallenge, CeremonyType $expected): ChallengeRecord
    {
        $nonce = self::base64UrlDecode($echoedChallenge);
        $record = $this->challenges->consume(self::challengeId($nonce));
        if ($record === null || $record->ceremonyType !== $expected) {
            throw WebAuthnCeremonyException::rejected('challenge');
        }

        return $record;
    }

    /**
     * The `userVerification` the browser is asked for: `'required'` whenever this verifier demands UV (a
     * weaker request would only make the browser skip a check the server then refuses the ceremony for);
     * otherwise the host's requested value, unchanged.
     */
    private function advertisedUserVerification(string $requested): string
    {
        return $this->userVerification->demandsVerification()
            ? UserVerificationRequirement::Required->value
            : $requested;
    }

    /**
     * The exact-string origin check against the RP's allowlist. lbuchs only checks that the origin's host
     * falls under the rpId, which would admit any subdomain; this is what holds a ceremony to the pages
     * the RP actually serves it from.
     */
    private function assertOriginAllowed(string $origin, RelyingParty $rp): void
    {
        if (!$rp->allowsOrigin($origin)) {
            throw WebAuthnCeremonyException::rejected('origin');
        }
    }

    /** The store id for a challenge: a one-way hash of the nonce (so it never leaks the nonce itself). */
    private static function challengeId(string $nonce): string
    {
        return self::base64UrlEncode(hash('sha256', $nonce, true));
    }

    /**
     * Decode and minimally validate the clientDataJSON the browser produced.
     *
     * @return array{challenge: string, origin: string}
     */
    private static function decodeClientData(string $clientDataJSON): array
    {
        $decoded = json_decode($clientDataJSON, true);
        if (!is_array($decoded)
            || !isset($decoded['challenge']) || !is_string($decoded['challenge'])
            || !isset($decoded['origin']) || !is_string($decoded['origin'])) {
            throw WebAuthnCeremonyException::rejected('client data');
        }

        return ['challenge' => $decoded['challenge'], 'origin' => $decoded['origin']];
    }

    /** Format lbuchs's raw 16-byte AAGUID as the canonical hyphenated uuid, or null when absent. */
    private static function formatAaguid(mixed $aaguid): ?string
    {
        if (!is_string($aaguid) || strlen($aaguid) !== 16) {
            return null;
        }
        $hex = bin2hex($aaguid);

        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12),
        );
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        return $decoded === false ? '' : $decoded;
    }
}
