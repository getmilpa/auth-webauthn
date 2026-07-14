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

namespace Milpa\Auth\WebAuthn\Contracts;

use Milpa\Auth\Actor;
use Milpa\Auth\WebAuthn\PublicKeyCredentialCreationOptions;
use Milpa\Auth\WebAuthn\PublicKeyCredentialRequestOptions;
use Milpa\Auth\WebAuthn\RelyingParty;
use Milpa\Auth\WebAuthn\WebAuthnAssertionResult;
use Milpa\Auth\WebAuthn\WebAuthnAuthenticationContext;
use Milpa\Auth\WebAuthn\WebAuthnAuthenticationResponse;
use Milpa\Auth\WebAuthn\WebAuthnCredentialRecord;
use Milpa\Auth\WebAuthn\WebAuthnRegistrationContext;
use Milpa\Auth\WebAuthn\WebAuthnRegistrationResponse;

/**
 * The two-ceremony WebAuthn producer — NOT a {@see \Milpa\Auth\Contracts\CredentialVerifier} (a passkey
 * is a stateful two-round-trip ceremony, not a single-shot per-request credential). `create*` issue a
 * challenge into the {@see ChallengeStore} and return the options the browser needs; `verify*` consume
 * the challenge and check the ceremony fail-closed. `verifyAuthentication` returns the cryptographic
 * proof ({@see WebAuthnAssertionResult}); it does NOT mint a session — the host does that.
 */
interface WebAuthnVerifier
{
    /** Begin registration for a known actor: issue a challenge, return the creation options. */
    public function createRegistrationOptions(Actor $actor, RelyingParty $rp, WebAuthnRegistrationContext $context): PublicKeyCredentialCreationOptions;

    /** Finish registration: verify the attestation ('none'), return the credential record for the host to save. */
    public function verifyRegistration(WebAuthnRegistrationResponse $response, RelyingParty $rp): WebAuthnCredentialRecord;

    /** Begin authentication: issue a challenge, return the request options (allowCredentials for a known actor, empty for discoverable). */
    public function createAuthenticationOptions(RelyingParty $rp, WebAuthnAuthenticationContext $context): PublicKeyCredentialRequestOptions;

    /** Finish authentication: verify the assertion signature/origin/rpId/flags fail-closed; return the proof (never a session). */
    public function verifyAuthentication(WebAuthnAuthenticationResponse $response, RelyingParty $rp): WebAuthnAssertionResult;
}
