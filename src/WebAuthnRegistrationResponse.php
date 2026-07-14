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

namespace Milpa\Auth\WebAuthn;

/**
 * What the browser returns after `navigator.credentials.create()` — raw byte-exact carriers, unverified.
 * The {@see \Milpa\Auth\WebAuthn\Contracts\WebAuthnVerifier} consumes this to produce a
 * {@see WebAuthnCredentialRecord}. None of these fields are secret.
 */
final readonly class WebAuthnRegistrationResponse
{
    /** @param list<string> $transports the authenticator transports the browser reported */
    public function __construct(
        public string $credentialId,
        public string $clientDataJSON,
        public string $attestationObject,
        public array $transports,
    ) {
    }
}
