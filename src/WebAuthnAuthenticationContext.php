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
 * The host-supplied inputs for an authentication ceremony — an optional known actor (username-less
 * flows leave it null, resolved instead from the assertion's credential) and the user verification
 * requirement.
 */
final readonly class WebAuthnAuthenticationContext
{
    public function __construct(
        public ?string $actorId = null,
        public string $userVerification = 'preferred',
    ) {
    }
}
