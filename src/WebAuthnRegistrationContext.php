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
 * The host-supplied inputs for a registration ceremony — who is registering and how strict user
 * verification must be. Not persisted itself; it shapes the {@see PublicKeyCredentialCreationOptions}.
 */
final readonly class WebAuthnRegistrationContext
{
    public function __construct(
        public string $userHandle,
        public string $userName,
        public string $userDisplayName,
        public string $userVerification = 'preferred',
    ) {
    }
}
