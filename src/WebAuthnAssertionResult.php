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
 * The verified product of an assertion: which credential/actor was cryptographically proven, plus the
 * sign-counter signal. The host turns this into a session; it is NOT itself a session or an AuthContext.
 */
final readonly class WebAuthnAssertionResult
{
    public function __construct(
        public string $credentialId,
        public string $actorId,
        public ?string $userHandle,
        public int $newSignCount,
        public bool $cloneWarning,
    ) {
    }
}
