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

namespace Milpa\Auth\WebAuthn\Exceptions;

/**
 * A WebAuthn ceremony failed a fail-closed check (bad/absent/expired challenge, origin, rpId, signature,
 * or flags). The message names the failed check — never a secret.
 */
final class WebAuthnCeremonyException extends \RuntimeException
{
    /** The ceremony was rejected for $reason (a policy/check name, never credential material). */
    public static function rejected(string $reason): self
    {
        return new self('[MILPA_WEBAUTHN_CEREMONY_REJECTED] WebAuthn ceremony rejected: ' . $reason);
    }
}
