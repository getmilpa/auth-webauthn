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

/** Which WebAuthn ceremony a {@see ChallengeRecord} belongs to — registration (attestation) or authentication (assertion). */
enum CeremonyType: string
{
    case Registration = 'registration';
    case Authentication = 'authentication';
}
