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
 * The relying party a ceremony runs for — resolved per request/tenant, never env-static. `id` is the
 * WebAuthn RP ID (an eTLD+1 or host); `allowedOrigins` is the exact-string https allowlist checked
 * against the ceremony's clientDataJSON origin. Multi-tenant hosts resolve one per request.
 */
final readonly class RelyingParty
{
    /** @param list<string> $allowedOrigins exact https origins accepted for this RP */
    public function __construct(
        public string $id,
        public string $name,
        public array $allowedOrigins,
    ) {
    }
}
