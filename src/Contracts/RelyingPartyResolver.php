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

use Milpa\Auth\WebAuthn\RelyingParty;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Resolves the {@see RelyingParty} a ceremony runs for, per request — a multi-tenant host looks at the
 * request (host header, tenant path, …) instead of reading a single env-static RP. The leaf declares
 * WHAT is needed; the host decides HOW a request maps to a relying party.
 */
interface RelyingPartyResolver
{
    /** The relying party this request's ceremony must run under. */
    public function resolve(ServerRequestInterface $request): RelyingParty;
}
