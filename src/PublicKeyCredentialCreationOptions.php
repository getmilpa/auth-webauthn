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
 * The registration options a server hands the browser (WebAuthn `navigator.credentials.create`). `toArray()` is the JSON body.
 */
final readonly class PublicKeyCredentialCreationOptions
{
    /** @param array<string,mixed> $publicKey the `publicKey` member the browser consumes */
    public function __construct(public array $publicKey)
    {
    }

    /**
     * The JSON body handed to `navigator.credentials.create`.
     *
     * @return array{publicKey: array<string,mixed>}
     */
    public function toArray(): array
    {
        return ['publicKey' => $this->publicKey];
    }
}
