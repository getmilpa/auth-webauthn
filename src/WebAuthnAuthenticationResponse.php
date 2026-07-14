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
 * What the browser returns after `navigator.credentials.get()` — raw byte-exact carriers, unverified.
 * The assertion `signature` is the secret the ceremony proves knowledge of, so it follows the
 * secret-bearing contract: private, redacted in dumps, non-serializable, non-clonable, one `signature()`
 * exit. `clientDataJSON`/`authenticatorData`/`credentialId` are not secret and stay public byte-exact.
 */
final class WebAuthnAuthenticationResponse
{
    public function __construct(
        public readonly string $credentialId,
        public readonly string $clientDataJSON,
        public readonly string $authenticatorData,
        #[\SensitiveParameter]
        private readonly string $signature,
        public readonly ?string $userHandle,
    ) {
    }

    /** The raw assertion signature bytes — the one deliberate read, for the verifier. */
    public function signature(): string
    {
        return $this->signature;
    }

    /** @return array{credentialId: string, userHandle: ?string, signature: string} redacted */
    public function __debugInfo(): array
    {
        return ['credentialId' => $this->credentialId, 'userHandle' => $this->userHandle, 'signature' => '[redacted]'];
    }

    public function __serialize(): array
    {
        throw new \LogicException('WebAuthnAuthenticationResponse must not be serialized — it carries signature material.');
    }

    public function __clone(): void
    {
        throw new \LogicException('WebAuthnAuthenticationResponse must not be cloned.');
    }
}
