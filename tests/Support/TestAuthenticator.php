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

namespace Milpa\Auth\WebAuthn\Tests\Support;

/**
 * A genuine software authenticator for the integration tier: it holds a REAL ES256 (P-256) key pair and
 * produces WebAuthn attestation objects (fmt `'none'`) and assertion signatures that the real
 * `lbuchs/webauthn` library cryptographically verifies. Nothing here is hand-fabricated — the COSE public
 * key is built from the real key's coordinates, and every assertion signature is a real openssl ECDSA /
 * SHA-256 signature over the exact WebAuthn signed-data construction (`authenticatorData ||
 * SHA-256(clientDataJSON)`). This is the "genuine ceremony with a verifiable crypto chain" the gate allows.
 */
final class TestAuthenticator
{
    private \OpenSSLAsymmetricKey $privateKey;

    /** 32-byte big-endian P-256 public X coordinate. */
    private string $x;

    /** 32-byte big-endian P-256 public Y coordinate. */
    private string $y;

    /** Raw (un-encoded) credential id bytes. */
    public readonly string $credentialIdRaw;

    /** Raw 16-byte AAGUID. */
    private readonly string $aaguidRaw;

    public function __construct(?string $credentialIdRaw = null, ?string $aaguidRaw = null)
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        if (!$key instanceof \OpenSSLAsymmetricKey) {
            throw new \RuntimeException('Unable to generate an ES256 key pair for the test authenticator.');
        }
        $this->privateKey = $key;

        $details = openssl_pkey_get_details($key);
        if (!is_array($details) || !isset($details['ec']) || !is_array($details['ec'])
            || !isset($details['ec']['x'], $details['ec']['y'])
            || !is_string($details['ec']['x']) || !is_string($details['ec']['y'])) {
            throw new \RuntimeException('Unable to read EC public key coordinates.');
        }
        $this->x = str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT);
        $this->y = str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT);

        $this->credentialIdRaw = $credentialIdRaw ?? random_bytes(20);
        $this->aaguidRaw = $aaguidRaw ?? str_repeat("\x00", 16);
    }

    /** The credential id as the base64url form the store and responses use. */
    public function credentialIdBase64Url(): string
    {
        return self::base64Url($this->credentialIdRaw);
    }

    /** The canonical hyphenated AAGUID string this authenticator reports. */
    public function aaguidUuid(): string
    {
        $hex = bin2hex($this->aaguidRaw);

        return sprintf('%s-%s-%s-%s-%s', substr($hex, 0, 8), substr($hex, 8, 4), substr($hex, 12, 4), substr($hex, 16, 4), substr($hex, 20, 12));
    }

    /**
     * A complete CBOR attestation object (fmt `'none'`) whose authData embeds the real COSE public key.
     * Feed this straight to `verifyRegistration` / lbuchs `processCreate`.
     */
    public function attestationObject(string $rpId, int $signCount = 0): string
    {
        $authData = $this->registrationAuthData($rpId, $signCount);

        return self::cborMap([
            [self::cborText('fmt'), self::cborText('none')],
            [self::cborText('attStmt'), self::cborMap([])],
            [self::cborText('authData'), self::cborBytes($authData)],
        ]);
    }

    /** The authenticatorData for an assertion (rpIdHash + UP flag + 32-bit counter, no attested data). */
    public function assertionAuthData(string $rpId, int $signCount): string
    {
        return hash('sha256', $rpId, true)
            . chr(0x01)          // UP
            . pack('N', $signCount);
    }

    /** Build the exact clientDataJSON string the browser would produce (reused for both response and signature). */
    public function clientDataJSON(string $type, string $challengeNonce, string $origin): string
    {
        return json_encode([
            'type' => $type,
            'challenge' => self::base64Url($challengeNonce),
            'origin' => $origin,
            'crossOrigin' => false,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    /** A REAL ECDSA/SHA-256 (DER) signature over `authenticatorData || SHA-256(clientDataJSON)`. */
    public function sign(string $authenticatorData, string $clientDataJSON): string
    {
        $signedData = $authenticatorData . hash('sha256', $clientDataJSON, true);
        $signature = '';
        if (openssl_sign($signedData, $signature, $this->privateKey, OPENSSL_ALGO_SHA256) !== true) {
            throw new \RuntimeException('Unable to sign the assertion.');
        }

        return $signature;
    }

    /** The registration authenticatorData: rpIdHash + (UP|AT) flags + counter + attested credential data. */
    private function registrationAuthData(string $rpId, int $signCount): string
    {
        $attestedCredentialData = $this->aaguidRaw
            . pack('n', strlen($this->credentialIdRaw))
            . $this->credentialIdRaw
            . $this->coseKey();

        return hash('sha256', $rpId, true)
            . chr(0x01 | 0x40)   // UP | AT (attested credential data included)
            . pack('N', $signCount)
            . $attestedCredentialData;
    }

    /** The COSE_Key (CBOR) for this authenticator's EC2/ES256/P-256 public key. */
    private function coseKey(): string
    {
        return self::cborMap([
            [self::cborUint(1), self::cborUint(2)],   // 1 (kty)  = 2   (EC2)
            [self::cborUint(3), self::cborNint(-7)],  // 3 (alg)  = -7  (ES256)
            [self::cborNint(-1), self::cborUint(1)],  // -1 (crv) = 1   (P-256)
            [self::cborNint(-2), self::cborBytes($this->x)], // -2 (x)
            [self::cborNint(-3), self::cborBytes($this->y)], // -3 (y)
        ]);
    }

    private static function base64Url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    // --- minimal, correct CBOR encoders (definite-length, canonical enough for lbuchs' decoder) ---

    private static function cborUint(int $value): string
    {
        return self::cborHead(0, $value);
    }

    private static function cborNint(int $value): string
    {
        return self::cborHead(1, -1 - $value);
    }

    private static function cborBytes(string $bytes): string
    {
        return self::cborHead(2, strlen($bytes)) . $bytes;
    }

    private static function cborText(string $text): string
    {
        return self::cborHead(3, strlen($text)) . $text;
    }

    /**
     * @param list<array{0: string, 1: string}> $pairs already-encoded [key, value] pairs
     */
    private static function cborMap(array $pairs): string
    {
        $out = self::cborHead(5, count($pairs));
        foreach ($pairs as [$key, $value]) {
            $out .= $key . $value;
        }

        return $out;
    }

    /** Encode a CBOR major-type head with its argument (definite length). */
    private static function cborHead(int $majorType, int $value): string
    {
        $prefix = $majorType << 5;
        if ($value < 24) {
            return chr($prefix | $value);
        }
        if ($value < 256) {
            return chr($prefix | 24) . chr($value);
        }
        if ($value < 65536) {
            return chr($prefix | 25) . pack('n', $value);
        }

        return chr($prefix | 26) . pack('N', $value);
    }
}
