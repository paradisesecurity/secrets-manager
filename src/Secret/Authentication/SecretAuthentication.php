<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret\Authentication;

use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\Request\Builder\EncryptionRequestBuilder;
use ParadiseSecurity\Component\SecretsManager\Exception\SecretAuthenticationException;
use ParadiseSecurity\Component\SecretsManager\Exception\SecretNotFoundException;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Utility\Utility;
use ParagonIE\HiddenString\HiddenString;

use const SODIUM_CRYPTO_GENERICHASH_BYTES_MAX;

/**
 * Handles authentication (MAC) operations for secret data integrity.
 */
final class SecretAuthentication
{
    public function __construct(
        private EncryptionAdapterInterface $encryptionAdapter,
    ) {
    }

    /**
     * Generates a MAC and prepends it to the data for authentication.
     */
    public function authenticateData(string $value, KeyInterface $authKey): string
    {
        $request = EncryptionRequestBuilder::create()
            ->withKey($authKey)
            ->withEncoderChoice(true)
            ->buildForMessage(new HiddenString($value));

        try {
            $mac = $this->encryptionAdapter->authenticate($request);
            return $mac . $value;
        } catch (\Exception $exception) {
            throw new SecretAuthenticationException(
                "Failed to authenticate data: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Verifies the MAC and returns the data without the MAC prefix.
     */
    public function verifyData(string $authenticatedData, KeyInterface $authKey): string
    {
        $mac = Utility::subString($authenticatedData, 0, SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);
        $data = Utility::subString($authenticatedData, SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);

        $request = EncryptionRequestBuilder::create()
            ->withKey($authKey)
            ->withEncoderChoice(true)
            ->withMac($mac)
            ->buildForMessage(new HiddenString($data));

        if (!$this->encryptionAdapter->verify($request)) {
            throw new SecretNotFoundException('Secret data could not be verified.');
        }

        return $data;
    }

    /**
     * Strips the MAC prefix from authenticated data.
     */
    public function stripMac(string $authenticatedData): string
    {
        return Utility::subString($authenticatedData, SODIUM_CRYPTO_GENERICHASH_BYTES_MAX);
    }
}
