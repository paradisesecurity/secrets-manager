<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption\Request;

use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;

/**
 * Message encryption request implementation.
 * 
 * Handles encryption/decryption of strings/messages.
 * Uses HiddenString to protect sensitive data in memory.
 * 
 * Example:
 * ```
 * $request = new MessageEncryptionRequest(
 *     new HiddenString('secret message'),
 *     $encryptionKey,
 *     ['encoding' => 'base64']
 * );
 * ```
 */
final class MessageEncryptionRequest extends EncryptionRequest implements MessageEncryptionRequestInterface
{
    /**
     * @param HiddenString $message Message to encrypt/decrypt
     * @param KeyInterface|array<KeyInterface> $keys Encryption keys
     * @param array<string, mixed> $config Additional configuration
     */
    public function __construct(
        private HiddenString $message,
        KeyInterface|array $keys,
        array $config = [],
    ) {
        parent::__construct($keys, $config);
    }

    public function getMessage(): HiddenString
    {
        return $this->message;
    }
}
