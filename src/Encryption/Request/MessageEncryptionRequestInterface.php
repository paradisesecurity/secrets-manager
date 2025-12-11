<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption\Request;

use ParagonIE\HiddenString\HiddenString;

/**
 * Encryption request for message/string operations.
 * 
 * Extends base request with message-specific properties.
 */
interface MessageEncryptionRequestInterface extends EncryptionRequestInterface
{
    /**
     * Gets the message to encrypt/decrypt.
     * 
     * @return HiddenString The message (sensitive data protected)
     */
    public function getMessage(): HiddenString;
}
