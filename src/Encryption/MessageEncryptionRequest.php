<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption;

use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;

final class MessageEncryptionRequest extends EncryptionRequest implements MessageEncryptionRequestInterface
{
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
