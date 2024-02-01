<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

class UnableToEncryptMessageException extends \Exception
{
    public function __construct(?string $message = null, \Exception $previousException = null)
    {
        parent::__construct($message ?: 'Unable to encrypt message.', 0, $previousException);
    }

    public static function withMissingKey(string $keyTypes): self
    {
        return new self(sprintf('Incorrect key(s) supplied for encryption type, expected (%s).', $keyTypes));
    }
}
