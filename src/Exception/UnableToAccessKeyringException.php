<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

class UnableToAccessKeyringException extends \Exception
{
    public function __construct(?string $message = null, ?\Exception $previousException = null)
    {
        parent::__construct($message ?: 'Keyring could not be accessed.', 0, $previousException);
    }
}
