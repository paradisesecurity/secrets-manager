<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

class UnableToAccessRestrictedCommandsException extends \Exception
{
    public function __construct(?string $message = null, ?\Exception $previousException = null)
    {
        parent::__construct($message ?: 'Unable to access a restricted command with current access rights.', 0, $previousException);
    }
}
