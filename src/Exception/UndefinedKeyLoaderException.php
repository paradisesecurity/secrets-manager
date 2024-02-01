<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

class UndefinedKeyLoaderException extends \Exception
{
    public function __construct(?string $message = null, \Exception $previousException = null)
    {
        parent::__construct($message ?: 'Undefined key loader.', 0, $previousException);
    }
}
