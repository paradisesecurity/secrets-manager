<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

class FilesystemErrorException extends \Exception
{
    public function __construct(?string $message = null, ?\Exception $previousException = null)
    {
        parent::__construct($message ?: 'Filesystem encountered an error.', 0, $previousException);
    }
}
