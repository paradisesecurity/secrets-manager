<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

class InvalidSignatureOrChecksumException extends \Exception
{
    public function __construct(?string $message = null, ?\Exception $previousException = null)
    {
        parent::__construct($message ?: 'Invalid signature or checksum detected.', 0, $previousException);
    }
}
