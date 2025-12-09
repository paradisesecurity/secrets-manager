<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

class UnableToGenerateSignatureOrChecksumException extends \Exception
{
    public function __construct(?string $message = null, ?\Exception $previousException = null)
    {
        parent::__construct($message ?: 'Unable to generate signature or checksum.', 0, $previousException);
    }
}
