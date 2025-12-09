<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

class UnableToGenerateKeyException extends \Exception
{
    public function __construct(?string $message = null, ?\Exception $previousException = null)
    {
        parent::__construct($message ?: 'Unable to generate key.', 0, $previousException);
    }

    public static function withType(string $type): self
    {
        return new self(sprintf('Unable to generate "%s".', $type));
    }
}
