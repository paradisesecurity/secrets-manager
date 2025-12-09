<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

class MissingEncryptionKeyException extends \Exception
{
    public function __construct(?string $message = null, ?\Exception $previousException = null)
    {
        parent::__construct($message ?: 'An encryption key is required but wasn\'t provided.', 0, $previousException);
    }

    public static function withType(string $type): self
    {
        return new self(sprintf('The following encryption key was expected, "%s".', $type));
    }
}
