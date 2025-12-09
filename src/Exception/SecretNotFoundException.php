<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

class SecretNotFoundException extends \Exception
{
    public function __construct(?string $message = null, ?\Exception $previousException = null)
    {
        parent::__construct($message ?: 'Secret not found.', 0, $previousException);
    }

    public static function withKey(string $key): self
    {
        return new self(sprintf('No secret was found for: "%s".', $key));
    }
}
