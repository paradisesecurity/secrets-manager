<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

class ValueNotSupportedException extends \Exception
{
    public function __construct(?string $message = null, ?\Exception $previousException = null)
    {
        parent::__construct($message ?: 'Unsupported value.', 0, $previousException);
    }

    public static function withKey(string $key): self
    {
        return new self(sprintf('This value is not supported: "%s".', $key));
    }
}
