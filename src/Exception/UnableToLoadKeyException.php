<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

class UnableToLoadKeyException extends \Exception
{
    public function __construct(?string $message = null, \Exception $previousException = null)
    {
        parent::__construct($message ?: 'Unable to load key.', 0, $previousException);
    }

    public static function withType(string $type): self
    {
        return new self(sprintf('Unable to load "%s".', $type));
    }
}
