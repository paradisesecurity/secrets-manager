<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Exception;

final class UnresolvedKeyProviderException extends \Exception
{
    public function __construct()
    {
        parent::__construct('No key adapter could be found that could provide the key type requested!');
    }
}
