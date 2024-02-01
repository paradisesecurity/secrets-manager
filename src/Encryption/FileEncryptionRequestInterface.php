<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption;

interface FileEncryptionRequestInterface
{
    public function getInputFile(): mixed;

    public function getOutputFile(): mixed;
}
