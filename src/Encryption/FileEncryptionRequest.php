<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption;

use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;

final class FileEncryptionRequest extends EncryptionRequest implements FileEncryptionRequestInterface
{
    public function __construct(
        private mixed $inputFile,
        private mixed $outputFile,
        KeyInterface|array $keys,
        array $config = [],
    ) {
        parent::__construct($keys, $config);
    }

    public function getInputFile(): mixed
    {
        return $this->inputFile;
    }

    public function getOutputFile(): mixed
    {
        return $this->outputFile;
    }
}
