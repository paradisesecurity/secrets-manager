<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption\Request;

/**
 * Encryption request for file operations.
 * 
 * Extends base request with file-specific properties.
 * Files can be paths (strings) or stream resources.
 */
interface FileEncryptionRequestInterface extends EncryptionRequestInterface
{
    /**
     * Gets input file (to be encrypted/decrypted).
     * 
     * @return mixed File path string or stream resource
     */
    public function getInputFile(): mixed;

    /**
     * Gets output file (encrypted/decrypted result).
     * 
     * @return mixed File path string or stream resource
     */
    public function getOutputFile(): mixed;
}
