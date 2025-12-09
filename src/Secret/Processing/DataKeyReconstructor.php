<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret\Processing;

use ParadiseSecurity\Component\SecretsManager\Exception\SecretProcessingException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;

/**
 * Reconstructs KeyInterface from decrypted key data.
 * Separates KeyFactory dependency from SecretDataProcessor.
 */
final class DataKeyReconstructor
{
    public function __construct(
        private KeyFactoryInterface $keyFactory,
    ) {
    }

    public function reconstruct(array $keyData): KeyInterface
    {
        $this->validateKeyData($keyData);

        try {
            return $this->keyFactory->buildKeyFromRawKeyData(
                $keyData['hex'],
                $keyData['type'],
                $keyData['adapter'],
                $keyData['version']
            );
        } catch (\Exception $e) {
            throw new SecretProcessingException(
                "Failed to reconstruct data key: {$e->getMessage()}",
                previous: $e
            );
        }
    }

    private function validateKeyData(array $keyData): void
    {
        $requiredFields = ['hex', 'type', 'adapter', 'version'];
        
        foreach ($requiredFields as $field) {
            if (!isset($keyData[$field])) {
                throw new SecretProcessingException(
                    "Missing required field '{$field}' in key data"
                );
            }
        }
    }
}
