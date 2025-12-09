<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret\Key;

use ParadiseSecurity\Component\SecretsManager\Exception\UnableToLoadKeyException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;

/**
 * Reconstructs data encryption keys from serialized data.
 */
final class SecretKeyBuilder
{
    public function __construct(
        private KeyFactoryInterface $keyFactory,
    ) {
    }

    /**
     * Builds a KeyInterface from decrypted data key data.
     */
    public function buildFromData(array $dataKeyData): KeyInterface
    {
        $this->validateDataKeyData($dataKeyData);

        try {
            return $this->keyFactory->buildKeyFromRawKeyData(
                $dataKeyData['hex'],
                $dataKeyData['type'],
                $dataKeyData['adapter'],
                $dataKeyData['version']
            );
        } catch (\Exception $exception) {
            throw new UnableToLoadKeyException(
                'Failed to build data key from decrypted data.',
                $exception
            );
        }
    }

    private function validateDataKeyData(array $data): void
    {
        $requiredFields = ['hex', 'type', 'adapter', 'version'];
        
        foreach ($requiredFields as $field) {
            if (!isset($data[$field])) {
                throw new UnableToLoadKeyException(
                    "Missing required field '{$field}' in data key data"
                );
            }
        }
    }
}
