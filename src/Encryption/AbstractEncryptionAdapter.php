<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption;

use ParadiseSecurity\Component\SecretsManager\Adapter\AbstractAdapter;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToEncryptMessageException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnresolvedKeyProviderException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Provider\AdapterBasedKeyProviderInterface;

use function implode;

abstract class AbstractEncryptionAdapter extends AbstractAdapter
{
    public function __construct(
        private AdapterBasedKeyProviderInterface $adapterBasedKeyProvider
    ) {
        parent::__construct();
    }

    protected function getAdapterAppropriateKey(
        string $keyType
    ): KeyFactoryAdapterInterface {
        if (!$this->adapterBasedKeyProvider->supports($keyType)) {
            throw new UnresolvedKeyProviderException();
        }

        return $this->adapterBasedKeyProvider->getSupportedAdapter($keyType);
    }

    protected function unableToEncryptMessageWithMissingKey(array $keys): void
    {
        $keyTypes = [];
        foreach ($keys as $key) {
            $keyTypes[] = $this->transformSnakeCaseIntoWord($key);
        }
        $keyTypes = implode(", ", $keyTypes);
        throw UnableToEncryptMessageException::withMissingKey($keyTypes);
    }
}
