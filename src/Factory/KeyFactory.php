<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Factory;

use ParadiseSecurity\Component\SecretsManager\Exception\UnresolvedKeyProviderException;
use ParadiseSecurity\Component\SecretsManager\Exception\UnableToGenerateKeyException;
use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfigInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\ServiceRegistry\Registry\ServiceRegistryInterface;
use ParagonIE\HiddenString\HiddenString;

final class KeyFactory implements KeyFactoryInterface
{
    public function __construct(
        private ServiceRegistryInterface $registry
    ) {
    }

    public function getAdapter(string $adapter): KeyFactoryAdapterInterface
    {
        if ($this->registry->has($adapter)) {
            return $this->registry->get($adapter);
        }

        throw new UnresolvedKeyProviderException();
    }

    public function generateKey(KeyConfigInterface $config, string $adapter): ?KeyInterface
    {
        try {
            $keyFactoryAdapter = $this->getAdapter($adapter);
            return $keyFactoryAdapter->generateKey($config);
        } catch (UnableToGenerateKeyException $exception) {
            return null;
        }
    }

    public function buildKeyFromRawKeyData(
        string $hex,
        string $type,
        string $adapter,
        string $version,
    ): KeyInterface {
        return new Key(new HiddenString($hex), $type, $adapter, $version);
    }

    public function getRawKeyMaterial(KeyInterface $key): HiddenString
    {
        $adapter = $key->getAdapter();
        $raw = new HiddenString('');
        $keyFactoryAdapter = $this->getAdapter($adapter);
        if (!$keyFactoryAdapter->supports(KeyFactoryInterface::RAW_KEY)) {
            return $raw;
        }
        try {
            return $keyFactoryAdapter->getAdapterRequiredKey($key, KeyFactoryInterface::RAW_KEY);
        } catch (UnableToGenerateKeyException $exception) {
            return $raw;
        }
    }
}
