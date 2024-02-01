<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Secret;

use ParadiseSecurity\Component\SecretsManager\Utility\Utility;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\OptionsResolver\Options;
use Symfony\Component\OptionsResolver\OptionsResolver;

use function is_null;

final class PSR6CacheVaultAdapter extends AbstractVaultAdapter
{
    public function __construct(
        private VaultAdapterInterface $adapter,
        private CacheItemPoolInterface $cache,
    ) {
    }

    public function getSecret(string $key, array $options = []): SecretInterface
    {
        $ttl = $this->getTtl($options);

        $item = $this->cache->getItem($key);

        if ($item->isHit()) {
            $data = json_decode($item->get(), true);
            return new Secret(
                $data['uniqueId'],
                $data['key'],
                $data['value'],
                $data['encrypted'],
                $data['metadata']
            );
        }

        $secret = $this->adapter->getSecret($key, $options);
        $item->set(json_encode($secret, JSON_PRETTY_PRINT));

        if (!is_null($ttl)) {
            $item->expiresAfter($ttl);
        }
        $this->cache->save($item);

        return $secret;
    }

    public function putSecret(SecretInterface $secret, array $options = []): SecretInterface
    {
        $ttl = $this->getTtl($options);

        $this->adapter->putSecret($secret, $options);

        if ($this->cache->hasItem($secret->getUniqueId()) || $ttl === 0) {
            $this->wipeCacheItem($secret->getUniqueId());

            return $secret;
        }

        $item = $this->cache->getItem($secret->getUniqueId());
        $item->set(json_encode($secret, JSON_PRETTY_PRINT));

        if (!is_null($ttl)) {
            $item->expiresAfter($ttl);
        }
        $this->cache->save($item);

        return $secret;
    }

    public function deleteSecret(SecretInterface $secret, array $options = []): void
    {
        $this->deleteSecretByKey($secret->getUniqueId(), $options);
    }

    public function deleteVault(array $options = []): void
    {
        if ($options['clear_cache'] === true) {
            $this->cache->clear();
        }
    }

    public function deleteSecretByKey(string $key, array $options): void
    {
        $this->adapter->deleteSecret($this->adapter->getSecret($key, $options), $options);

        $this->wipeCacheItem($key);
    }

    public function configureSharedOptions(OptionsResolver $resolver): void
    {
        parent::configureSharedOptions($resolver);

        $this->adapter->configureSharedOptions($resolver);
    }

    public function configureGetSecretOptions(OptionsResolver $resolver): void
    {
        parent::configureGetSecretOptions($resolver);

        $this->adapter->configureGetSecretOptions($resolver);

        $this->configureSharedGetAndPutSecretOptions($resolver);
    }

    public function configurePutSecretOptions(OptionsResolver $resolver): void
    {
        parent::configurePutSecretOptions($resolver);

        $this->adapter->configurePutSecretOptions($resolver);

        $this->configureSharedGetAndPutSecretOptions($resolver);
    }

    public function configureDeleteSecretOptions(OptionsResolver $resolver): void
    {
        parent::configureDeleteSecretOptions($resolver);

        $this->adapter->configureDeleteSecretOptions($resolver);

        $resolver->define('clear_cache')
            ->allowedTypes('bool')
            ->required()
            ->info('Clear the entire vault cache');

        $resolver->setDefault('clear_cache', function (Options $options): bool {
            if (true === $options['delete_all']) {
                return true;
            }

            return false;
        });
    }

    private function wipeCacheItem(string $key): void
    {
        if ($this->cache->hasItem($key)) {
            $item = $this->cache->getItem($key);
            $fetch = $item->get();
            $length = Utility::stringLength($fetch);
            $item->set(\str_repeat("\0", $length));
            $this->cache->save($item);
            $this->cache->deleteItem($key);
        }
    }

    private function configureSharedGetAndPutSecretOptions(OptionsResolver $resolver): void
    {
        $resolver->define('ttl')
            ->allowedTypes('int')
            ->info('Time in seconds to expire cache item');
    }

    private function getTtl(array $options): ?int
    {
        if (isset($options['ttl'])) {
            return $options['ttl'];
        }
        return null;
    }
}
