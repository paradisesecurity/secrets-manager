<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Vault;

use ParadiseSecurity\Component\SecretsManager\Secret\SecretInterface;
use ParadiseSecurity\Component\SecretsManager\Secret\Secret;
use ParadiseSecurity\Component\SecretsManager\Utility\Utility;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\OptionsResolver\Options;
use Symfony\Component\OptionsResolver\OptionsResolver;

use function is_null;

use const JSON_PRETTY_PRINT;
use const JSON_THROW_ON_ERROR;

/**
 * PSR-6 cache decorator for vault adapters.
 * 
 * Implements the Decorator pattern to add caching capabilities to any
 * VaultAdapterInterface implementation. Uses PSR-6 CacheItemPoolInterface
 * for maximum compatibility with different cache backends.
 * 
 * Cache Strategy:
 * - Read-through: On cache miss, loads from wrapped adapter and caches
 * - Write-through: Writes to both cache and wrapped adapter
 * - Cache invalidation: On update/delete, removes from cache
 * 
 * Security:
 * - Overwrites cache items with zeros before deletion (data sanitization)
 * - Supports TTL for automatic expiration
 * - Can be chained with other decorators
 * 
 * Example:
 * ```
 * $cached = new PSR6CacheVaultAdapter(
 *     new FilesystemVaultAdapter($fsManager),
 *     $redisCache
 * );
 * ```
 * 
 * @see https://www.php-fig.org/psr/psr-6/
 * @see https://refactoring.guru/design-patterns/decorator
 */
final class PSR6CacheVaultAdapter extends AbstractVaultAdapter
{
    public function __construct(
        private VaultAdapterInterface $decoratedAdapter,
        private CacheItemPoolInterface $cache,
    ) {
    }

    /**
     * Read-through cache: Check cache first, load from adapter on miss.
     */
    public function getSecret(string $key, array $options = []): SecretInterface
    {
        $ttl = $this->getTtl($options);
        $item = $this->cache->getItem($key);

        if ($item->isHit()) {
            return $this->deserializeSecret($item->get());
        }

        // Cache miss: load from decorated adapter
        $secret = $this->decoratedAdapter->getSecret($key, $options);
        
        // Store in cache
        $this->cacheSecret($item, $secret, $ttl);

        return $secret;
    }

    /**
     * Write-through cache: Write to adapter and update cache.
     */
    public function putSecret(SecretInterface $secret, array $options = []): SecretInterface
    {
        $ttl = $this->getTtl($options);

        // Write to decorated adapter first
        $this->decoratedAdapter->putSecret($secret, $options);

        // Update cache
        if ($ttl === 0 || $this->cache->hasItem($secret->getUniqueId())) {
            // TTL=0 means no caching, or update existing cache entry
            $this->wipeCacheItem($secret->getUniqueId());
        }

        if ($ttl !== 0) {
            $item = $this->cache->getItem($secret->getUniqueId());
            $this->cacheSecret($item, $secret, $ttl);
        }

        return $secret;
    }

    /**
     * Deletes from both cache and decorated adapter.
     */
    public function deleteSecret(SecretInterface $secret, array $options = []): void
    {
        $this->deleteSecretByKey($secret->getUniqueId(), $options);
    }

    /**
     * Deletes from both cache and decorated adapter.
     */
    public function deleteSecretByKey(string $key, array $options): void
    {
        // Delete from decorated adapter
        $this->decoratedAdapter->deleteSecretByKey($key, $options);

        // Remove from cache
        $this->wipeCacheItem($key);
    }

    /**
     * Clears cache if requested, then deletes vault from decorated adapter.
     */
    public function deleteVault(array $options = []): void
    {
        if ($options['clear_cache'] === true) {
            $this->cache->clear();
        }

        $this->decoratedAdapter->deleteVault($options);
    }

    /**
     * Delegates to decorated adapter and adds cache-specific options.
     */
    public function configureSharedOptions(OptionsResolver $resolver): void
    {
        parent::configureSharedOptions($resolver);
        $this->decoratedAdapter->configureSharedOptions($resolver);
    }

    public function configureGetSecretOptions(OptionsResolver $resolver): void
    {
        parent::configureGetSecretOptions($resolver);
        $this->decoratedAdapter->configureGetSecretOptions($resolver);
        $this->configureCacheTtlOption($resolver);
    }

    public function configurePutSecretOptions(OptionsResolver $resolver): void
    {
        parent::configurePutSecretOptions($resolver);
        $this->decoratedAdapter->configurePutSecretOptions($resolver);
        $this->configureCacheTtlOption($resolver);
    }

    public function configureDeleteSecretOptions(OptionsResolver $resolver): void
    {
        parent::configureDeleteSecretOptions($resolver);
        $this->decoratedAdapter->configureDeleteSecretOptions($resolver);

        $resolver->define('clear_cache')
            ->allowedTypes('bool')
            ->default(function (Options $options): bool {
                return $options['delete_all'] === true;
            })
            ->info('Clear the entire cache when deleting vault');
    }

    /**
     * Configures TTL option for caching.
     */
    private function configureCacheTtlOption(OptionsResolver $resolver): void
    {
        if (!$resolver->isDefined('ttl')) {
            $resolver->define('ttl')
                ->allowedTypes('int', 'null')
                ->default(null)
                ->info('Time-to-live in seconds for cached secrets (null = no expiration, 0 = no caching)');
        }
    }

    /**
     * Gets TTL from options.
     */
    private function getTtl(array $options): ?int
    {
        return $options['ttl'] ?? null;
    }

    /**
     * Caches a secret with optional TTL.
     */
    private function cacheSecret(\Psr\Cache\CacheItemInterface $item, SecretInterface $secret, ?int $ttl): void
    {
        $item->set(json_encode($secret, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));

        if (!is_null($ttl)) {
            $item->expiresAfter($ttl);
        }

        $this->cache->save($item);
    }

    /**
     * Securely wipes and deletes a cache item.
     * 
     * Overwrites cached data with zeros before deletion for security.
     */
    private function wipeCacheItem(string $key): void
    {
        if (!$this->cache->hasItem($key)) {
            return;
        }

        $item = $this->cache->getItem($key);
        $data = $item->get();

        if (is_string($data)) {
            $length = Utility::stringLength($data);
            $item->set(str_repeat("\0", $length));
            $this->cache->save($item);
        }

        $this->cache->deleteItem($key);
    }

    /**
     * Deserializes cached JSON to Secret object.
     */
    private function deserializeSecret(string $json): SecretInterface
    {
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        return new Secret(
            $data['uniqueId'],
            $data['key'],
            $data['value'],
            $data['encrypted'],
            $data['metadata'] ?? []
        );
    }

    /**
     * Gets the decorated adapter.
     * 
     * Useful for testing and adapter introspection.
     */
    public function getDecoratedAdapter(): VaultAdapterInterface
    {
        return $this->decoratedAdapter;
    }
}
