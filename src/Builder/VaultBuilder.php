<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Builder;

use ParadiseSecurity\Component\SecretsManager\File\FilesystemManagerInterface;
use ParadiseSecurity\Component\SecretsManager\Adapter\Vault\VaultAdapterInterface;
use Symfony\Component\Cache\Adapter\ApcuAdapter;
use Symfony\Component\Cache\Adapter\ChainAdapter;
use ParadiseSecurity\Component\SecretsManager\Adapter\Vault\ChainVaultAdapter;
use ParadiseSecurity\Component\SecretsManager\Adapter\Vault\PSR6CacheVaultAdapter;
use ParadiseSecurity\Component\SecretsManager\Adapter\Vault\FilesystemVaultAdapter;

/**
 * Sub-builder for vault adapter configuration.
 */
final class VaultBuilder
{
    private bool $useCache = true;
    private string $cachePrefix = 'secret-manager';
    private ?FilesystemManagerInterface $filesystemManager = null;

    public function withCache(bool $enabled = true, string $prefix = 'secret-manager'): self
    {
        $this->useCache = $enabled;
        $this->cachePrefix = $prefix;
        return $this;
    }

    public function withFilesystemManager(FilesystemManagerInterface $manager): self
    {
        $this->filesystemManager = $manager;
        return $this;
    }

    public function build(): VaultAdapterInterface
    {
        $filesystemVault = new FilesystemVaultAdapter(
            $this->filesystemManager
        );

        if (!$this->useCache) {
            return new ChainVaultAdapter([$filesystemVault]);
        }

        $cacheAdapter = new ChainAdapter([new ApcuAdapter($this->cachePrefix)]);
        $cacheVault = new PSR6CacheVaultAdapter(
            $filesystemVault,
            $cacheAdapter
        );

        return new ChainVaultAdapter([$cacheVault]);
    }
}
