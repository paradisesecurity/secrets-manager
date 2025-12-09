<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\KeyFactory;

use ParadiseSecurity\Component\SecretsManager\Adapter\AbstractAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfigInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;

interface KeyFactoryAdapterInterface extends AbstractAdapterInterface
{
    public function getAdapterSpecificKeyType(KeyInterface $key): string;

    public function getSupportedKeyTypes(): array;

    public function supports(string $encryption): bool;

    public function getAdapterRequiredKey(KeyInterface $key, string $type): mixed;

    public function splitKeyPair(KeyInterface $key, string $keyType): array;

    public function getDefaultConfig(?string $version = null): array;

    public function generateKey(KeyConfigInterface $config): KeyInterface;
}
