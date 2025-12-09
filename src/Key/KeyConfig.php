<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key;

use ParagonIE\HiddenString\HiddenString;
use ParadiseSecurity\Component\SecretsManager\Trait\ConfigurationTrait;

use function is_string;

/**
 * Immutable configuration for key generation.
 */
// TODO: Make readonly when possible
final class KeyConfig implements KeyConfigInterface
{
    use ConfigurationTrait;

    private KeyType $type;

    private ?HiddenString $password = null;

    private ?string $salt = null;

    private ?string $securityLevel = null;

    private ?int $algorithm = null;

    private ?string $version = null;

    private array $default = [
        KeyConfigInterface::PASSWORD,
        KeyConfigInterface::SALT,
        KeyConfigInterface::SECURITY_LEVEL,
        KeyConfigInterface::ALGORITHM,
        KeyConfigInterface::VERSION
    ];

    public function __construct(
        KeyType|string $type,
        array $config = [],
    ) {
        foreach ($config as $key => $value) {
            if (is_string($key)) {
                $this->processConfiguration($key, $value);
            }
        }

        if (is_string($type)) {
            $this->type = KeyType::fromString($type);
        }
    }

    /**
     * Create from legacy array-based config.
     * 
     * This maintains backward compatibility with your old array pattern
     * while allowing forward migration to named parameters.
     */
    public static function fromArray(KeyType|string $type, array $config): self
    {
        return new self(
            type: $type,
            password: $config[self::PASSWORD] ?? null,
            salt: $config[self::SALT] ?? null,
            securityLevel: $config[self::SECURITY_LEVEL] ?? null,
            algorithm: $config[self::ALGORITHM] ?? null,
            version: $config[self::VERSION] ?? null,
        );
    }

    /**
     * Export to array format (for code that expects arrays).
     */
    public function toArray(): array
    {
        return array_filter([
            self::PASSWORD => $this->password,
            self::SALT => $this->salt,
            self::SECURITY_LEVEL => $this->securityLevel,
            self::ALGORITHM => $this->algorithm,
            self::VERSION => $this->version,
        ], fn($value) => $value !== null);
    }

    public function getType(): string
    {
        return $this->type->toString();
    }

    public function getPassword(): ?HiddenString
    {
        return $this->password;
    }

    public function getSalt(): ?string
    {
        return $this->salt;
    }

    public function getSecurityLevel(): ?string
    {
        return $this->securityLevel;
    }

    public function getAlgorithm(): ?int
    {
        return $this->algorithm;
    }

    public function getVersion(): ?string
    {
        return $this->version;
    }

    // DEPRECATED setters for backward compatibility
    /** @deprecated Use withPassword() */
    public function setPassword(?HiddenString $password): self
    {
        return $this->withPassword($password);
    }

    /** @deprecated Use withSalt() */
    public function setSalt(?string $salt): self
    {
        return $this->withSalt($salt);
    }

    /** @deprecated Use withSecurityLevel() */
    public function setSecurityLevel(?string $securityLevel): self
    {
        return $this->withSecurityLevel($securityLevel);
    }

    /** @deprecated Use withAlgorithm() */
    public function setAlgorithm(?int $algorithm): self
    {
        return $this->withAlgorithm($algorithm);
    }

    /** @deprecated Use withVersion() */
    public function setVersion(?string $version): self
    {
        return $this->withVersion($version);
    }

    // Immutable update methods (with*)
    public function withPassword(?HiddenString $password): self
    {
        return new self(
            $this->type,
            [
                KeyConfigInterface::PASSWORD => $password,
                KeyConfigInterface::SALT => $this->salt,
                KeyConfigInterface::SECURITY_LEVEL => $this->securityLevel,
                KeyConfigInterface::ALGORITHM => $this->algorithm,
                KeyConfigInterface::VERSION => $this->version
            ]
        );
    }

    public function withSalt(?string $salt): self
    {
        return new self(
            $this->type,
            [
                KeyConfigInterface::PASSWORD => $this->password,
                KeyConfigInterface::SALT => $salt,
                KeyConfigInterface::SECURITY_LEVEL => $this->securityLevel,
                KeyConfigInterface::ALGORITHM => $this->algorithm,
                KeyConfigInterface::VERSION => $this->version
            ]
        );
    }

    public function withSecurityLevel(?string $securityLevel): self
    {
        return new self(
            $this->type,
            [
                KeyConfigInterface::PASSWORD => $this->password,
                KeyConfigInterface::SALT => $this->salt,
                KeyConfigInterface::SECURITY_LEVEL => $securityLevel,
                KeyConfigInterface::ALGORITHM => $this->algorithm,
                KeyConfigInterface::VERSION => $this->version
            ]
        );
    }

    public function withAlgorithm(?int $algorithm): self
    {
        return new self(
            $this->type,
            [
                KeyConfigInterface::PASSWORD => $this->password,
                KeyConfigInterface::SALT => $this->salt,
                KeyConfigInterface::SECURITY_LEVEL => $this->securityLevel,
                KeyConfigInterface::ALGORITHM => $algorithm,
                KeyConfigInterface::VERSION => $this->version
            ]
        );
    }

    public function withVersion(?string $version): self
    {
        return new self(
            $this->type,
            [
                KeyConfigInterface::PASSWORD => $this->password,
                KeyConfigInterface::SALT => $this->salt,
                KeyConfigInterface::SECURITY_LEVEL => $this->securityLevel,
                KeyConfigInterface::ALGORITHM => $this->algorithm,
                KeyConfigInterface::VERSION => $version
            ]
        );
    }

    /**
     * Merge with another config array (for your ConfigurationTrait use case).
     */
    public function merge(array $config): self
    {
        return self::fromArray($this->type, array_merge($this->toArray(), $config));
    }
}
