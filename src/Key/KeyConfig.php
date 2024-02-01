<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key;

use ParagonIE\HiddenString\HiddenString;
use ParadiseSecurity\Component\SecretsManager\Trait\ConfigurationTrait;

use function is_string;

final class KeyConfig implements KeyConfigInterface
{
    use ConfigurationTrait;

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
        private string $type,
        array $config = [],
    ) {
        foreach ($config as $key => $value) {
            if (is_string($key)) {
                $this->processConfiguration($key, $value);
            }
        }
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function setPassword(?HiddenString $password): self
    {
        $this->password = $password;

        return $this;
    }

    public function getPassword(): ?HiddenString
    {
        return $this->password;
    }

    public function setSalt(?string $salt): self
    {
        $this->salt = $salt;

        return $this;
    }

    public function getSalt(): ?string
    {
        return $this->salt;
    }

    public function setSecurityLevel(?string $securityLevel): self
    {
        $this->securityLevel = $securityLevel;

        return $this;
    }

    public function getSecurityLevel(): ?string
    {
        return $this->securityLevel;
    }

    public function setAlgorithm(?int $algorithm): self
    {
        $this->algorithm = $algorithm;

        return $this;
    }

    public function getAlgorithm(): ?int
    {
        return $this->algorithm;
    }

    public function setVersion(?string $version): self
    {
        $this->version = $version;

        return $this;
    }

    public function getVersion(): ?string
    {
        return $this->version;
    }
}
