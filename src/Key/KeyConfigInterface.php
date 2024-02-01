<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Key;

use ParadiseSecurity\Component\SecretsManager\Trait\ConfigurationAwareInterface;
use ParagonIE\HiddenString\HiddenString;

interface KeyConfigInterface extends ConfigurationAwareInterface
{
    public const PASSWORD = 'password';

    public const SALT = 'salt';

    public const SECURITY_LEVEL = 'security_level';

    public const ALGORITHM = 'algorithm';

    public const VERSION = 'version';

    public function getType(): string;

    public function setPassword(?HiddenString $password): self;

    public function getPassword(): ?HiddenString;

    public function setSalt(?string $salt): self;

    public function getSalt(): ?string;

    public function setSecurityLevel(?string $securityLevel): self;

    public function getSecurityLevel(): ?string;

    public function setAlgorithm(?int $algorithm): self;

    public function getAlgorithm(): ?int;

    public function setVersion(?string $version): self;

    public function getVersion(): ?string;
}
