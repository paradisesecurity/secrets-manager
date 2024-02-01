<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption;

use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Trait\ConfigurationAwareInterface;

interface EncryptionRequestInterface extends ConfigurationAwareInterface
{
    public const ENCODING = 'encoding';

    public const CHOOSE_ENCODER = 'choose_encoder';

    public const DECODE = 'decode';

    public const ADDITIONAL_DATA = 'additional_data';

    public const ASYMMETRIC = 'asymmetric';

    public const MAC = 'mac';

    public const SIGNATURE = 'signature';

    public const VERSION = 'version';

    public function getKeys(): array;

    public function getKey(): KeyInterface;

    public function setEncoding(?string $encoding): self;

    public function getEncoding(): ?string;

    public function setChooseEncoder(?bool $choose): self;

    public function chooseEncoder(): ?bool;

    public function setDecode(bool $decode): self;

    public function decode(): bool;

    public function setAdditionalData(?string $data): self;

    public function getAdditionalData(): string;

    public function setAsymmetric(bool $asymmetric): self;

    public function isAsymmetric(): bool;

    public function setVersion(?string $version): self;

    public function getVersion(): ?string;

    public function setMac(?string $mac): self;

    public function getMac(): ?string;

    public function setSignature(?string $signature): self;

    public function getSignature(): ?string;
}
