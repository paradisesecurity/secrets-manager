<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption;

use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Trait\ConfigurationTrait;

use function current;
use function is_array;
use function is_string;
use function reset;

class EncryptionRequest implements EncryptionRequestInterface
{
    use ConfigurationTrait;

    private ?string $encoding = null;

    private ?bool $chooseEncoder = null;

    private bool $decode = false;

    private string $additionalData = '';

    private bool $asymmetric = false;

    private ?string $mac = null;

    private ?string $signature = null;

    private ?string $version = null;

    private array $keys = [];

    private array $default = [
        EncryptionRequestInterface::ENCODING,
        EncryptionRequestInterface::CHOOSE_ENCODER,
        EncryptionRequestInterface::DECODE,
        EncryptionRequestInterface::ADDITIONAL_DATA,
        EncryptionRequestInterface::MAC,
        EncryptionRequestInterface::VERSION,
        EncryptionRequestInterface::ASYMMETRIC,
        EncryptionRequestInterface::SIGNATURE
    ];

    public function __construct(
        KeyInterface|array $keys,
        array $config = [],
    ) {
        if (!is_array(($single = $keys))) {
            $keys = [];
            $keys[] = $single;
        }
        $this->processKeys($keys);
        foreach ($config as $key => $value) {
            if (is_string($key)) {
                $this->processConfiguration($key, $value);
            }
        }
    }

    public function getKeys(): array
    {
        return $this->keys;
    }

    public function getKey(): KeyInterface
    {
        reset($this->keys);
        return current($this->keys);
    }

    public function setEncoding(?string $encoding): self
    {
        $this->encoding = $encoding;

        return $this;
    }

    public function getEncoding(): ?string
    {
        return $this->encoding;
    }

    public function setChooseEncoder(?bool $choose): self
    {
        $this->chooseEncoder = $choose;

        return $this;
    }

    public function chooseEncoder(): ?bool
    {
        return $this->chooseEncoder;
    }

    public function setDecode(bool $decode): self
    {
        $this->decode = $decode;

        return $this;
    }

    public function decode(): bool
    {
        return $this->decode;
    }

    public function setAdditionalData(?string $data): self
    {
        $this->additionalData = ($data ? $data : '');

        return $this;
    }

    public function getAdditionalData(): string
    {
        return $this->additionalData;
    }

    public function setAsymmetric(bool $asymmetric): self
    {
        $this->asymmetric = $asymmetric;

        return $this;
    }

    public function isAsymmetric(): bool
    {
        return $this->asymmetric;
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

    public function setMac(?string $mac): self
    {
        $this->mac = $mac;

        return $this;
    }

    public function getMac(): ?string
    {
        return $this->mac;
    }

    public function setSignature(?string $signature): self
    {
        $this->signature = $signature;

        return $this;
    }

    public function getSignature(): ?string
    {
        return $this->signature;
    }

    protected function processKeys(array $keys): void
    {
        foreach ($keys as $key) {
            if ($key instanceof KeyInterface) {
                $this->keys[] = $key;
            }
        }
    }
}
