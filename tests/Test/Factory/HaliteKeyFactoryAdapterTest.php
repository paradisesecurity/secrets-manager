<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Factory;

use PHPUnit\Framework\TestCase;
use ParadiseSecurity\Component\SecretsManager\Factory\HaliteKeyFactoryAdapter;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfig;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfigInterface;
use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use ParagonIE\Halite\Asymmetric\SignaturePublicKey;
use ParagonIE\Halite\Asymmetric\SignatureSecretKey;
use ParagonIE\HiddenString\HiddenString;

use function bin2hex;

use const SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13;

final class HaliteKeyFactoryAdapterTest extends TestCase
{
    protected function deriveKey(string $type, string $raw, array $options = [])
    {
        $adapter = new HaliteKeyFactoryAdapter();
        $config = new KeyConfig(
            $type,
            [
                KeyConfigInterface::PASSWORD => new HiddenString('apple'),
                KeyConfigInterface::SALT => "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
            ]
        );
        $config->addOptions($options);
        $key = $adapter->generateKey($config);
        $this->assertSame(
            $key->getType(),
            $type
        );
        $haliteKey = $adapter->getAdapterRequiredKey($key, HaliteKeyFactoryAdapter::HALITE_KEY);
        $this->assertSame(
            $haliteKey->getRawKeyMaterial(),
            $raw
        );
    }

    public function testDeriveSymmetricAuthenticationKey()
    {
        $type = KeyFactoryInterface::SYMMETRIC_AUTHENTICATION_KEY;
        $raw = "\x3a\x16\x68\xc1\x45\x8a\x4f\x59\x9c\x36\x4e\xa4\x7f\xae\xfa\xe1" .
        "\xee\xa3\xa6\xd0\x34\x26\x35\xc9\xb4\x79\xee\xab\xf4\x71\x86\xaa";
        $this->deriveKey($type, $raw);
    }

    public function testDeriveSymmetricEncryptionKey()
    {
        $type = KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY;
        $raw = "\x3a\x16\x68\xc1\x45\x8a\x4f\x59\x9c\x36\x4e\xa4\x7f\xae\xfa\xe1" .
        "\xee\xa3\xa6\xd0\x34\x26\x35\xc9\xb4\x79\xee\xab\xf4\x71\x86\xaa";
        $this->deriveKey($type, $raw);
    }

    public function testDeriveSymmetricEncryptionKeyOldAlgorithm()
    {
        $type = KeyFactoryInterface::SYMMETRIC_ENCRYPTION_KEY;
        $raw = "\x79\x12\x36\xc1\xf0\x6b\x73\xbd\xaa\x88\x89\x80\xe3\x2c\x4b\xdb" .
        "\x25\xd1\xf9\x39\xe5\xf7\x13\x30\x5c\xd8\x4c\x50\x22\xcc\x96\x6e";
        $options = [
            KeyConfigInterface::ALGORITHM => SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13
        ];
        $this->deriveKey($type, $raw, $options);
    }

    public function testDeriveAsymmetricSigningKey()
    {
        $adapter = new HaliteKeyFactoryAdapter();
        $config = new KeyConfig(
            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_KEY_PAIR,
            [
                KeyConfigInterface::PASSWORD => new HiddenString('apple'),
                KeyConfigInterface::SALT => "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
            ]
        );
        $keypair = $adapter->generateKey($config);
        $this->assertSame(
            $keypair->getType(),
            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_KEY_PAIR
        );
        $haliteKeypair = $adapter->getAdapterRequiredKey($keypair, HaliteKeyFactoryAdapter::HALITE_KEY);
        $signSecret = $haliteKeypair->getSecretKey();
        $signPublic = $haliteKeypair->getPublicKey();
        $this->assertTrue($signSecret instanceof SignatureSecretKey);
        $this->assertTrue($signPublic instanceof SignaturePublicKey);
        $this->assertSame(
            $signPublic->getRawKeyMaterial(),
            "\x9a\xce\x92\x8f\x6a\x27\x93\x8e\x87\xac\x9b\x97\xfb\xe2\x50\x6b" .
            "\x67\xd5\x8b\x68\xeb\x37\xc2\x2d\x31\xdb\xcf\x7e\x8d\xa0\xcb\x17"
        );
    }

    public function testSplitEncryptionKeyPair()
    {
        $adapter = new HaliteKeyFactoryAdapter();
        $config = new KeyConfig(KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_KEY_PAIR);
        $keypair = $adapter->generateKey($config);
        $this->assertSame(
            $keypair->getType(),
            KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_KEY_PAIR
        );
        $haliteKeypair = $adapter->getAdapterRequiredKey($keypair, HaliteKeyFactoryAdapter::HALITE_KEY);
        $encSecret = $haliteKeypair->getSecretKey();
        $encPublic = $haliteKeypair->getPublicKey();
        $this->assertTrue($encSecret instanceof EncryptionSecretKey);
        $this->assertTrue($encPublic instanceof EncryptionPublicKey);
        $keys = $adapter->splitKeyPair($keypair, HaliteKeyFactoryAdapter::HALITE_KEY);
        foreach ($keys as $key) {
            if ($key->getType() === KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_SECRET_KEY) {
                $secretKey = $adapter->getAdapterRequiredKey($key, HaliteKeyFactoryAdapter::HALITE_KEY);
            }
            if ($key->getType() === KeyFactoryInterface::ASYMMETRIC_ENCRYPTION_PUBLIC_KEY) {
                $publicKey = $adapter->getAdapterRequiredKey($key, HaliteKeyFactoryAdapter::HALITE_KEY);
            }
        }
        $this->assertSame(
            bin2hex($encPublic->getRawKeyMaterial()),
            bin2hex($publicKey->getRawKeyMaterial())
        );
        $this->assertSame(
            bin2hex($encSecret->getRawKeyMaterial()),
            bin2hex($secretKey->getRawKeyMaterial())
        );
    }
}
