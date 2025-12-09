<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Key;

use PHPUnit\Framework\TestCase;
use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\HaliteEncryptionAdapter;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyringInterface;
use ParadiseSecurity\Component\SecretsManager\Key\Keyring;
use ParagonIE\HiddenString\HiddenString;

final class KeyringTest extends TestCase
{
    public function testSavedKeyring(): void
    {
        $keyring = $this->getExampleKeyring();
        $this->assertTrue($keyring->isLocked());

        $value = $keyring->getMetadata('my_secrets', 'access_pin');
        $this->assertSame($value, '12345');

        $key = $keyring->getKey('my_secrets', 'encryption_key');
        $this->assertSame($key->getHex()->getString(), '901b3eccb6d802776156e8ec93763c5f5b494d496fc56eef51f83efd8f9b7d78');

        $this->assertSame($keyring->getUniqueId(), 'HC9JuFvtSZuD9oZSjJ6l1nGpuUwzXmmEV7rBQSsxIi6DvGpI39E0zO-NotSPMav7');

        $publicKey = $this->getExampleSignaturePublicKey();
        $keyring->addKey('my_secrets', 'public_key', $publicKey);
        $badKey = $keyring->getKey('my_secrets', 'public_key');
        $this->assertSame($badKey, null);

        $keyring->unlock('KChHV4LyeZnCDxcBHCl5qvOIdl630fTtQj2Cw5ZQUCIwstjhNDU4AvpNv_D_qFFIx3itAZAercdEYfZ5Z9cb3w==');
        $this->assertFalse($keyring->isLocked());

        $keyring->addKey('my_secrets', 'public_key', $publicKey);
        $goodKey = $keyring->getKey('my_secrets', 'public_key');
        $this->assertSame($goodKey->getHex()->getString(), $publicKey->getHex()->getString());
    }

    protected function getExampleSignaturePublicKey(): KeyInterface
    {
        return new Key(
            new HiddenString(
                '4af75f7fc8051778a86944e45a2c9643145401c62552e147d719c6c831b7864a'
            ),
            KeyFactoryInterface::ASYMMETRIC_SIGNATURE_PUBLIC_KEY,
            HaliteEncryptionAdapter::ADAPTER_NAME,
            HaliteEncryptionAdapter::CURRENT_VERSION,
        );
    }

    protected function getExampleKeyring(): KeyringInterface
    {
        $keyring = new Keyring();

        return $keyring->withSecuredData(
            'HC9JuFvtSZuD9oZSjJ6l1nGpuUwzXmmEV7rBQSsxIi6DvGpI39E0zO-NotSPMav7',
            [
                'my_secrets' => [
                    'encryption_key' => [
                        'hex' => '901b3eccb6d802776156e8ec93763c5f5b494d496fc56eef51f83efd8f9b7d78',
                        'type' => 'symmetric_encryption_key',
                        'adapter' => 'halite',
                        'version' => '5.0.0',
                    ],
                    'metadata' => [
                        'access_pin' => '12345'
                    ]
                ]
            ],
            [
                'KChHV4LyeZnCDxcBHCl5qvOIdl630fTtQj2Cw5ZQUCIwstjhNDU4AvpNv_D_qFFIx3itAZAercdEYfZ5Z9cb3w=='
            ]
        );
    }
}
