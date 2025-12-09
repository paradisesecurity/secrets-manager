<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Secret\Processing;

use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Exception\SecretProcessingException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyConfigInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Secret\Processing\SecretDataProcessor;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(SecretDataProcessor::class)]
final class SecretDataProcessorTest extends TestCase
{
    private function createKeyFactoryStub(?KeyInterface $returnKey = null): KeyFactoryInterface
    {
        return new class($returnKey) implements KeyFactoryInterface {
            public function __construct(private ?KeyInterface $returnKey = null) {}
            
            public function getAdapter(string $adapter): never { throw new \BadMethodCallException('Not implemented'); }
            public function generateKey(KeyConfigInterface $config, string $adapter): never { throw new \BadMethodCallException('Not implemented'); }
            public function getRawKeyMaterial(KeyInterface $key): never { throw new \BadMethodCallException('Not implemented'); }
            
            public function buildKeyFromRawKeyData(string $hex, string $type, string $adapter, string $version): KeyInterface
            {
                return $this->returnKey ?? throw new \RuntimeException('No key configured');
            }
        };
    }

    #[Test]
    public function it_encrypts_simple_value(): void
    {
        $dataKey = $this->createStub(KeyInterface::class);
        $value = 'my-secret-password';
        $expectedCiphertext = 'encrypted-data';

        $encryptionAdapter = $this->createMock(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->expects($this->once())
            ->method('encrypt')
            ->willReturn($expectedCiphertext);

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $result = $processor->encryptValue($dataKey, $value);

        $this->assertSame($expectedCiphertext, $result);
    }

    #[Test]
    public function it_encrypts_array_value(): void
    {
        $dataKey = $this->createStub(KeyInterface::class);
        $value = ['username' => 'admin', 'password' => 'secret'];

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('encrypt')
            ->willReturn('encrypted-array-data');

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $result = $processor->encryptValue($dataKey, $value);

        $this->assertIsString($result);
    }

    #[Test]
    public function it_throws_exception_for_non_serializable_value(): void
    {
        $dataKey = $this->createStub(KeyInterface::class);
        $resource = fopen('php://memory', 'r');

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $this->expectException(SecretProcessingException::class);
        $this->expectExceptionMessage('Failed to encode secret value');

        try {
            $processor->encryptValue($dataKey, $resource);
        } finally {
            fclose($resource);
        }
    }

    #[Test]
    public function it_throws_exception_when_encryption_fails(): void
    {
        $dataKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('encrypt')
            ->willThrowException(new \RuntimeException('Encryption error'));

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $this->expectException(SecretProcessingException::class);
        $this->expectExceptionMessage('Failed to encrypt secret value');

        $processor->encryptValue($dataKey, 'value');
    }

    #[Test]
    public function it_decrypts_simple_value(): void
    {
        $dataKey = $this->createStub(KeyInterface::class);
        $encryptedValue = 'encrypted-data';
        $decryptedJson = '"my-secret-password"';

        $encryptionAdapter = $this->createMock(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->expects($this->once())
            ->method('decrypt')
            ->willReturn(new HiddenString($decryptedJson));

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $result = $processor->decryptValue($encryptedValue, $dataKey);

        $this->assertSame('my-secret-password', $result);
    }

    #[Test]
    public function it_decrypts_array_value(): void
    {
        $dataKey = $this->createStub(KeyInterface::class);
        $encryptedValue = 'encrypted-array-data';
        $decryptedJson = '{"username":"admin","password":"secret"}';

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('decrypt')
            ->willReturn(new HiddenString($decryptedJson));

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $result = $processor->decryptValue($encryptedValue, $dataKey);

        $this->assertIsArray($result);
        $this->assertSame('admin', $result['username']);
        $this->assertSame('secret', $result['password']);
    }

    #[Test]
    public function it_throws_exception_when_decryption_fails(): void
    {
        $dataKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('decrypt')
            ->willThrowException(new \RuntimeException('Decryption error'));

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $this->expectException(SecretProcessingException::class);
        $this->expectExceptionMessage('Failed to decrypt secret value');

        $processor->decryptValue('encrypted-data', $dataKey);
    }

    #[Test]
    public function it_throws_exception_for_invalid_json_after_decryption(): void
    {
        $dataKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('decrypt')
            ->willReturn(new HiddenString('invalid-json{'));

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $this->expectException(SecretProcessingException::class);
        $this->expectExceptionMessage('Failed to decode decrypted secret');

        $processor->decryptValue('encrypted-data', $dataKey);
    }

    #[Test]
    public function it_authenticates_data(): void
    {
        $authKey = $this->createStub(KeyInterface::class);
        $value = 'data-to-authenticate';
        $mac = 'generated-mac';

        $encryptionAdapter = $this->createMock(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->expects($this->once())
            ->method('authenticate')
            ->willReturn($mac);

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $result = $processor->authenticateData($value, $authKey);

        $this->assertStringStartsWith($mac, $result);
        $this->assertStringContainsString($value, $result);
    }

    #[Test]
    public function it_throws_exception_when_authentication_fails(): void
    {
        $authKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('authenticate')
            ->willThrowException(new \RuntimeException('Auth error'));

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $this->expectException(SecretProcessingException::class);
        $this->expectExceptionMessage('Failed to authenticate data');

        $processor->authenticateData('data', $authKey);
    }

    #[Test]
    public function it_verifies_authenticated_data(): void
    {
        $authKey = $this->createStub(KeyInterface::class);
        // MAC is 64 bytes (SODIUM_CRYPTO_GENERICHASH_BYTES_MAX)
        $mac = str_repeat('a', 64);
        $data = 'original-data';
        $authenticatedData = $mac . $data;

        $encryptionAdapter = $this->createMock(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->expects($this->once())
            ->method('verify')
            ->willReturn(true);

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $result = $processor->verifyData($authenticatedData, $authKey);

        $this->assertSame($data, $result);
    }

    #[Test]
    public function it_throws_exception_when_verification_fails(): void
    {
        $authKey = $this->createStub(KeyInterface::class);
        $mac = str_repeat('a', 64);
        $authenticatedData = $mac . 'data';

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('verify')
            ->willReturn(false);

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $this->expectException(SecretProcessingException::class);
        $this->expectExceptionMessage('Secret data authentication failed');

        $processor->verifyData($authenticatedData, $authKey);
    }

    #[Test]
    public function it_encrypts_data_key(): void
    {
        $dataKey = $this->createConfiguredStub(KeyInterface::class, [
            'getHex' => new HiddenString('hex-value'),
            'getType' => 'symmetric_encryption_key',
            'getVersion' => '5.0.0',
            'getAdapter' => 'halite'
        ]);
        $kmsKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createMock(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->expects($this->once())
            ->method('encrypt')
            ->willReturn('encrypted-key-data');

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $result = $processor->encryptDataKey($dataKey, $kmsKey);

        $this->assertSame('encrypted-key-data', $result);
    }

    #[Test]
    public function it_throws_exception_when_data_key_encryption_fails(): void
    {
        $dataKey = $this->createConfiguredStub(KeyInterface::class, [
            'getHex' => new HiddenString('hex'),
            'getType' => 'type',
            'getVersion' => 'v1',
            'getAdapter' => 'adapter'
        ]);
        $kmsKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('encrypt')
            ->willThrowException(new \RuntimeException('Encryption failed'));

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $this->expectException(SecretProcessingException::class);
        $this->expectExceptionMessage('Failed to encrypt data key');

        $processor->encryptDataKey($dataKey, $kmsKey);
    }

    #[Test]
    public function it_decrypts_data_key(): void
    {
        $kmsKey = $this->createStub(KeyInterface::class);
        $encryptedDataKey = 'encrypted-key-data';
        $decryptedKeyData = json_encode([
            'hex' => 'decrypted-hex',
            'type' => 'symmetric_encryption_key',
            'adapter' => 'halite',
            'version' => '5.0.0'
        ]);

        $reconstructedKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('decrypt')
            ->willReturn(new HiddenString($decryptedKeyData));

        $keyFactory = $this->createKeyFactoryStub($reconstructedKey);

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $result = $processor->decryptDataKey($encryptedDataKey, $kmsKey);

        $this->assertSame($reconstructedKey, $result);
    }

    #[Test]
    public function it_throws_exception_when_data_key_decryption_fails(): void
    {
        $kmsKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('decrypt')
            ->willThrowException(new \RuntimeException('Decryption failed'));

        $keyFactory = $this->createKeyFactoryStub();

        $processor = new SecretDataProcessor($encryptionAdapter, $keyFactory);

        $this->expectException(SecretProcessingException::class);
        $this->expectExceptionMessage('Failed to decrypt data key');

        $processor->decryptDataKey('encrypted', $kmsKey);
    }
}

