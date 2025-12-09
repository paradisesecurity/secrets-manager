<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Key\Encryption;

use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\MessageEncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Exception\KeyringEncryptionException;
use ParadiseSecurity\Component\SecretsManager\Key\Encryption\KeyringEncryption;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(KeyringEncryption::class)]
final class KeyringEncryptionTest extends TestCase
{
    #[Test]
    public function it_encrypts_plaintext_successfully(): void
    {
        $plaintext = '{"uniqueId":"test","vault":{},"macs":[]}';
        $expectedCiphertext = 'encrypted-data-here';

        $testKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createMock(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->expects($this->once())
            ->method('encrypt')
            ->with($this->callback(function (MessageEncryptionRequest $request) use ($plaintext) {
                return $request->getMessage()->getString() === $plaintext;
            }))
            ->willReturn($expectedCiphertext);

        $keyringEncryption = new KeyringEncryption($encryptionAdapter);

        $result = $keyringEncryption->encrypt($plaintext, $testKey);

        $this->assertSame($expectedCiphertext, $result);
    }

    #[Test]
    public function it_throws_exception_when_encryption_fails(): void
    {
        $testKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('encrypt')
            ->willThrowException(new \RuntimeException('Encryption failed'));

        $keyringEncryption = new KeyringEncryption($encryptionAdapter);

        $this->expectException(KeyringEncryptionException::class);
        $this->expectExceptionMessage('Failed to encrypt keyring data');

        $keyringEncryption->encrypt('plaintext', $testKey);
    }

    #[Test]
    public function it_decrypts_ciphertext_successfully(): void
    {
        $ciphertext = 'encrypted-data-here';
        $expectedPlaintext = '{"uniqueId":"test","vault":{},"macs":[]}';

        $testKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createMock(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->expects($this->once())
            ->method('decrypt')
            ->with($this->callback(function (MessageEncryptionRequest $request) use ($ciphertext) {
                return $request->getMessage()->getString() === $ciphertext;
            }))
            ->willReturn(new HiddenString($expectedPlaintext));

        $keyringEncryption = new KeyringEncryption($encryptionAdapter);

        $result = $keyringEncryption->decrypt($ciphertext, $testKey);

        $this->assertSame($expectedPlaintext, $result);
    }

    #[Test]
    public function it_throws_exception_when_decryption_fails(): void
    {
        $testKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('decrypt')
            ->willThrowException(new \RuntimeException('Decryption failed'));

        $keyringEncryption = new KeyringEncryption($encryptionAdapter);

        $this->expectException(KeyringEncryptionException::class);
        $this->expectExceptionMessage('Failed to decrypt keyring data');

        $keyringEncryption->decrypt('ciphertext', $testKey);
    }

    #[Test]
    public function it_generates_mac_successfully(): void
    {
        $data = 'unique-id-to-authenticate';
        $expectedMac = 'generated-mac-value';

        $testKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createMock(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->expects($this->once())
            ->method('authenticate')
            ->with($this->callback(function (MessageEncryptionRequest $request) use ($data) {
                return $request->getMessage()->getString() === $data;
            }))
            ->willReturn($expectedMac);

        $keyringEncryption = new KeyringEncryption($encryptionAdapter);

        $result = $keyringEncryption->generateMAC($testKey, $data);

        $this->assertSame($expectedMac, $result);
    }

    #[Test]
    public function it_throws_exception_when_mac_generation_fails(): void
    {
        $testKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('authenticate')
            ->willThrowException(new \RuntimeException('MAC generation failed'));

        $keyringEncryption = new KeyringEncryption($encryptionAdapter);

        $this->expectException(KeyringEncryptionException::class);
        $this->expectExceptionMessage('Failed to generate MAC');

        $keyringEncryption->generateMAC($testKey, 'data');
    }

    #[Test]
    public function it_handles_empty_plaintext(): void
    {
        $testKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('encrypt')
            ->willReturn('encrypted-empty');

        $keyringEncryption = new KeyringEncryption($encryptionAdapter);

        $result = $keyringEncryption->encrypt('', $testKey);

        $this->assertSame('encrypted-empty', $result);
    }

    #[Test]
    public function it_handles_large_plaintext(): void
    {
        $largePlaintext = str_repeat('A', 10000);
        $expectedCiphertext = 'encrypted-large-data';

        $testKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('encrypt')
            ->willReturn($expectedCiphertext);

        $keyringEncryption = new KeyringEncryption($encryptionAdapter);

        $result = $keyringEncryption->encrypt($largePlaintext, $testKey);

        $this->assertSame($expectedCiphertext, $result);
    }
}
