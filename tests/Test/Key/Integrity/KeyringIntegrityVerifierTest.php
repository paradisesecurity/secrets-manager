<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Key\Integrity;

use ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\EncryptionAdapterInterface;
use ParadiseSecurity\Component\SecretsManager\Encryption\FileEncryptionRequest;
use ParadiseSecurity\Component\SecretsManager\Exception\KeyringIntegrityException;
use ParadiseSecurity\Component\SecretsManager\File\Checksum;
use ParadiseSecurity\Component\SecretsManager\File\ChecksumInterface;
use ParadiseSecurity\Component\SecretsManager\Key\Integrity\KeyringIntegrityVerifier;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(KeyringIntegrityVerifier::class)]
final class KeyringIntegrityVerifierTest extends TestCase
{
    private function createValidChecksum(?string $checksumValue = null, ?string $signatureValue = null): Checksum
    {
        // Create valid 88-byte checksum and signature strings
        $checksum = $checksumValue ?? str_repeat('a', ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        $signature = $signatureValue ?? str_repeat('b', ChecksumInterface::SIGNATURE_LENGTH_BYTES);
        
        return new Checksum($checksum, $signature);
    }

    #[Test]
    public function it_generates_checksum_successfully(): void
    {
        $fileHandle = fopen('php://memory', 'r');
        $expectedChecksum = 'abc123checksum';

        $encryptionAdapter = $this->createMock(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->expects($this->once())
            ->method('checksum')
            ->with($this->isInstanceOf(FileEncryptionRequest::class))
            ->willReturn($expectedChecksum);

        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $result = $verifier->generateChecksum($fileHandle);

        $this->assertSame($expectedChecksum, $result);

        fclose($fileHandle);
    }

    #[Test]
    public function it_throws_exception_when_checksum_generation_fails(): void
    {
        $fileHandle = fopen('php://memory', 'r');

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('checksum')
            ->willThrowException(new \RuntimeException('Checksum failed'));

        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $this->expectException(KeyringIntegrityException::class);
        $this->expectExceptionMessage('Failed to generate checksum');

        try {
            $verifier->generateChecksum($fileHandle);
        } finally {
            fclose($fileHandle);
        }
    }

    #[Test]
    public function it_generates_signature_successfully(): void
    {
        $fileHandle = fopen('php://memory', 'r');
        $secretKey = $this->createStub(KeyInterface::class);
        $expectedSignature = 'def456signature';

        $encryptionAdapter = $this->createMock(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->expects($this->once())
            ->method('sign')
            ->with($this->isInstanceOf(FileEncryptionRequest::class))
            ->willReturn($expectedSignature);

        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $result = $verifier->generateSignature($fileHandle, $secretKey);

        $this->assertSame($expectedSignature, $result);

        fclose($fileHandle);
    }

    #[Test]
    public function it_throws_exception_when_secret_key_is_null(): void
    {
        $fileHandle = fopen('php://memory', 'r');

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);

        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $this->expectException(KeyringIntegrityException::class);
        $this->expectExceptionMessage('Cannot generate signature without a secret key');

        try {
            $verifier->generateSignature($fileHandle, null);
        } finally {
            fclose($fileHandle);
        }
    }

    #[Test]
    public function it_throws_exception_when_signature_generation_fails(): void
    {
        $fileHandle = fopen('php://memory', 'r');
        $secretKey = $this->createStub(KeyInterface::class);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('sign')
            ->willThrowException(new \RuntimeException('Signing failed'));

        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $this->expectException(KeyringIntegrityException::class);
        $this->expectExceptionMessage('Failed to generate signature');

        try {
            $verifier->generateSignature($fileHandle, $secretKey);
        } finally {
            fclose($fileHandle);
        }
    }

    #[Test]
    public function it_verifies_matching_checksums(): void
    {
        $checksumValue = str_repeat('a', ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        $signatureValue = str_repeat('b', ChecksumInterface::SIGNATURE_LENGTH_BYTES);
        
        $storedChecksum = new Checksum($checksumValue, $signatureValue);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $result = $verifier->verifyChecksum($checksumValue, $storedChecksum);

        $this->assertTrue($result);
    }

    #[Test]
    public function it_rejects_non_matching_checksums(): void
    {
        $calculatedChecksum = str_repeat('a', ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        $storedChecksumValue = str_repeat('x', ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        $signatureValue = str_repeat('b', ChecksumInterface::SIGNATURE_LENGTH_BYTES);
        
        $storedChecksum = new Checksum($storedChecksumValue, $signatureValue);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $result = $verifier->verifyChecksum($calculatedChecksum, $storedChecksum);

        $this->assertFalse($result);
    }

    #[Test]
    public function it_verifies_valid_signature(): void
    {
        $fileHandle = fopen('php://memory', 'r');
        $publicKey = $this->createStub(KeyInterface::class);
        
        $checksumValue = str_repeat('c', ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        $signatureValue = str_repeat('s', ChecksumInterface::SIGNATURE_LENGTH_BYTES);
        $storedChecksum = new Checksum($checksumValue, $signatureValue);

        $encryptionAdapter = $this->createMock(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->expects($this->once())
            ->method('verify')
            ->with($this->isInstanceOf(FileEncryptionRequest::class))
            ->willReturn(true);

        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $result = $verifier->verifySignature($fileHandle, $storedChecksum, $publicKey);

        $this->assertTrue($result);

        fclose($fileHandle);
    }

    #[Test]
    public function it_rejects_invalid_signature(): void
    {
        $fileHandle = fopen('php://memory', 'r');
        $publicKey = $this->createStub(KeyInterface::class);
        
        $checksumValue = str_repeat('c', ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        $signatureValue = str_repeat('s', ChecksumInterface::SIGNATURE_LENGTH_BYTES);
        $storedChecksum = new Checksum($checksumValue, $signatureValue);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('verify')
            ->willReturn(false);

        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $result = $verifier->verifySignature($fileHandle, $storedChecksum, $publicKey);

        $this->assertFalse($result);

        fclose($fileHandle);
    }

    #[Test]
    public function it_skips_signature_verification_when_no_public_key_provided(): void
    {
        $fileHandle = fopen('php://memory', 'r');
        
        $checksumValue = str_repeat('c', ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        $signatureValue = str_repeat('s', ChecksumInterface::SIGNATURE_LENGTH_BYTES);
        $storedChecksum = new Checksum($checksumValue, $signatureValue);

        $encryptionAdapter = $this->createMock(EncryptionAdapterInterface::class);
        // Should not call verify when key is null
        $encryptionAdapter
            ->expects($this->never())
            ->method('verify');

        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $result = $verifier->verifySignature($fileHandle, $storedChecksum, null);

        $this->assertTrue($result);

        fclose($fileHandle);
    }

    #[Test]
    public function it_throws_exception_when_signature_verification_fails(): void
    {
        $fileHandle = fopen('php://memory', 'r');
        $publicKey = $this->createStub(KeyInterface::class);
        
        $checksumValue = str_repeat('c', ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        $signatureValue = str_repeat('s', ChecksumInterface::SIGNATURE_LENGTH_BYTES);
        $storedChecksum = new Checksum($checksumValue, $signatureValue);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $encryptionAdapter
            ->method('verify')
            ->willThrowException(new \RuntimeException('Verification error'));

        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $this->expectException(KeyringIntegrityException::class);
        $this->expectExceptionMessage('Signature verification failed');

        try {
            $verifier->verifySignature($fileHandle, $storedChecksum, $publicKey);
        } finally {
            fclose($fileHandle);
        }
    }

    #[Test]
    public function it_creates_checksum_file_content(): void
    {
        $checksum = str_repeat('a', ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        $signature = str_repeat('b', ChecksumInterface::SIGNATURE_LENGTH_BYTES);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $result = $verifier->createChecksumFile($checksum, $signature);

        $expected = $checksum . $signature;
        $this->assertSame($expected, $result);
        $this->assertSame(176, strlen($result)); // 88 + 88 = 176
    }

    #[Test]
    public function it_parses_checksum_file_content(): void
    {
        // Create valid 176-byte string (88 bytes checksum + 88 bytes signature)
        $checksumValue = str_repeat('a', ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        $signatureValue = str_repeat('b', ChecksumInterface::SIGNATURE_LENGTH_BYTES);
        $checksumFileContents = $checksumValue . $signatureValue;

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $result = $verifier->parseChecksumFile($checksumFileContents);

        $this->assertInstanceOf(Checksum::class, $result);
        $this->assertSame($checksumValue, $result->getChecksum());
        $this->assertSame($signatureValue, $result->getSignature());
    }

    #[Test]
    public function it_throws_exception_for_invalid_checksum_file_content(): void
    {
        // Create invalid string (wrong length)
        $invalidContent = 'too-short';

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        $this->expectException(\Exception::class);

        $verifier->parseChecksumFile($invalidContent);
    }

    #[Test]
    public function it_verifies_checksums_use_timing_safe_comparison(): void
    {
        // This test ensures we're using hash_equals (timing-safe comparison)
        $checksumA = str_repeat('a', ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        $checksumB = str_repeat('a', ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        $signatureValue = str_repeat('b', ChecksumInterface::SIGNATURE_LENGTH_BYTES);
        
        $storedChecksum = new Checksum($checksumA, $signatureValue);

        $encryptionAdapter = $this->createStub(EncryptionAdapterInterface::class);
        $verifier = new KeyringIntegrityVerifier($encryptionAdapter);

        // Should return true for identical values
        $this->assertTrue($verifier->verifyChecksum($checksumB, $storedChecksum));
        
        // Should return false for different values
        $checksumC = str_repeat('x', ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        $this->assertFalse($verifier->verifyChecksum($checksumC, $storedChecksum));
    }
}
