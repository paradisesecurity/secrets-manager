<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Secret\Processing;

use ParadiseSecurity\Component\SecretsManager\Exception\SecretProcessingException;
use ParadiseSecurity\Component\SecretsManager\Factory\KeyFactoryInterface;
use ParadiseSecurity\Component\SecretsManager\Key\KeyInterface;
use ParadiseSecurity\Component\SecretsManager\Secret\Processing\DataKeyReconstructor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(DataKeyReconstructor::class)]
final class DataKeyReconstructorTest extends TestCase
{
    #[Test]
    public function it_reconstructs_key_from_valid_data(): void
    {
        $keyData = [
            'hex' => 'abc123',
            'type' => 'symmetric_encryption_key',
            'adapter' => 'halite',
            'version' => '5.0.0'
        ];

        $expectedKey = $this->createStub(KeyInterface::class);

        $keyFactory = $this->createMock(KeyFactoryInterface::class);
        $keyFactory
            ->expects($this->once())
            ->method('buildKeyFromRawKeyData')
            ->with('abc123', 'symmetric_encryption_key', 'halite', '5.0.0')
            ->willReturn($expectedKey);

        $reconstructor = new DataKeyReconstructor($keyFactory);

        $result = $reconstructor->reconstruct($keyData);

        $this->assertSame($expectedKey, $result);
    }

    #[Test]
    public function it_throws_exception_for_missing_hex_field(): void
    {
        $keyData = [
            'type' => 'symmetric_encryption_key',
            'adapter' => 'halite',
            'version' => '5.0.0'
        ];

        $keyFactory = $this->createStub(KeyFactoryInterface::class);
        $reconstructor = new DataKeyReconstructor($keyFactory);

        $this->expectException(SecretProcessingException::class);
        $this->expectExceptionMessage("Missing required field 'hex'");

        $reconstructor->reconstruct($keyData);
    }

    #[Test]
    public function it_throws_exception_for_missing_type_field(): void
    {
        $keyData = [
            'hex' => 'abc123',
            'adapter' => 'halite',
            'version' => '5.0.0'
        ];

        $keyFactory = $this->createStub(KeyFactoryInterface::class);
        $reconstructor = new DataKeyReconstructor($keyFactory);

        $this->expectException(SecretProcessingException::class);
        $this->expectExceptionMessage("Missing required field 'type'");

        $reconstructor->reconstruct($keyData);
    }

    #[Test]
    public function it_throws_exception_when_factory_fails(): void
    {
        $keyData = [
            'hex' => 'abc123',
            'type' => 'symmetric_encryption_key',
            'adapter' => 'halite',
            'version' => '5.0.0'
        ];

        $keyFactory = $this->createStub(KeyFactoryInterface::class);
        $keyFactory
            ->method('buildKeyFromRawKeyData')
            ->willThrowException(new \RuntimeException('Factory error'));

        $reconstructor = new DataKeyReconstructor($keyFactory);

        $this->expectException(SecretProcessingException::class);
        $this->expectExceptionMessage('Failed to reconstruct data key');

        $reconstructor->reconstruct($keyData);
    }
}
