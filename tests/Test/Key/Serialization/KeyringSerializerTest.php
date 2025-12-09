<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Test\Key\Serialization;

use ParadiseSecurity\Component\SecretsManager\Exception\KeyringSerializationException;
use ParadiseSecurity\Component\SecretsManager\Key\Keyring;
use ParadiseSecurity\Component\SecretsManager\Key\KeyringInterface;
use ParadiseSecurity\Component\SecretsManager\Key\Serialization\KeyringSerializer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(KeyringSerializer::class)]
final class KeyringSerializerTest extends TestCase
{
    private KeyringSerializer $serializer;

    protected function setUp(): void
    {
        $this->serializer = new KeyringSerializer();
    }

    #[Test]
    public function it_serializes_keyring_to_json(): void
    {
        // Create a real Keyring instance with test data
        $keyring = new Keyring();
        $keyring = $keyring->withSecuredData(
            'test-unique-id',
            ['vault1' => ['key1' => 'data']],
            ['mac1', 'mac2']
        );

        $result = $this->serializer->serialize($keyring);

        $this->assertJson($result);
        
        $decoded = json_decode($result, true);
        $this->assertArrayHasKey('uniqueId', $decoded);
        $this->assertArrayHasKey('vault', $decoded);
        $this->assertArrayHasKey('macs', $decoded);
        $this->assertSame('test-unique-id', $decoded['uniqueId']);
    }

    #[Test]
    public function it_deserializes_valid_json_to_keyring(): void
    {
        $jsonData = json_encode([
            'uniqueId' => 'test-unique-id-123',
            'vault' => [
                'test-vault' => [
                    'key1' => 'encrypted-key-data'
                ]
            ],
            'macs' => ['mac-value-1', 'mac-value-2']
        ], JSON_PRETTY_PRINT);

        $keyring = $this->serializer->deserialize($jsonData);

        $this->assertInstanceOf(KeyringInterface::class, $keyring);
    }

    #[Test]
    public function it_throws_exception_for_invalid_json(): void
    {
        $invalidJson = '{"uniqueId": "test", "vault": {invalid}';

        $this->expectException(KeyringSerializationException::class);
        $this->expectExceptionMessage('Invalid JSON');

        $this->serializer->deserialize($invalidJson);
    }

    #[Test]
    public function it_throws_exception_for_missing_unique_id(): void
    {
        $jsonData = json_encode([
            'vault' => ['test' => []],
            'macs' => []
        ]);

        $this->expectException(KeyringSerializationException::class);
        $this->expectExceptionMessage("Missing required field 'uniqueId'");

        $this->serializer->deserialize($jsonData);
    }

    #[Test]
    public function it_throws_exception_for_missing_vault(): void
    {
        $jsonData = json_encode([
            'uniqueId' => 'test-id',
            'macs' => []
        ]);

        $this->expectException(KeyringSerializationException::class);
        $this->expectExceptionMessage("Missing required field 'vault'");

        $this->serializer->deserialize($jsonData);
    }

    #[Test]
    public function it_throws_exception_for_missing_macs(): void
    {
        $jsonData = json_encode([
            'uniqueId' => 'test-id',
            'vault' => []
        ]);

        $this->expectException(KeyringSerializationException::class);
        $this->expectExceptionMessage("Missing required field 'macs'");

        $this->serializer->deserialize($jsonData);
    }

    #[Test]
    public function it_throws_exception_for_non_array_data(): void
    {
        $jsonData = json_encode('just a string');

        $this->expectException(KeyringSerializationException::class);
        $this->expectExceptionMessage('Keyring data must be an array');

        $this->serializer->deserialize($jsonData);
    }

    #[Test]
    public function it_handles_complex_keyring_structures(): void
    {
        $complexData = [
            'uniqueId' => 'complex-id',
            'vault' => [
                'vault1' => [
                    'key1' => 'data1',
                    'key2' => 'data2'
                ],
                'vault2' => [
                    'key3' => 'data3'
                ]
            ],
            'macs' => ['mac1', 'mac2', 'mac3']
        ];

        $jsonData = json_encode($complexData, JSON_PRETTY_PRINT);
        
        $keyring = $this->serializer->deserialize($jsonData);
        
        $this->assertInstanceOf(KeyringInterface::class, $keyring);
        
        // Serialize again and verify round-trip
        $reserialized = $this->serializer->serialize($keyring);
        $this->assertJson($reserialized);
        
        // Verify data integrity after round-trip
        $redecodedData = json_decode($reserialized, true);
        $this->assertSame('complex-id', $redecodedData['uniqueId']);
        $this->assertCount(2, $redecodedData['vault']);
        $this->assertCount(3, $redecodedData['macs']);
    }

    #[Test]
    public function it_preserves_empty_vaults(): void
    {
        $jsonData = json_encode([
            'uniqueId' => 'empty-vault-id',
            'vault' => [],
            'macs' => []
        ]);

        $keyring = $this->serializer->deserialize($jsonData);
        $reserialized = $this->serializer->serialize($keyring);
        
        $decoded = json_decode($reserialized, true);
        $this->assertIsArray($decoded['vault']);
        $this->assertEmpty($decoded['vault']);
    }

    #[Test]
    public function it_handles_nested_vault_structures(): void
    {
        $nestedData = [
            'uniqueId' => 'nested-id',
            'vault' => [
                'vault1' => [
                    'nested' => [
                        'deep' => 'value'
                    ]
                ]
            ],
            'macs' => ['mac']
        ];

        $jsonData = json_encode($nestedData, JSON_PRETTY_PRINT);
        
        $keyring = $this->serializer->deserialize($jsonData);
        $reserialized = $this->serializer->serialize($keyring);
        
        $decoded = json_decode($reserialized, true);
        $this->assertArrayHasKey('vault1', $decoded['vault']);
    }
}
