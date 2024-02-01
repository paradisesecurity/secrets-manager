<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\File;

use ParadiseSecurity\Component\SecretsManager\Exception\InvalidSignatureOrChecksumException;
use ParadiseSecurity\Component\SecretsManager\Utility\Utility;

final class Checksum implements ChecksumInterface
{
    private string $checksum;

    private string $signature;

    public function __construct(string ...$data)
    {
        if (func_num_args() === 1) {
            $tempData = $data[0];
            $data = [];
            $data[0] = Utility::subString($tempData, 0, ChecksumInterface::CHECKSUM_LENGTH_BYTES);
            $data[1] = Utility::subString($tempData, ChecksumInterface::CHECKSUM_LENGTH_BYTES);
        }

        if (Utility::stringLength($data[0]) !== ChecksumInterface::CHECKSUM_LENGTH_BYTES) {
            throw new InvalidSignatureOrChecksumException();
        }

        if (Utility::stringLength($data[1]) !== ChecksumInterface::SIGNATURE_LENGTH_BYTES) {
            throw new InvalidSignatureOrChecksumException();
        }

        $this->checksum = $data[0];
        $this->signature = $data[1];
    }

    public function getChecksum(): string
    {
        return $this->checksum;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }
}
