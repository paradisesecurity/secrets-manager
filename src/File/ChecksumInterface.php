<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\File;

interface ChecksumInterface
{
    public const CHECKSUM_LENGTH_BYTES = 88;

    public const SIGNATURE_LENGTH_BYTES = 88;
}
