<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Adapter\Encryption\Halite;

use ParagonIE\Halite\Contract\StreamInterface;
use ParagonIE\Halite\Stream\MutableFile;
use ParagonIE\Halite\Stream\ReadOnlyFile;

use function is_resource;
use function is_string;

/**
 * Handles conversion of various file types to Halite stream interfaces.
 */
final class HaliteFileHandler
{
    /**
     * Processes input file to Halite-compatible format.
     */
    public function processInputFile(mixed $file): StreamInterface|string
    {
        if ($file instanceof StreamInterface) {
            return $file;
        }

        if (is_string($file)) {
            return $file;
        }

        if (is_resource($file)) {
            return new ReadOnlyFile($file);
        }

        return '';
    }

    /**
     * Processes output file to Halite-compatible format.
     */
    public function processOutputFile(mixed $file): StreamInterface|string
    {
        if ($file instanceof StreamInterface) {
            return $file;
        }

        if (is_string($file)) {
            return $file;
        }

        if (is_resource($file)) {
            return new MutableFile($file);
        }

        return '';
    }

    /**
     * Processes file based on context (input or output).
     */
    public function processFile(mixed $file, string $context): StreamInterface|string
    {
        return match ($context) {
            'input' => $this->processInputFile($file),
            'output' => $this->processOutputFile($file),
            default => '',
        };
    }
}
