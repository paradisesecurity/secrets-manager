<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Storage\Env;

use ParadiseSecurity\Component\SecretsManager\Exception\EnvFileException;
use Symfony\Component\Dotenv\Dotenv;

use function strtoupper;

use const PHP_EOL;

/**
 * Manages reading and writing .env files.
 * Handles parsing, merging, and persisting environment variables.
 */
final class EnvFileManager
{
    private Dotenv $dotenv;

    public function __construct()
    {
        $this->dotenv = new Dotenv();
    }

    /**
     * Loads environment variables from a file path.
     */
    public function load(string $filePath): void
    {
        if (!file_exists($filePath)) {
            throw new EnvFileException("Environment file not found: {$filePath}");
        }

        try {
            $this->dotenv->load($filePath);
        } catch (\Exception $exception) {
            throw new EnvFileException(
                "Failed to load environment file: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Parses environment file content into an associative array.
     */
    public function parse(string $content): array
    {
        try {
            return $this->dotenv->parse($content);
        } catch (\Exception $exception) {
            throw new EnvFileException(
                "Failed to parse environment file content: {$exception->getMessage()}",
                previous: $exception
            );
        }
    }

    /**
     * Retrieves a value from loaded environment variables.
     */
    public function get(string $name): ?string
    {
        $name = $this->normalizeKey($name);
        return $_ENV[$name] ?? null;
    }

    /**
     * Checks if an environment variable exists.
     */
    public function has(string $name): bool
    {
        $name = $this->normalizeKey($name);
        return isset($_ENV[$name]);
    }

    /**
     * Merges new variables with existing environment data and formats for writing.
     */
    public function merge(array $existing, string $name, string $value): string
    {
        $name = $this->normalizeKey($name);
        $existing[$name] = $value;

        return $this->format($existing);
    }

    /**
     * Formats environment variables into .env file format.
     */
    public function format(array $variables): string
    {
        $lines = [];
        
        foreach ($variables as $key => $value) {
            $key = $this->normalizeKey($key);
            $escapedValue = $this->escapeValue($value);
            $lines[] = "{$key}={$escapedValue}";
        }

        return implode(PHP_EOL, $lines) . PHP_EOL;
    }

    /**
     * Normalizes environment variable keys to uppercase.
     */
    private function normalizeKey(string $name): string
    {
        return strtoupper($name);
    }

    /**
     * Escapes values that need quoting in .env files.
     */
    private function escapeValue(string $value): string
    {
        // Quote values that contain special characters
        if ($this->needsQuoting($value)) {
            return "'{$value}'";
        }

        return $value;
    }

    /**
     * Determines if a value needs to be quoted.
     */
    private function needsQuoting(string $value): bool
    {
        // Quote if contains spaces, special chars, or starts with special chars
        return (
            str_contains($value, ' ') ||
            str_contains($value, '#') ||
            str_contains($value, '=') ||
            str_contains($value, '{') ||
            str_contains($value, '}') ||
            str_contains($value, '"')
        );
    }
}
