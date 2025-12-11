<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Console\Command;

/**
 * Represents the result of a setup operation.
 */
final class SetupResult
{
    private bool $success = true;
    private array $messages = [];
    private array $errors = [];
    private array $warnings = [];
    private array $data = [];

    public function isSuccess(): bool
    {
        return $this->success;
    }

    public function setSuccess(bool $success): void
    {
        $this->success = $success;
    }

    public function addMessage(string $message): void
    {
        $this->messages[] = $message;
    }

    public function addError(string $error): void
    {
        $this->errors[] = $error;
        $this->success = false;
    }

    public function addWarning(string $warning): void
    {
        $this->warnings[] = $warning;
    }

    public function setData(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
    }

    public function getData(string $key): mixed
    {
        return $this->data[$key] ?? null;
    }

    public function getMessages(): array
    {
        return $this->messages;
    }

    public function getErrors(): array
    {
        return $this->errors;
    }

    public function getWarnings(): array
    {
        return $this->warnings;
    }

    public function getAllData(): array
    {
        return $this->data;
    }

    public function getFormattedOutput(): string
    {
        $output = [];

        if (!empty($this->messages)) {
            $output[] = "Messages:";
            foreach ($this->messages as $message) {
                $output[] = "  {$message}";
            }
        }

        if (!empty($this->warnings)) {
            $output[] = "\nWarnings:";
            foreach ($this->warnings as $warning) {
                $output[] = "  ⚠ {$warning}";
            }
        }

        if (!empty($this->errors)) {
            $output[] = "\nErrors:";
            foreach ($this->errors as $error) {
                $output[] = "  ✗ {$error}";
            }
        }

        $output[] = "\nStatus: " . ($this->success ? '✓ SUCCESS' : '✗ FAILED');

        return implode("\n", $output);
    }
}
