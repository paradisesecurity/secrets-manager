<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Trait;

use function array_key_exists;
use function in_array;
use function is_null;
use function lcfirst;
use function preg_replace_callback;
use function property_exists;
use function strtoupper;

trait ConfigurationTrait
{
    protected array $options = [];

    public function hasOption(string $key): bool
    {
        return array_key_exists($key, $this->options);
    }

    public function getOption(string $key): mixed
    {
        if ($this->hasOption($key)) {
            return $this->options[$key];
        }

        return null;
    }

    public function getOptions(): array
    {
        return $this->options;
    }

    public function addOption(string $key, mixed $value): self
    {
        $this->processConfiguration($key, $value);

        return $this;
    }

    public function addOptions(array $options): self
    {
        foreach ($options as $key => $value) {
            if (is_string($key)) {
                $this->processConfiguration($key, $value);
            }
        }

        return $this;
    }

    public function getConfig(string $key): mixed
    {
        if (in_array($key, $this->default, true)) {
            $variableName = $this->getVariableName($key);
            if (property_exists($this, $variableName)) {
                return $this->$variableName;
            }
        }
        return $this->getOption($key);
    }

    public function getConfiguration(): array
    {
        $options = $this->options;

        foreach ($this->default as $key) {
            $option = $this->getConfig($key);
            if (!is_null($option)) {
                $options[$key] = $option;
            }
        }

        return $options;
    }

    protected function getVariableName(string $key): string
    {
        return lcfirst(preg_replace_callback('/(^|_|\.)+(.)/', fn ($match) => ('.' === $match[1] ? '_' : '').strtoupper($match[2]), $key));
    }

    protected function processConfiguration(string $key, mixed $value): void
    {
        if (in_array($key, $this->default, true)) {
            $variableName = $this->getVariableName($key);
            if (property_exists($this, $variableName)) {
                $this->$variableName = $value;
                return;
            }
        }
        $this->options[$key] = $value;
    }
}
