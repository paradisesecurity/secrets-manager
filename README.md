# Paradise Security Secrets Manager

A modern, flexible secrets management library for PHP applications with a fluent builder API and multiple storage backends.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-8892BF.svg)](https://php.net/)

## Features

- **Fluent Builder API** - Intuitive, chainable methods for configuration
- **Multiple Storage Backends** - File-based and environment-based key storage
- **Secure Encryption** - Built on Halite/libsodium for authenticated encryption
- **Vault Management** - Organize secrets into isolated vaults
- **Key Rotation** - Generate and manage cryptographic keys with ease
- **File & Message Encryption** - Encrypt data of any size
- **Zero Configuration** - Sensible defaults with full customization

## Installation

```bash
composer require paradisesecurity/secrets-manager
```

## Quick Start

### Basic Usage

```php
use ParadiseSecurity\Component\SecretsManager\Builder\SecretsManagerBuilder;
use ParadiseSecurity\Component\SecretsManager\Key\Key;
use ParagonIE\HiddenString\HiddenString;

// Create authentication key
$authKey = new Key(
    new HiddenString('your-secure-auth-key'),
    'symmetric_authentication_key',
    'halite',
    '5.0.0'
);

// Build the secrets manager
$secretsManager = SecretsManagerBuilder::create()
    ->withAuthKey($authKey)
    ->withPaths('/path/to/project')
    ->withDefaultVault('production')
    ->configureStorage(fn($builder) => 
        $builder
            ->useMasterKeyStorage('env')
            ->withEnvFile('.env')
    )
    ->build();

// Create a vault
$secretsManager->newVault('production');

// Store secrets
$secretsManager->set('database_password', 'super_secret_password');
$secretsManager->set('api_key', 'sk-1234567890abcdef');

// Retrieve secrets
$dbPassword = $secretsManager->get('database_password');
$apiKey = $secretsManager->get('api_key');
```

### Advanced Configuration

```php
$secretsManager = SecretsManagerBuilder::create()
    ->withAuthKey($authKey)
    ->withKeyringName('production-keyring')
    ->withDefaultVault('app-secrets')
    ->withPaths('/var/www/project', '/var/www/project/config/secrets')
    ->configureEncryption(fn($builder) => 
        $builder->useAdapter('halite')
    )
    ->configureStorage(fn($builder) => 
        $builder
            ->useMasterKeyStorage('env')
            ->withEnvFile('.env.production')
    )
    ->configureVault(fn($builder) => 
        $builder->withCache(true, 'secrets-cache')
    )
    ->build();
```

## Architecture

The Secrets Manager is built around a modular architecture with independent builders:

- **EncryptionBuilder** - Configure encryption adapters and key generation
- **StorageBuilder** - Manage filesystem paths and key storage mechanisms  
- **VaultBuilder** - Configure vault adapters with optional caching
- **KeyManagerBuilder** - Coordinate key generation and management
- **SecretsManagerBuilder** - Orchestrate all components into a unified API

Each builder can be used independently or composed together for full functionality.

## Storage Options

### File-Based Storage
Keys are stored as encrypted files in the filesystem:

```php
$builder->configureStorage(fn($b) => 
    $b->useMasterKeyStorage('file')
);
```

### Environment-Based Storage
Keys are stored in `.env` files for easy deployment:

```php
$builder->configureStorage(fn($b) => 
    $b->useMasterKeyStorage('env')
      ->withEnvFile('.env.secrets')
);
```

## Documentation

Comprehensive documentation is available in the [docs](docs/index.md) folder:

- [Installation Guide](docs/installation.md)
- [Architecture Overview](docs/architecture.md)
- [Builder Pattern Guide](docs/builders.md)
- [Storage Systems](docs/storage.md)
- [Encryption Guide](docs/encryption.md)
- [Key Management](docs/keys.md)
- [Vault Management](docs/vaults.md)
- [Examples & Recipes](docs/examples.md)

## Requirements

- PHP 8.1 or higher
- [paragonie/halite](https://github.com/paragonie/halite) ^5.0
- [paragonie/hidden-string](https://github.com/paragonie/hidden-string) ^2.0
- [symfony/options-resolver](https://github.com/symfony/options-resolver) ^6.0|^7.0
- [league/flysystem](https://github.com/thephpleague/flysystem) ^3.0

## Development Status

⚠️ **This library is currently in active development.** APIs may change before the first stable release. Not recommended for production use yet.

## Testing

```bash
composer install
vendor/bin/phpunit
```

## Security

If you discover any security vulnerabilities, please email security@paradisesecurity.work instead of using the issue tracker.

## License

This component is open-sourced software licensed under the [MIT license](LICENSE).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Credits

- Created by [Paradise Security](https://github.com/paradisesecurity)
- Inspired by [Secretary for PHP](https://github.com/secretary/php)
- Built with [Halite](https://github.com/paragonie/halite) cryptography library

---

**Paradise Security** - Building secure, decoupled PHP components with the highest quality code.

![Paradise Security](https://paradisesecurity.work/src/images/logo-splash-banner.png)
