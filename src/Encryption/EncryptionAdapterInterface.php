<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption;

use ParagonIE\HiddenString\HiddenString;

interface EncryptionAdapterInterface
{
    public function getRequiredEncryptionKeyType(): string;

    public function checksum(EncryptionRequestInterface $request): string;

    public function seal(EncryptionRequestInterface $request): string|int;

    public function sign(EncryptionRequestInterface $request): string;

    public function signAndEncrypt(EncryptionRequestInterface $request): string;

    public function unseal(EncryptionRequestInterface $request): HiddenString|bool;

    public function verify(EncryptionRequestInterface $request): bool;

    public function verifyAndDecrypt(EncryptionRequestInterface $request): HiddenString;

    public function decrypt(EncryptionRequestInterface $request): HiddenString|bool;

    public function encrypt(EncryptionRequestInterface $request): string|int;

    public function authenticate(EncryptionRequestInterface $request): string;
}
