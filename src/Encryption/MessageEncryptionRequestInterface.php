<?php

declare(strict_types=1);

namespace ParadiseSecurity\Component\SecretsManager\Encryption;

use ParagonIE\HiddenString\HiddenString;

interface MessageEncryptionRequestInterface
{
    public function getMessage(): HiddenString;
}
