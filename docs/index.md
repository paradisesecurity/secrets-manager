# Secrets Manager

Store private information in a secret vault protected by an encrypted key ring. The key ring is protected by a master encryption key that can be accessed through an environment variable or stored in a file.

It is incredibly important that you keep your master key in a secure location on the server. When saving the key ring, a checksum is also created and will be verified before you can access the key ring. A master signature key pair is also created that will be used to verify the key ring.

Once you have access to the key ring, you can begin storing secrets. The key ring creates a data key when storing a secret. The data key is stored encrypted alongside the secret. When accessing a secret, the data key is decrypted which will then decrypt the secret.

## Installation

```bash
composer require paradisesecurity/secrets-manager
```

## Basic Usage

Secrets Manager allows you to use any encryption method you wish as well as store the key ring and your secrets in any storage medium. Secrets Manager provides default adapters, but you can create your own. We'll use the default adapters in our example.

It's advisable that you use the console command to create your master keys.

```bash
php ./vendor/bin/secrets-manager setup
```

### Best Security Practices

The key ring and the checksum should not be stored on the same server. The checksum does not prevent an attacker from gaining access to the key ring or manipulating it, since decrypting the key ring with the master keys is all that is required. However, the app tests the key ring against the checksum and if it does not match, it will not load it. You will know if the key ring has been tampered with.

### TODO

Add the ability for the installer to store data outside the local server.