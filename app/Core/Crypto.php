<?php
declare(strict_types=1);

namespace App\Core;

/** Cifra segredos (API keys, senhas de conexão) com libsodium secretbox. */
final class Crypto
{
    private static function key(): string
    {
        $b64 = Config::get('app_key');
        $key = $b64 ? base64_decode((string) $b64, true) : false;
        if ($key === false || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new \RuntimeException('app_key ausente ou inválida. Rode: php bin/console key:generate');
        }
        return $key;
    }

    public static function encrypt(?string $plain): ?string
    {
        if ($plain === null || $plain === '') {
            return null;
        }
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return 'v1:' . base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, self::key()));
    }

    public static function decrypt(?string $cipher): ?string
    {
        if ($cipher === null || $cipher === '' || !str_starts_with($cipher, 'v1:')) {
            return null;
        }
        $raw = base64_decode(substr($cipher, 3), true);
        if ($raw === false || strlen($raw) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            return null;
        }
        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $nonce, self::key());
        return $plain === false ? null : $plain;
    }

    public static function generateKey(): string
    {
        return base64_encode(random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES));
    }
}
