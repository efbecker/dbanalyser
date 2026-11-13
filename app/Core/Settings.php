<?php
declare(strict_types=1);

namespace App\Core;

final class Settings
{
    private static ?array $cache = null;

    public static function get(string $key, ?string $default = null): ?string
    {
        if (self::$cache === null) {
            try {
                self::$cache = array_column(Database::all('SELECT key, value FROM settings'), 'value', 'key');
            } catch (\Throwable) {
                self::$cache = [];
            }
        }
        return self::$cache[$key] ?? $default;
    }

    public static function set(string $key, ?string $value): void
    {
        Database::exec(
            "INSERT INTO settings(key, value, updated_at) VALUES (?, ?, datetime('now'))
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            [$key, $value]
        );
        self::$cache = null;
    }
}
