<?php
declare(strict_types=1);

namespace App\Core;

final class Http
{
    public static function redirect(string $path): never
    {
        header('Location: ' . (str_starts_with($path, 'http') ? $path : url($path)), true, 302);
        exit;
    }

    public static function json(mixed $data, int $status = 200): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
    }

    /** Corpo JSON da requisição (fetch) ou $_POST. */
    public static function input(): array
    {
        static $data = null;
        if ($data === null) {
            $ct = $_SERVER['CONTENT_TYPE'] ?? '';
            $data = str_contains($ct, 'application/json')
                ? (json_decode((string) file_get_contents('php://input'), true) ?: [])
                : $_POST;
        }
        return $data;
    }

    public static function str(string $key, string $default = ''): string
    {
        $v = self::input()[$key] ?? $default;
        return is_scalar($v) ? trim((string) $v) : $default;
    }
}
