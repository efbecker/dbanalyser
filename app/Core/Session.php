<?php
declare(strict_types=1);

namespace App\Core;

final class Session
{
    public static function start(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
        session_name((string) Config::get('session_name', 'DBORACULO'));
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.gc_maxlifetime', (string) Config::get('session_ttl', 7200));
        $dir = Config::dataDir() . '/sessions';
        if (is_dir($dir) && is_writable($dir)) {
            session_save_path($dir);
        }
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => url('/'),
            'secure'   => $https,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();

        $ttl = (int) Config::get('session_ttl', 7200);
        $now = time();
        if (isset($_SESSION['_last']) && ($now - (int) $_SESSION['_last']) > $ttl) {
            $_SESSION = [];
            session_regenerate_id(true);
        }
        $_SESSION['_last'] = $now;
    }

    public static function flash(string $type, string $msg): void
    {
        $_SESSION['_flash'][] = ['type' => $type, 'msg' => $msg];
    }

    public static function pullFlash(): array
    {
        $f = $_SESSION['_flash'] ?? [];
        unset($_SESSION['_flash']);
        return $f;
    }
}
