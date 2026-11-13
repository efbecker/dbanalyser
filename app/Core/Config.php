<?php
declare(strict_types=1);

namespace App\Core;

/**
 * Configuração: /etc/db-analyzer/config.php (produção, gerado pelo install.sh)
 * ou APP_ROOT/storage/config.php (desenvolvimento). Variável DBA_CONFIG sobrescreve.
 */
final class Config
{
    private static array $data = [];

    public static function load(): void
    {
        $defaults = [
            'debug'          => false,
            'timezone'       => 'America/Sao_Paulo',
            'base_path'      => '',
            'data_dir'       => APP_ROOT . '/storage',
            'app_key'        => null,             // base64 de 32 bytes (libsodium)
            'session_name'   => 'DBORACULO',
            'session_ttl'    => 7200,             // segundos de inatividade
            'login_max_attempts' => 5,            // por usuário+IP na janela
            'login_window_min'   => 15,
            'analyzer_statement_timeout_ms' => 15000,
            'ai_timeout'     => 120,
            'trusted_proxy'  => null,
        ];
        $file = getenv('DBA_CONFIG') ?: (is_file('/etc/db-analyzer/config.php')
            ? '/etc/db-analyzer/config.php'
            : APP_ROOT . '/storage/config.php');
        $cfg = is_file($file) ? require $file : [];
        self::$data = array_replace($defaults, is_array($cfg) ? $cfg : []);
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        return self::$data[$key] ?? $default;
    }

    public static function dataDir(): string
    {
        return rtrim((string) self::get('data_dir'), '/');
    }
}
