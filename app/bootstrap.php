<?php
declare(strict_types=1);

/**
 * Bootstrap: configuração, autoload (PSR-4 simples, sem Composer) e tratamento de erros.
 */

define('APP_ROOT', dirname(__DIR__));
define('APP_VERSION', '0.1.0');

spl_autoload_register(static function (string $class): void {
    $prefix = 'App\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $file = __DIR__ . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});

require __DIR__ . '/helpers.php';

App\Core\Config::load();

date_default_timezone_set(App\Core\Config::get('timezone', 'America/Sao_Paulo'));
mb_internal_encoding('UTF-8');

if (App\Core\Config::get('debug', false)) {
    ini_set('display_errors', '1');
    error_reporting(E_ALL);
} else {
    ini_set('display_errors', '0');
}
