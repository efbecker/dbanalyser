<?php
declare(strict_types=1);

namespace App\Analyzer;

use App\Core\Config;
use PDO;

/**
 * Abre conexões PDO com o banco alvo SEMPRE em modo somente leitura (Safe Mode).
 */
final class Connector
{
    public const ENGINES = [
        'postgresql' => ['label' => 'PostgreSQL', 'port' => 5432],
        'mysql'      => ['label' => 'MySQL',      'port' => 3306],
        'mariadb'    => ['label' => 'MariaDB',    'port' => 3306],
    ];

    /** @param array{engine:string,host:string,port:int,username:string,password:?string,ssl:string} $c */
    public static function connect(array $c, ?string $database = null): PDO
    {
        $engine = $c['engine'];
        if (!isset(self::ENGINES[$engine])) {
            throw new \InvalidArgumentException('Motor não suportado: ' . $engine);
        }
        $host = $c['host'];
        if (!preg_match('/^[A-Za-z0-9.\-:_\[\]]+$/', $host)) {
            throw new \InvalidArgumentException('Host inválido');
        }
        $port = (int) $c['port'];
        $timeoutMs = (int) Config::get('analyzer_statement_timeout_ms', 15000);
        $opts = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_TIMEOUT            => 8,
        ];

        if ($engine === 'postgresql') {
            $ssl = in_array($c['ssl'], ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full'], true) ? $c['ssl'] : 'prefer';
            $db = $database ?: 'postgres';
            $dsn = sprintf("pgsql:host=%s;port=%d;dbname=%s;sslmode=%s;connect_timeout=8;application_name='db-oraculo-analyzer'", $host, $port, $db, $ssl);
            $pdo = new PDO($dsn, $c['username'], $c['password'] ?? '', $opts);
            $pdo->exec('SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY');
            $pdo->exec('SET statement_timeout = ' . $timeoutMs);
            $pdo->exec("SET lock_timeout = '3s'");
            return $pdo;
        }

        $dsn = sprintf('mysql:host=%s;port=%d;charset=utf8mb4', $host, $port) . ($database ? ';dbname=' . $database : '');
        if (in_array($c['ssl'], ['require', 'verify-ca', 'verify-full'], true)) {
            $opts[PDO::MYSQL_ATTR_SSL_CA] = is_file('/etc/ssl/certs/ca-certificates.crt') ? '/etc/ssl/certs/ca-certificates.crt' : '';
            $opts[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = $c['ssl'] === 'verify-full';
        }
        $pdo = new PDO($dsn, $c['username'], $c['password'] ?? '', $opts);
        try {
            $pdo->exec('SET SESSION TRANSACTION READ ONLY');
        } catch (\Throwable) {
        }
        // MySQL usa max_execution_time (ms); MariaDB usa max_statement_time (s)
        try {
            $pdo->exec('SET SESSION max_execution_time = ' . $timeoutMs);
        } catch (\Throwable) {
            try {
                $pdo->exec('SET SESSION max_statement_time = ' . ($timeoutMs / 1000));
            } catch (\Throwable) {
            }
        }
        return $pdo;
    }

    public static function listDatabases(PDO $pdo, string $engine): array
    {
        if ($engine === 'postgresql') {
            $sql = "SELECT datname AS name, pg_database_size(datname) AS size FROM pg_database
                    WHERE datallowconn AND NOT datistemplate AND has_database_privilege(datname, 'CONNECT') ORDER BY datname";
        } else {
            $sql = "SELECT s.SCHEMA_NAME AS name, COALESCE(SUM(t.DATA_LENGTH + t.INDEX_LENGTH), 0) AS size
                    FROM information_schema.SCHEMATA s LEFT JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = s.SCHEMA_NAME
                    WHERE s.SCHEMA_NAME NOT IN ('information_schema','performance_schema','mysql','sys')
                    GROUP BY s.SCHEMA_NAME ORDER BY s.SCHEMA_NAME";
        }
        return $pdo->query($sql)->fetchAll();
    }

    public static function collector(PDO $pdo, string $engine, string $database): Collector
    {
        return $engine === 'postgresql'
            ? new PostgresCollector($pdo, $database)
            : new MysqlCollector($pdo, $database, $engine);
    }
}
