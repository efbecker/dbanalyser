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
        'sqlserver'  => ['label' => 'SQL Server', 'port' => 1433],
        'oracle'     => ['label' => 'Oracle',     'port' => 1521],
    ];

    /** Bancos de sistema do SQL Server que nunca são oferecidos para análise. */
    public const MSSQL_SYSTEM_DBS = ['master', 'model', 'msdb', 'tempdb', 'distribution', 'SSISDB', 'rdsadmin'];

    /** Serviços Oracle tentados quando o usuário não informa o service name. */
    public const ORACLE_SERVICES = ['FREEPDB1', 'ORCLPDB1', 'XEPDB1', 'ORCLPDB', 'ORCL', 'FREE', 'XE'];

    /** @param array{engine:string,host:string,port:int,username:string,password:?string,ssl:string} $c */
    public static function connect(array $c, ?string $database = null): PDO|OracleConnection
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

        if ($engine === 'sqlserver') {
            return self::connectMssql($c, $host, $port, $database, $timeoutMs, $opts);
        }
        if ($engine === 'oracle') {
            // No Oracle o "banco" escolhido na tela é o schema (owner); a conexão usa o service name.
            return new OracleConnection([
                'host' => $host, 'port' => $port, 'service' => $c['service'] ?? ($database ?: 'FREEPDB1'),
                'user' => $c['username'], 'password' => $c['password'] ?? '', 'timeout_ms' => $timeoutMs, 'ssl' => $c['ssl'],
            ]);
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

    /**
     * SQL Server via pdo_dblib (FreeTDS, pacote php8.4-sybase). O FreeTDS lê TLS e versão do protocolo
     * do freetds.conf, então geramos um arquivo por servidor (sem segredos) e apontamos FREETDSCONF para ele.
     */
    private static function connectMssql(array $c, string $host, int $port, ?string $database, int $timeoutMs, array $opts): PDO
    {
        if (!extension_loaded('pdo_dblib')) {
            throw new \RuntimeException('could not find driver (pdo_dblib)');
        }
        $enc = match ($c['ssl']) {
            'disable' => 'off', 'require', 'verify-ca', 'verify-full' => 'require', default => 'request',
        };
        $alias = 'dboraculo_' . substr(hash('sha256', "$host|$port|$enc|{$c['ssl']}"), 0, 16);
        $conf = "[global]\n\ttds version = 7.4\n\tclient charset = UTF-8\n\ttext size = 1048576\n"
            . "[$alias]\n\thost = " . trim($host, '[]') . "\n\tport = $port\n\tencryption = $enc\n"
            . ($c['ssl'] === 'verify-full' && is_file('/etc/ssl/certs/ca-certificates.crt') ? "\tca file = /etc/ssl/certs/ca-certificates.crt\n\tcheck certificate hostname = yes\n" : '');
        $file = rtrim(sys_get_temp_dir(), '/') . "/$alias.conf";
        if (!is_file($file) || file_get_contents($file) !== $conf) {
            file_put_contents($file, $conf, LOCK_EX);
            @chmod($file, 0600);
        }
        putenv("FREETDSCONF=$file");
        $attr = fn(string $n) => defined("PDO::DBLIB_ATTR_$n") ? constant("PDO::DBLIB_ATTR_$n") : null;
        if ($k = $attr('CONNECTION_TIMEOUT')) {
            $opts[$k] = 8;
        }
        if ($k = $attr('QUERY_TIMEOUT')) {
            $opts[$k] = max(1, intdiv($timeoutMs, 1000));
        }
        $opts[PDO::ATTR_TIMEOUT] = max(1, intdiv($timeoutMs, 1000));
        $dsn = "dblib:host=$alias;charset=UTF-8;appname=db-oraculo-analyzer" . ($database ? ';dbname=' . $database : '');
        $pdo = new PDO($dsn, $c['username'], $c['password'] ?? '', $opts);
        // SQL Server não tem sessão somente leitura: o coletor só envia SELECT/WITH (MssqlCollector::q),
        // lê sem bloquear a produção e desiste rápido de locks.
        $pdo->exec('SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED; SET LOCK_TIMEOUT 3000; SET DEADLOCK_PRIORITY LOW; SET NOCOUNT ON; SET ANSI_WARNINGS ON; SET ANSI_NULLS ON; SET QUOTED_IDENTIFIER ON; SET CONCAT_NULL_YIELDS_NULL ON; SET ANSI_PADDING ON; SET ARITHABORT ON');
        return $pdo;
    }

    /**
     * Conexão inicial (para listar bancos). No PostgreSQL o pg_hba.conf costuma liberar o usuário
     * apenas em bancos específicos (ex.: "host zabbix zabbix ..."), então tentamos em ordem:
     * banco informado, postgres, banco com o nome do usuário e template1.
     * @return array{0: PDO, 1: ?string} conexão e banco efetivamente usado
     */
    public static function connectAny(array $c, ?string $preferred = null): array
    {
        if ($c['engine'] === 'oracle') {
            // Banco inicial = service name. Sem ele, tenta os nomes mais comuns (PDB padrão de cada edição).
            $services = $preferred ? [$preferred] : self::ORACLE_SERVICES;
            $first = null;
            foreach ($services as $svc) {
                try {
                    return [self::connect($c + ['service' => $svc]), $svc];
                } catch (\PDOException $e) {
                    $first ??= $e;
                    if (!preg_match('/ORA-12514|DPY-6001|DPY-6003|not registered|does not currently know of service/i', $e->getMessage())) {
                        throw $e;
                    }
                }
            }
            throw new \PDOException('Nenhum service name padrão respondeu (' . implode(', ', $services) . '). Informe o service name em "Banco inicial". ' . $first?->getMessage());
        }
        if ($c['engine'] !== 'postgresql') {
            return [self::connect($c, $preferred ?: null), $preferred ?: null];
        }
        $candidates = array_values(array_unique(array_filter([$preferred, 'postgres', $c['username'], 'template1'])));
        $first = null;
        foreach ($candidates as $db) {
            try {
                return [self::connect($c, $db), $db];
            } catch (\PDOException $e) {
                $first ??= $e;
                $m = $e->getMessage();
                // Só vale tentar outro banco quando o erro é específico do banco (pg_hba ou banco inexistente)
                if (!str_contains($m, 'pg_hba.conf') && !preg_match('/database "[^"]+" does not exist|banco de dados "[^"]+" n[ãa]o existe/u', $m)) {
                    throw $e;
                }
            }
        }
        throw $first;
    }

    public static function listDatabases(PDO|OracleConnection $pdo, string $engine): array
    {
        if ($engine === 'sqlserver') {
            $sys = "'" . implode("','", self::MSSQL_SYSTEM_DBS) . "'";
            $rows = $pdo->query("SELECT d.name, CAST(COALESCE((SELECT SUM(CAST(mf.size AS bigint)) FROM sys.master_files mf WHERE mf.database_id = d.database_id), 0) * 8192 AS bigint) AS size
                                   FROM sys.databases d
                                  WHERE d.database_id > 4 AND d.name NOT IN ($sys) AND d.state = 0 AND d.is_distributor = 0
                                    AND HAS_DBACCESS(d.name) = 1 ORDER BY d.name")->fetchAll();
            return $rows;
        }
        if ($engine === 'oracle') {
            // "Bancos" no Oracle = schemas com tabelas, excluindo usuários mantidos pela Oracle (SYS, SYSTEM, XDB, MDSYS…)
            try {
                return $pdo->query("SELECT u.username AS name, NVL((SELECT SUM(s.bytes) FROM dba_segments s WHERE s.owner = u.username), 0) AS \"SIZE\"
                                      FROM dba_users u
                                     WHERE u.oracle_maintained = 'N'
                                       AND EXISTS (SELECT 1 FROM dba_tables t WHERE t.owner = u.username)
                                     ORDER BY u.username")->fetchAll();
            } catch (\PDOException) {
                // Sem SELECT_CATALOG_ROLE: só os schemas visíveis ao usuário, sem tamanho
                return $pdo->query("SELECT u.username AS name, 0 AS \"SIZE\" FROM all_users u
                                     WHERE u.oracle_maintained = 'N' AND EXISTS (SELECT 1 FROM all_tables t WHERE t.owner = u.username)
                                     ORDER BY u.username")->fetchAll();
            }
        }
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

    public static function collector(PDO|OracleConnection $pdo, string $engine, string $database): Collector
    {
        return match ($engine) {
            'postgresql' => new PostgresCollector($pdo, $database),
            'sqlserver'  => new MssqlCollector($pdo, $database),
            'oracle'     => new OracleCollector($pdo, $database),
            default      => new MysqlCollector($pdo, $database, $engine),
        };
    }
}
