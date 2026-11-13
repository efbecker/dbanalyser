<?php
declare(strict_types=1);

namespace App\Core;

use PDO;

/** Conexão com o SQLite interno + runner de migrations. */
final class Database
{
    private static ?PDO $pdo = null;

    public static function pdo(): PDO
    {
        if (self::$pdo === null) {
            $path = Config::dataDir() . '/app.sqlite';
            self::$pdo = new PDO('sqlite:' . $path, null, null, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);
            self::$pdo->exec('PRAGMA foreign_keys = ON');
            self::$pdo->exec('PRAGMA journal_mode = WAL');
            self::$pdo->exec('PRAGMA busy_timeout = 5000');
            self::$pdo->exec('PRAGMA synchronous = NORMAL');
        }
        return self::$pdo;
    }

    public static function all(string $sql, array $params = []): array
    {
        $st = self::pdo()->prepare($sql);
        $st->execute($params);
        return $st->fetchAll();
    }

    public static function one(string $sql, array $params = []): ?array
    {
        $st = self::pdo()->prepare($sql);
        $st->execute($params);
        $row = $st->fetch();
        return $row === false ? null : $row;
    }

    public static function value(string $sql, array $params = []): mixed
    {
        $st = self::pdo()->prepare($sql);
        $st->execute($params);
        $v = $st->fetchColumn();
        return $v === false ? null : $v;
    }

    public static function exec(string $sql, array $params = []): int
    {
        $st = self::pdo()->prepare($sql);
        $st->execute($params);
        return $st->rowCount();
    }

    public static function insert(string $table, array $data): int
    {
        $cols = array_keys($data);
        $sql = sprintf(
            'INSERT INTO %s (%s) VALUES (%s)',
            $table,
            implode(',', $cols),
            implode(',', array_map(fn($c) => ':' . $c, $cols))
        );
        self::exec($sql, $data);
        return (int) self::pdo()->lastInsertId();
    }

    public static function update(string $table, array $data, string $where, array $params = []): int
    {
        $set = implode(',', array_map(fn($c) => "$c = :$c", array_keys($data)));
        return self::exec("UPDATE $table SET $set WHERE $where", array_merge($data, $params));
    }

    /** Aplica database/migrations/*.sql ainda não aplicadas. Retorna as versões aplicadas. */
    public static function migrate(): array
    {
        $pdo = self::pdo();
        $pdo->exec('CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime(\'now\')))');
        $done = array_column(self::all('SELECT version FROM schema_migrations'), 'version');
        $applied = [];
        foreach (glob(APP_ROOT . '/database/migrations/*.sql') ?: [] as $file) {
            $version = basename($file, '.sql');
            if (in_array($version, $done, true)) {
                continue;
            }
            $pdo->beginTransaction();
            try {
                $pdo->exec((string) file_get_contents($file));
                self::exec('INSERT INTO schema_migrations(version) VALUES (?)', [$version]);
                $pdo->commit();
                $applied[] = $version;
            } catch (\Throwable $e) {
                $pdo->rollBack();
                throw new \RuntimeException("Falha na migration $version: " . $e->getMessage(), 0, $e);
            }
        }
        return $applied;
    }
}
