<?php
declare(strict_types=1);

namespace App\Analyzer;

use PDO;

/** Coletor para MySQL 8+ e MariaDB 10.6+. */
final class MysqlCollector extends Collector
{
    private array $vars = [];
    private array $status = [];

    public function __construct(PDO $pdo, string $database, private string $engine)
    {
        parent::__construct($pdo, $database);
    }

    private function qid(string $s): string
    {
        return self::qi($s, '`');
    }

    private function loadVars(): void
    {
        if (!$this->vars) {
            foreach ($this->q('SHOW GLOBAL VARIABLES') as $r) {
                $this->vars[$r['Variable_name']] = $r['Value'];
            }
            foreach ($this->q('SHOW GLOBAL STATUS') as $r) {
                $this->status[$r['Variable_name']] = $r['Value'];
            }
        }
    }

    public function connect(): array
    {
        $this->loadVars();
        $version = $this->vars['version'] ?? '';
        $isMaria = stripos($version, 'mariadb') !== false;
        $size = (int) ($this->q('SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) AS s FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?', [$this->database])[0]['s'] ?? 0);
        $this->log('✔ Handshake OK — ' . ($isMaria ? 'MariaDB ' : 'MySQL ') . $version . ' (' . ($this->vars['version_comment'] ?? '') . ')');
        $this->log('✔ Sessão READ ONLY com limite de tempo por instrução');
        if ($this->engine === 'mysql' && $isMaria) {
            $this->log('ℹ Servidor é MariaDB — regras ajustadas automaticamente');
        }
        $this->log('• Banco ' . $this->database . ' — ' . human_bytes($size));
        return $this->result([
            'version' => $version, 'flavor' => $isMaria ? 'mariadb' : 'mysql', 'db_size' => $size,
            'uptime_s' => (int) ($this->status['Uptime'] ?? 0), 'read_only' => ($this->vars['read_only'] ?? 'OFF') === 'ON',
        ], ['db_size' => $size]);
    }

    public function schemas(): array
    {
        $tables = $this->q("SELECT TABLE_NAME AS name, ENGINE AS engine, TABLE_ROWS AS `rows`, DATA_LENGTH AS data_bytes, INDEX_LENGTH AS index_bytes,
                                   DATA_FREE AS data_free, TABLE_COLLATION AS collation, ROW_FORMAT AS row_format
                              FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'
                             ORDER BY DATA_LENGTH + INDEX_LENGTH DESC", [$this->database]);
        $pks = array_column($this->q("SELECT TABLE_NAME FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA = ? AND CONSTRAINT_TYPE = 'PRIMARY KEY'", [$this->database]), 'TABLE_NAME');
        $pks = array_flip($pks);
        $fks = $this->q("SELECT CONSTRAINT_NAME AS name, TABLE_NAME AS table_name, GROUP_CONCAT(COLUMN_NAME ORDER BY ORDINAL_POSITION) AS columns,
                                REFERENCED_TABLE_SCHEMA AS ref_schema, REFERENCED_TABLE_NAME AS ref_table
                           FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? AND REFERENCED_TABLE_NAME IS NOT NULL
                          GROUP BY CONSTRAINT_NAME, TABLE_NAME, REFERENCED_TABLE_SCHEMA, REFERENCED_TABLE_NAME", [$this->database]);
        $linked = [];
        foreach ($fks as $f) {
            $linked[$f['table_name']] = $linked[$f['ref_table']] = true;
        }
        $this->log('• ' . count($tables) . ' tabelas mapeadas, ' . count($fks) . ' chaves estrangeiras');

        $out = [];
        $noPk = 0;
        foreach ($tables as $t) {
            $qt = $this->qid($this->database) . '.' . $this->qid($t['name']);
            $rows = (int) $t['rows'];
            $data = (int) $t['data_bytes'];
            $free = (int) $t['data_free'];
            $this->log("  ↳ {$t['name']} ({$t['engine']}, ~" . number_format($rows, 0, ',', '.') . ' linhas, ' . human_bytes($data) . ')');
            $hasPk = isset($pks[$t['name']]);
            if (!$hasPk) {
                $noPk++;
                $this->finding($rows > 10000 ? 'high' : 'medium', 'schema', "Tabela sem chave primária: {$t['name']}",
                    'No InnoDB, sem PK o motor cria um clustered index oculto (6 bytes) e a replicação baseada em linha fica lenta.',
                    "-- Avalie a coluna candidata antes de aplicar\nALTER TABLE $qt ADD COLUMN id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST;", $t['name']);
            }
            if ($t['engine'] && strcasecmp($t['engine'], 'InnoDB') !== 0 && strcasecmp($t['engine'], 'Aria') !== 0) {
                $this->finding('high', 'schema', "Tabela {$t['name']} usa engine {$t['engine']}",
                    'MyISAM não é transacional, usa lock de tabela e não é crash-safe.', "ALTER TABLE $qt ENGINE=InnoDB;", $t['name']);
            }
            if ($free > 100 * 1024 * 1024 && $data > 0 && $free / ($data + $free) > 0.2) {
                $pct = round($free * 100 / ($data + $free), 1);
                $this->finding('medium', 'bloat', "Fragmentação de tablespace em {$t['name']} ($pct%)",
                    human_bytes($free) . ' livres não devolvidos ao SO.', "OPTIMIZE TABLE $qt; -- ou pt-online-schema-change/gh-ost em produção", $t['name']);
            }
            if ($t['collation'] && !str_starts_with((string) $t['collation'], 'utf8mb4')) {
                $this->finding('low', 'types', "Collation legada em {$t['name']} ({$t['collation']})",
                    'utf8/latin1 não armazenam todos os caracteres Unicode (ex: emojis) e geram conversões em JOINs.',
                    "ALTER TABLE $qt CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;", $t['name']);
            }
            $out[] = ['schema' => $this->database, 'name' => $t['name'], 'engine' => $t['engine'], 'rows' => $rows, 'data_bytes' => $data,
                'index_bytes' => (int) $t['index_bytes'], 'data_free' => $free, 'has_pk' => $hasPk, 'isolated' => !isset($linked[$t['name']])];
        }

        $smells = $this->tryQ('tipos de dados', "SELECT TABLE_NAME AS table_name, COLUMN_NAME AS col, COLUMN_TYPE AS type FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = ? AND ((DATA_TYPE IN ('float','double') AND COLUMN_NAME REGEXP '(price|preco|valor|amount|total|saldo)')
                OR (COLUMN_NAME REGEXP '(_id|^id)$' AND DATA_TYPE IN ('varchar','char','text'))
                OR (DATA_TYPE IN ('text','longtext','mediumtext') AND COLUMN_KEY <> '' ))
             LIMIT 200", [$this->database]) ?? [];
        foreach ($smells as $s) {
            $this->finding('low', 'types', "Tipo inadequado: {$s['table_name']}.{$s['col']} ({$s['type']})",
                str_contains($s['type'], 'float') || str_contains($s['type'], 'double') ? 'Ponto flutuante para valores monetários causa erros de arredondamento; use DECIMAL.' : 'Identificador/chave em tipo texto: maior e mais lento em índices e JOINs.',
                null, "{$s['table_name']}.{$s['col']}");
        }
        return $this->result(['tables' => $out, 'foreign_keys' => $fks, 'type_smells' => $smells],
            ['tables' => count($out), 'fks' => count($fks), 'no_pk' => $noPk, 'rows' => array_sum(array_column($out, 'rows'))]);
    }

    public function indexes(): array
    {
        $rows = $this->q("SELECT TABLE_NAME AS t, INDEX_NAME AS i, NON_UNIQUE AS nu, SEQ_IN_INDEX AS seq, COLUMN_NAME AS c, SUB_PART AS sub,
                                 CARDINALITY AS card, INDEX_TYPE AS type
                            FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX", [$this->database]);
        $idx = [];
        foreach ($rows as $r) {
            $k = $r['t'] . '.' . $r['i'];
            $idx[$k] ??= ['table' => $r['t'], 'name' => $r['i'], 'unique' => !(int) $r['nu'], 'primary' => $r['i'] === 'PRIMARY', 'type' => $r['type'], 'cols' => [], 'card' => (int) $r['card']];
            $idx[$k]['cols'][] = $r['c'] . ($r['sub'] ? "({$r['sub']})" : '');
        }
        $this->log('• ' . count($idx) . ' índices encontrados');

        // Duplicados e redundantes (prefixo)
        $byTable = [];
        foreach ($idx as $i) {
            $byTable[$i['table']][] = $i;
        }
        $dups = 0;
        foreach ($byTable as $table => $list) {
            foreach ($list as $a) {
                foreach ($list as $b) {
                    if ($a['name'] === $b['name'] || $a['unique'] || $a['type'] !== 'BTREE' || $b['type'] !== 'BTREE') {
                        continue;
                    }
                    $ka = implode(',', $a['cols']);
                    $kb = implode(',', $b['cols']);
                    $isDup = $ka === $kb && strcmp($a['name'], $b['name']) > 0 || ($ka === $kb && $b['unique']);
                    $isPrefix = $ka !== $kb && str_starts_with($kb . ',', $ka . ',');
                    if ($isDup || $isPrefix) {
                        $dups++;
                        $this->finding($isDup ? 'high' : 'medium', 'indexes', ($isDup ? 'Índice duplicado' : 'Índice redundante') . ": $table.{$a['name']} ($ka)",
                            ($isDup ? 'Idêntico a ' : 'Prefixo de ') . "{$b['name']} ($kb). Remova para reduzir custo de escrita e disco.",
                            'ALTER TABLE ' . $this->qid($this->database) . '.' . $this->qid($table) . ' DROP INDEX ' . $this->qid($a['name']) . ';', "$table.{$a['name']}");
                        continue 2;
                    }
                }
            }
        }

        // Nunca utilizados (performance_schema)
        $unused = $this->tryQ('performance_schema (uso de índices)', "SELECT OBJECT_NAME AS t, INDEX_NAME AS i FROM performance_schema.table_io_waits_summary_by_index_usage
              WHERE OBJECT_SCHEMA = ? AND INDEX_NAME IS NOT NULL AND INDEX_NAME <> 'PRIMARY' AND COUNT_STAR = 0", [$this->database]);
        $uptime = (int) ($this->status['Uptime'] ?? 0);
        foreach ($unused ?? [] as $u) {
            $k = $u['t'] . '.' . $u['i'];
            if (isset($idx[$k]) && !$idx[$k]['unique'] && $uptime > 7 * 86400) {
                $this->finding('medium', 'indexes', "Índice nunca utilizado: $k", 'Sem leituras desde o start do servidor (' . round($uptime / 86400) . ' dias). Confirme nas réplicas.',
                    'ALTER TABLE ' . $this->qid($this->database) . '.' . $this->qid($u['t']) . ' DROP INDEX ' . $this->qid($u['i']) . ';', $k);
            }
        }
        if ($unused !== null && $uptime <= 7 * 86400) {
            $this->log('ℹ Uptime < 7 dias: análise de índices não usados é pouco confiável');
        }

        // FKs sem índice cuja coluna inicial coincida
        $fkNoIdx = [];
        foreach ($this->q("SELECT CONSTRAINT_NAME AS fk, TABLE_NAME AS t, GROUP_CONCAT(COLUMN_NAME ORDER BY ORDINAL_POSITION) AS cols
                             FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? AND REFERENCED_TABLE_NAME IS NOT NULL
                            GROUP BY CONSTRAINT_NAME, TABLE_NAME", [$this->database]) as $f) {
            $covered = false;
            foreach ($byTable[$f['t']] ?? [] as $i) {
                if (str_starts_with(implode(',', $i['cols']) . ',', $f['cols'] . ',')) {
                    $covered = true;
                    break;
                }
            }
            if (!$covered) {
                $fkNoIdx[] = $f;
                $this->finding('high', 'relationships', "FK sem índice: {$f['t']} ({$f['cols']})", 'JOINs e DELETE em cascata farão varredura completa.',
                    'CREATE INDEX ' . $this->qid(substr('ix_' . $f['t'] . '_' . str_replace(',', '_', $f['cols']), 0, 64)) . ' ON ' . $this->qid($this->database) . '.' . $this->qid($f['t']) . ' (' . implode(', ', array_map([$this, 'qid'], explode(',', $f['cols']))) . ');', $f['t']);
            }
        }

        $list = array_map(fn($i) => $i + ['def' => ($i['unique'] ? 'UNIQUE ' : '') . "{$i['type']} (" . implode(', ', $i['cols']) . ')'], array_values($idx));
        return $this->result(['indexes' => array_slice($list, 0, 500), 'unused' => count($unused ?? []), 'duplicates' => $dups, 'fk_without_index' => $fkNoIdx],
            ['indexes' => count($idx), 'unused' => count($unused ?? []), 'fk_no_idx' => count($fkNoIdx)]);
    }

    public function queries(): array
    {
        $this->loadVars();
        $top = $this->tryQ('performance_schema (digests)', "SELECT LEFT(DIGEST_TEXT, 2000) AS query, COUNT_STAR AS calls,
                    ROUND(SUM_TIMER_WAIT / 1e9, 1) AS total_ms, ROUND(AVG_TIMER_WAIT / 1e9, 2) AS mean_ms, SUM_ROWS_EXAMINED AS rows_examined,
                    SUM_ROWS_SENT AS rows_sent, SUM_NO_INDEX_USED AS no_index, SUM_CREATED_TMP_DISK_TABLES AS tmp_disk
               FROM performance_schema.events_statements_summary_by_digest WHERE SCHEMA_NAME = ? ORDER BY SUM_TIMER_WAIT DESC LIMIT 15", [$this->database]);
        if ($top !== null) {
            $this->log('✔ performance_schema: ' . count($top) . ' digests mais custosos');
        }
        if (($this->vars['performance_schema'] ?? 'OFF') !== 'ON') {
            $this->finding('medium', 'observability', 'performance_schema desabilitado', 'Sem ele não há histórico de queries nem uso de índices.', "-- my.cnf [mysqld]\nperformance_schema = ON");
        }
        if (($this->vars['slow_query_log'] ?? 'OFF') !== 'ON') {
            $this->finding('low', 'observability', 'slow_query_log desligado', 'Ative para capturar queries acima de long_query_time.',
                "SET GLOBAL slow_query_log = ON;\nSET GLOBAL long_query_time = 1;");
        }
        foreach ($top ?? [] as $t) {
            $exam = (int) $t['rows_examined'];
            $sent = max(1, (int) $t['rows_sent']);
            if ((float) $t['mean_ms'] > 500 || ((int) $t['no_index'] > 0 && $exam / $sent > 1000)) {
                $this->finding('high', 'queries', 'Query custosa (média ' . $t['mean_ms'] . ' ms, ' . $t['calls'] . ' chamadas)',
                    mb_substr($t['query'], 0, 400) . "\nLinhas examinadas/enviadas: " . round($exam / $sent), 'EXPLAIN FORMAT=TREE ' . mb_substr((string) $t['query'], 0, 2000) . ';');
            }
        }
        $trx = $this->tryQ('information_schema.INNODB_TRX', "SELECT trx_mysql_thread_id AS id, trx_state AS state, TIMESTAMPDIFF(SECOND, trx_started, NOW()) AS age_s,
                    trx_rows_locked AS rows_locked, LEFT(trx_query, 300) AS query FROM information_schema.INNODB_TRX ORDER BY trx_started LIMIT 30") ?? [];
        foreach ($trx as $t) {
            if ((int) $t['age_s'] > 60) {
                $this->finding('high', 'locks', "Transação aberta há {$t['age_s']}s (thread {$t['id']})", 'Transações longas seguram locks e crescem o history list (undo).',
                    "KILL {$t['id']}; -- avalie antes");
            }
        }
        $waits = (int) ($this->tryQ('lock waits', 'SELECT COUNT(*) AS c FROM performance_schema.data_lock_waits')[0]['c']
            ?? $this->tryQ('lock waits', 'SELECT COUNT(*) AS c FROM information_schema.INNODB_LOCK_WAITS')[0]['c'] ?? 0);
        $this->log('• ' . count($trx) . ' transações abertas, ' . $waits . ' esperas de lock');
        return $this->result(['top_queries' => $top ?? [], 'activity' => $trx, 'locks_waiting' => $waits], ['queries' => count($top ?? []), 'long_sessions' => count($trx), 'locks' => $waits]);
    }

    public function sizing(): array
    {
        $this->loadVars();
        $names = ['innodb_buffer_pool_size', 'innodb_buffer_pool_instances', 'innodb_log_file_size', 'innodb_redo_log_capacity', 'innodb_log_buffer_size',
            'innodb_flush_log_at_trx_commit', 'innodb_flush_method', 'innodb_io_capacity', 'innodb_io_capacity_max', 'thread_cache_size', 'tmp_table_size',
            'max_heap_table_size', 'max_connections', 'table_open_cache', 'sort_buffer_size', 'join_buffer_size', 'query_cache_type', 'query_cache_size',
            'innodb_file_per_table', 'sync_binlog', 'long_query_time'];
        $settings = [];
        foreach ($names as $n) {
            if (isset($this->vars[$n])) {
                $settings[$n] = ['value' => $this->vars[$n], 'bytes' => is_numeric($this->vars[$n]) ? (int) $this->vars[$n] : null];
                $this->log("  ↳ $n = {$this->vars[$n]}");
            }
        }
        $s = fn($k) => (float) ($this->status[$k] ?? 0);
        $reqs = $s('Innodb_buffer_pool_read_requests');
        $hit = $reqs > 0 ? round(100 - ($s('Innodb_buffer_pool_reads') * 100 / $reqs), 2) : null;
        $tmp = $s('Created_tmp_tables');
        $tmpDiskPct = $tmp > 0 ? round($s('Created_tmp_disk_tables') * 100 / $tmp, 2) : 0;
        $threadMiss = $s('Connections') > 0 ? round($s('Threads_created') * 100 / $s('Connections'), 2) : 0;
        $metrics = [
            'cache_hit_ratio' => $hit, 'tmp_disk_pct' => $tmpDiskPct, 'thread_cache_miss_pct' => $threadMiss,
            'max_used_connections' => (int) $s('Max_used_connections'), 'max_connections' => (int) ($this->vars['max_connections'] ?? 151),
            'connections' => (int) $s('Threads_connected'), 'slow_queries' => (int) $s('Slow_queries'), 'aborted_connects' => (int) $s('Aborted_connects'),
            'uptime_s' => (int) $s('Uptime'), 'bp_pages_free' => (int) $s('Innodb_buffer_pool_pages_free'), 'bp_pages_total' => (int) $s('Innodb_buffer_pool_pages_total'),
        ];
        $this->log('✔ Buffer pool hit: ' . ($hit ?? 'n/d') . "% • tmp em disco: $tmpDiskPct% • conexões máx usadas {$metrics['max_used_connections']}/{$metrics['max_connections']}");
        if ($hit !== null && $hit < 99) {
            $this->finding($hit < 95 ? 'high' : 'medium', 'sizing', "Buffer pool hit ratio baixo ($hit%)", 'Leituras físicas frequentes: avalie aumentar innodb_buffer_pool_size.');
        }
        if ($tmpDiskPct > 25) {
            $this->finding('medium', 'sizing', "Tabelas temporárias em disco: $tmpDiskPct%", 'Aumente tmp_table_size/max_heap_table_size juntos ou revise GROUP BY/ORDER BY com TEXT/BLOB.');
        }
        if ($metrics['max_connections'] > 0 && $metrics['max_used_connections'] / $metrics['max_connections'] > 0.85) {
            $this->finding('high', 'sizing', 'Pico de conexões próximo do limite', "Max_used_connections {$metrics['max_used_connections']} de {$metrics['max_connections']}. Considere pool de conexões (ProxySQL).");
        }
        if ($threadMiss > 10) {
            $this->finding('low', 'sizing', "thread_cache ineficiente ($threadMiss% de miss)", 'Aumente thread_cache_size.', 'SET GLOBAL thread_cache_size = 64;');
        }
        return $this->result(['settings' => $settings, 'stats' => $metrics], ['hit' => $hit, 'conns' => $metrics['connections']]);
    }
}
