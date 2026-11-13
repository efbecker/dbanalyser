<?php
declare(strict_types=1);

namespace App\Analyzer;

final class PostgresCollector extends Collector
{
    private const SYS = "n.nspname NOT IN ('pg_catalog','information_schema','pg_toast') AND n.nspname NOT LIKE 'pg_temp%' AND n.nspname NOT LIKE 'pg_toast_temp%'";

    public function connect(): array
    {
        $v = $this->q("SELECT version() AS version, current_setting('server_version_num')::int AS num,
                              pg_database_size(current_database()) AS db_size,
                              EXTRACT(EPOCH FROM now() - pg_postmaster_start_time())::bigint AS uptime_s,
                              current_user AS usr, pg_is_in_recovery() AS replica")[0];
        $this->log('✔ Handshake OK — ' . $v['version']);
        $this->log('✔ Sessão em modo READ ONLY, statement_timeout ativo');
        $this->log('• Banco ' . $this->database . ' — ' . human_bytes((int) $v['db_size']) . ($v['replica'] ? ' (réplica)' : ''));
        return $this->result([
            'version' => $v['version'], 'version_num' => (int) $v['num'], 'db_size' => (int) $v['db_size'],
            'uptime_s' => (int) $v['uptime_s'], 'user' => $v['usr'], 'replica' => (bool) $v['replica'],
        ], ['db_size' => (int) $v['db_size']]);
    }

    public function schemas(): array
    {
        $tables = $this->q("
            SELECT n.nspname AS schema, c.relname AS name, c.oid::bigint AS oid,
                   pg_table_size(c.oid) AS data_bytes, pg_indexes_size(c.oid) AS index_bytes,
                   COALESCE(s.n_live_tup, c.reltuples::bigint) AS rows, COALESCE(s.n_dead_tup, 0) AS dead,
                   s.seq_scan, s.idx_scan, s.last_autovacuum, s.last_vacuum, s.last_autoanalyze, s.last_analyze,
                   EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'p') AS has_pk
              FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
             WHERE c.relkind IN ('r','p') AND " . self::SYS . "
             ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 2000");

        $fks = $this->q("
            SELECT con.conname AS name, n.nspname AS schema, c.relname AS table_name, rn.nspname AS ref_schema, rc.relname AS ref_table,
                   ARRAY_TO_STRING(ARRAY(SELECT a.attname FROM unnest(con.conkey) WITH ORDINALITY k(attnum, ord)
                        JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum ORDER BY k.ord), ',') AS columns
              FROM pg_constraint con
              JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
              JOIN pg_class rc ON rc.oid = con.confrelid JOIN pg_namespace rn ON rn.oid = rc.relnamespace
             WHERE con.contype = 'f' AND " . self::SYS);

        $this->log('• ' . count($tables) . ' tabelas mapeadas, ' . count($fks) . ' chaves estrangeiras');
        $linked = [];
        foreach ($fks as $fk) {
            $linked[$fk['schema'] . '.' . $fk['table_name']] = true;
            $linked[$fk['ref_schema'] . '.' . $fk['ref_table']] = true;
        }

        $out = [];
        $noPk = 0;
        foreach ($tables as $t) {
            $fq = $t['schema'] . '.' . $t['name'];
            $qi = self::qi($t['schema']) . '.' . self::qi($t['name']);
            $rows = (int) $t['rows'];
            $dead = (int) $t['dead'];
            $deadPct = ($rows + $dead) > 0 ? round($dead * 100 / ($rows + $dead), 1) : 0.0;
            $this->log("  ↳ $fq (" . number_format($rows, 0, ',', '.') . ' linhas, ' . human_bytes((int) $t['data_bytes']) . ')');
            if (!$t['has_pk']) {
                $noPk++;
                $this->finding($rows > 10000 ? 'high' : 'medium', 'schema', "Tabela sem chave primária: $fq",
                    'Tabelas sem PK impedem replicação lógica eficiente, dificultam UPDATE/DELETE pontuais e escondem duplicidades.',
                    "-- Avalie a coluna candidata antes de aplicar\nALTER TABLE $qi ADD COLUMN id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY;", $fq);
            }
            if ($dead > 10000 && $deadPct >= 20) {
                $this->finding($deadPct >= 40 ? 'high' : 'medium', 'bloat', "Bloat/dead tuples em $fq ($deadPct%)",
                    "$dead tuplas mortas. Último autovacuum: " . ($t['last_autovacuum'] ?: 'nunca') . '. Ajuste autovacuum_vacuum_scale_factor nesta tabela.',
                    "VACUUM (ANALYZE, VERBOSE) $qi;\nALTER TABLE $qi SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);", $fq);
            }
            if ($rows > 50000 && !$t['last_autoanalyze'] && !$t['last_analyze']) {
                $this->finding('medium', 'statistics', "Estatísticas nunca coletadas em $fq", 'O planner pode escolher planos ruins sem estatísticas.', "ANALYZE $qi;", $fq);
            }
            if ($rows > 100000 && (int) $t['seq_scan'] > 10 * max(1, (int) $t['idx_scan'])) {
                $this->finding('medium', 'queries', "Leituras sequenciais predominantes em $fq",
                    "seq_scan={$t['seq_scan']} vs idx_scan=" . (int) $t['idx_scan'] . '. Provável falta de índice para filtros frequentes.', null, $fq);
            }
            $out[] = [
                'schema' => $t['schema'], 'name' => $t['name'], 'rows' => $rows, 'dead' => $dead, 'dead_pct' => $deadPct,
                'data_bytes' => (int) $t['data_bytes'], 'index_bytes' => (int) $t['index_bytes'], 'has_pk' => (bool) $t['has_pk'],
                'seq_scan' => (int) $t['seq_scan'], 'idx_scan' => (int) $t['idx_scan'],
                'last_autovacuum' => $t['last_autovacuum'], 'isolated' => !isset($linked[$fq]),
            ];
        }

        // Tipos de dados suspeitos
        $smells = $this->tryQ('tipos de dados', "
            SELECT n.nspname AS schema, c.relname AS table_name, a.attname AS col, format_type(a.atttypid, a.atttypmod) AS type
              FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped AND " . self::SYS . "
               AND ( (format_type(a.atttypid, a.atttypmod) IN ('real','double precision') AND a.attname ~* '(price|preco|valor|amount|total|saldo|money)')
                  OR (format_type(a.atttypid, a.atttypmod) = 'timestamp without time zone')
                  OR (a.attname ~* '(_id|^id)$' AND format_type(a.atttypid, a.atttypmod) ~* '^(text|character varying)') )
             LIMIT 200") ?? [];
        foreach ($smells as $s) {
            $fq = "{$s['schema']}.{$s['table_name']}.{$s['col']}";
            [$why, $fix] = match (true) {
                str_contains($s['type'], 'timestamp without') => ['timestamp sem fuso horário gera ambiguidade em horário de verão e entre servidores.', 'timestamptz'],
                in_array($s['type'], ['real', 'double precision'], true) => ['Ponto flutuante para valores monetários causa erros de arredondamento.', 'numeric(14,2)'],
                default => ['Identificador armazenado como texto: maior, mais lento em JOINs e índices.', 'bigint'],
            };
            $this->finding('low', 'types', "Tipo inadequado: $fq ({$s['type']})", $why,
                'ALTER TABLE ' . self::qi($s['schema']) . '.' . self::qi($s['table_name']) . ' ALTER COLUMN ' . self::qi($s['col']) . " TYPE $fix; -- requer reescrita da tabela, agende janela", $fq);
        }

        $isolated = array_values(array_filter($out, fn($t) => $t['isolated']));
        if (count($out) > 5 && count($isolated) > 0) {
            $this->log('• ' . count($isolated) . ' tabelas isoladas (sem FK de entrada/saída)');
        }
        return $this->result(['tables' => $out, 'foreign_keys' => $fks, 'type_smells' => $smells],
            ['tables' => count($out), 'fks' => count($fks), 'no_pk' => $noPk, 'rows' => array_sum(array_column($out, 'rows'))]);
    }

    public function indexes(): array
    {
        $idx = $this->q("
            SELECT n.nspname AS schema, t.relname AS table_name, i.relname AS name, ix.indisunique AS is_unique, ix.indisprimary AS is_pk,
                   pg_relation_size(i.oid) AS bytes, COALESCE(s.idx_scan, 0) AS scans, pg_get_indexdef(i.oid) AS def,
                   ix.indrelid::text || ':' || ix.indkey::text || ':' || ix.indclass::text || ':' || COALESCE(pg_get_expr(ix.indexprs, ix.indrelid), '') || ':' || COALESCE(pg_get_expr(ix.indpred, ix.indrelid), '') AS sig,
                   ix.indkey::text AS keys, ix.indrelid::bigint AS relid
              FROM pg_index ix JOIN pg_class i ON i.oid = ix.indexrelid JOIN pg_class t ON t.oid = ix.indrelid
              JOIN pg_namespace n ON n.oid = t.relnamespace LEFT JOIN pg_stat_user_indexes s ON s.indexrelid = ix.indexrelid
             WHERE " . self::SYS . " ORDER BY pg_relation_size(i.oid) DESC");
        $this->log('• ' . count($idx) . ' índices encontrados');

        // Duplicados (assinatura idêntica)
        $bySig = [];
        foreach ($idx as $i) {
            $bySig[$i['sig']][] = $i;
        }
        $dups = 0;
        foreach ($bySig as $group) {
            if (count($group) < 2) {
                continue;
            }
            usort($group, fn($a, $b) => ($b['is_pk'] <=> $a['is_pk']) ?: ($b['is_unique'] <=> $a['is_unique']));
            foreach (array_slice($group, 1) as $d) {
                $dups++;
                $this->finding('high', 'indexes', "Índice duplicado: {$d['schema']}.{$d['name']}",
                    "Idêntico a {$group[0]['name']}. Consome " . human_bytes((int) $d['bytes']) . ' e custo extra em cada escrita.',
                    'DROP INDEX CONCURRENTLY ' . self::qi($d['schema']) . '.' . self::qi($d['name']) . ';', "{$d['schema']}.{$d['name']}");
            }
        }
        // Redundantes: colunas são prefixo de outro índice da mesma tabela (btree, sem expressão)
        $byRel = [];
        foreach ($idx as $i) {
            if (str_ends_with($i['sig'], '::') && !$i['is_unique']) {
                $byRel[$i['relid']][] = $i;
            }
        }
        foreach ($idx as $i) {
            foreach ($byRel[$i['relid']] ?? [] as $cand) {
                if ($cand['name'] === $i['name'] || $cand['keys'] === $i['keys'] || !str_contains($cand['def'], 'btree') || !str_contains($i['def'], 'btree')) {
                    continue;
                }
                if (str_starts_with($i['keys'] . ' ', $cand['keys'] . ' ') && !preg_match('/ WHERE /', $cand['def'] . $i['def'])) {
                    $this->finding('medium', 'indexes', "Índice redundante: {$cand['schema']}.{$cand['name']}",
                        "Suas colunas são prefixo de {$i['name']}, que já atende às mesmas buscas.",
                        'DROP INDEX CONCURRENTLY ' . self::qi($cand['schema']) . '.' . self::qi($cand['name']) . ';', "{$cand['schema']}.{$cand['name']}");
                    $byRel[$i['relid']] = array_filter($byRel[$i['relid']], fn($x) => $x['name'] !== $cand['name']);
                }
            }
        }
        // Nunca utilizados
        $unused = array_values(array_filter($idx, fn($i) => !$i['is_unique'] && !$i['is_pk'] && (int) $i['scans'] === 0));
        foreach (array_slice($unused, 0, 50) as $u) {
            if ((int) $u['bytes'] < 1024 * 1024) {
                continue;
            }
            $this->finding('medium', 'indexes', "Índice nunca utilizado: {$u['schema']}.{$u['name']}",
                'idx_scan = 0 desde o último reset de estatísticas. Ocupa ' . human_bytes((int) $u['bytes']) . '. Confirme também nas réplicas antes de remover.',
                'DROP INDEX CONCURRENTLY ' . self::qi($u['schema']) . '.' . self::qi($u['name']) . ';', "{$u['schema']}.{$u['name']}");
        }

        // FKs sem índice de suporte
        $fkNoIdx = $this->q("
            SELECT n.nspname AS schema, c.relname AS table_name, con.conname AS fk,
                   ARRAY_TO_STRING(ARRAY(SELECT quote_ident(a.attname) FROM unnest(con.conkey) WITH ORDINALITY k(attnum, ord)
                        JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum ORDER BY k.ord), ', ') AS cols,
                   COALESCE(s.n_live_tup, 0) AS rows
              FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
              LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
             WHERE con.contype = 'f' AND " . self::SYS . "
               AND NOT EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = con.conrelid
                     AND (i.indkey::int2[])[0:array_length(con.conkey,1)-1] @> con.conkey
                     AND (i.indkey::int2[])[0:array_length(con.conkey,1)-1] <@ con.conkey)");
        foreach ($fkNoIdx as $f) {
            $fq = "{$f['schema']}.{$f['table_name']}";
            $name = substr('ix_' . $f['table_name'] . '_' . preg_replace('/\W+/', '_', $f['cols']), 0, 63);
            $this->finding((int) $f['rows'] > 10000 ? 'high' : 'medium', 'relationships', "FK sem índice: $fq ({$f['cols']})",
                "A constraint {$f['fk']} não tem índice correspondente: DELETE/UPDATE na tabela pai gera seq scan e locks prolongados.",
                'CREATE INDEX CONCURRENTLY ' . self::qi($name) . ' ON ' . self::qi($f['schema']) . '.' . self::qi($f['table_name']) . " ({$f['cols']});", $fq);
        }

        $list = array_map(fn($i) => [
            'schema' => $i['schema'], 'table' => $i['table_name'], 'name' => $i['name'], 'bytes' => (int) $i['bytes'],
            'scans' => (int) $i['scans'], 'unique' => (bool) $i['is_unique'], 'primary' => (bool) $i['is_pk'], 'def' => $i['def'],
        ], array_slice($idx, 0, 500));
        return $this->result(['indexes' => $list, 'unused' => count($unused), 'duplicates' => $dups, 'fk_without_index' => $fkNoIdx],
            ['indexes' => count($idx), 'unused' => count($unused), 'fk_no_idx' => count($fkNoIdx)]);
    }

    public function queries(): array
    {
        $top = null;
        $ext = $this->tryQ('pg_stat_statements', "SELECT extversion FROM pg_extension WHERE extname = 'pg_stat_statements'");
        if ($ext) {
            $top = $this->tryQ('pg_stat_statements', "
                SELECT LEFT(query, 2000) AS query, calls, round(total_exec_time::numeric, 1) AS total_ms, round(mean_exec_time::numeric, 2) AS mean_ms,
                       rows, shared_blks_hit, shared_blks_read, temp_blks_written
                  FROM pg_stat_statements s JOIN pg_database d ON d.oid = s.dbid
                 WHERE d.datname = current_database() ORDER BY total_exec_time DESC LIMIT 15");
            $this->log('✔ pg_stat_statements ' . $ext[0]['extversion'] . ': ' . count($top ?? []) . ' queries mais custosas');
        } else {
            $this->finding('medium', 'observability', 'pg_stat_statements não habilitado',
                'Sem ele não é possível identificar as queries mais custosas historicamente.',
                "-- postgresql.conf: shared_preload_libraries = 'pg_stat_statements' (requer restart)\nCREATE EXTENSION IF NOT EXISTS pg_stat_statements;");
        }
        foreach ($top ?? [] as $t) {
            if ((float) $t['mean_ms'] > 500) {
                $this->finding('high', 'queries', 'Query lenta (média ' . $t['mean_ms'] . ' ms, ' . $t['calls'] . ' chamadas)',
                    mb_substr(preg_replace('/\s+/', ' ', $t['query']), 0, 400), "EXPLAIN (ANALYZE, BUFFERS) " . mb_substr($t['query'], 0, 2000) . ';');
            }
        }

        $act = $this->tryQ('pg_stat_activity', "
            SELECT pid, usename, state, wait_event_type, wait_event,
                   EXTRACT(EPOCH FROM now() - xact_start)::int AS xact_s, EXTRACT(EPOCH FROM now() - query_start)::int AS query_s,
                   LEFT(query, 500) AS query
              FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()
                AND (state = 'idle in transaction' OR now() - query_start > interval '30 seconds') AND state <> 'idle'
              ORDER BY xact_start NULLS LAST LIMIT 30") ?? [];
        foreach ($act as $a) {
            if ($a['state'] === 'idle in transaction' && (int) $a['xact_s'] > 60) {
                $this->finding('high', 'locks', "Transação ociosa há {$a['xact_s']}s (pid {$a['pid']})",
                    'Sessões "idle in transaction" seguram locks e impedem o VACUUM de limpar tuplas mortas.',
                    "SELECT pg_terminate_backend({$a['pid']}); -- avalie antes\nALTER DATABASE " . self::qi($this->database) . " SET idle_in_transaction_session_timeout = '5min';");
            }
        }
        $locks = $this->tryQ('pg_locks', "SELECT count(*) AS waiting FROM pg_locks WHERE NOT granted")[0]['waiting'] ?? 0;
        if ($locks > 0) {
            $this->finding('medium', 'locks', "$locks locks aguardando no momento da coleta", 'Investigue a cadeia de bloqueio com pg_blocking_pids().',
                "SELECT pid, pg_blocking_pids(pid), wait_event, left(query,120) FROM pg_stat_activity WHERE cardinality(pg_blocking_pids(pid)) > 0;");
        }
        $this->log('• ' . count($act) . ' sessões longas/ociosas, ' . $locks . ' locks aguardando');
        return $this->result(['top_queries' => $top ?? [], 'activity' => $act, 'locks_waiting' => (int) $locks, 'pg_stat_statements' => (bool) $ext],
            ['queries' => count($top ?? []), 'long_sessions' => count($act), 'locks' => (int) $locks]);
    }

    public function sizing(): array
    {
        $names = ['shared_buffers', 'work_mem', 'maintenance_work_mem', 'effective_cache_size', 'max_connections', 'random_page_cost',
            'effective_io_concurrency', 'max_worker_processes', 'max_parallel_workers', 'max_parallel_workers_per_gather', 'wal_buffers',
            'min_wal_size', 'max_wal_size', 'checkpoint_completion_target', 'autovacuum', 'autovacuum_max_workers', 'default_statistics_target',
            'huge_pages', 'jit', 'idle_in_transaction_session_timeout', 'shared_preload_libraries'];
        $rows = $this->q('SELECT name, setting, unit, source FROM pg_settings WHERE name = ANY(?::text[])', ['{' . implode(',', $names) . '}']);
        $settings = [];
        foreach ($rows as $r) {
            $settings[$r['name']] = ['value' => $r['setting'], 'unit' => $r['unit'], 'bytes' => self::toBytes($r['setting'], $r['unit']), 'source' => $r['source']];
            $this->log("  ↳ {$r['name']} = {$r['setting']}" . ($r['unit'] ? " {$r['unit']}" : ''));
        }
        $db = $this->q("SELECT blks_hit, blks_read, temp_files, temp_bytes, deadlocks, xact_commit, xact_rollback, stats_reset
                          FROM pg_stat_database WHERE datname = current_database()")[0];
        $hit = ((int) $db['blks_hit'] + (int) $db['blks_read']) > 0 ? round($db['blks_hit'] * 100 / ($db['blks_hit'] + $db['blks_read']), 2) : null;
        $conns = (int) $this->q('SELECT count(*) AS c FROM pg_stat_activity')[0]['c'];
        $metrics = [
            'cache_hit_ratio' => $hit, 'temp_files' => (int) $db['temp_files'], 'temp_bytes' => (int) $db['temp_bytes'],
            'deadlocks' => (int) $db['deadlocks'], 'connections' => $conns, 'max_connections' => (int) ($settings['max_connections']['value'] ?? 100),
            'rollback_ratio' => ((int) $db['xact_commit'] + (int) $db['xact_rollback']) > 0 ? round($db['xact_rollback'] * 100 / ($db['xact_commit'] + $db['xact_rollback']), 2) : 0,
            'stats_reset' => $db['stats_reset'],
        ];
        $this->log('✔ Cache hit ratio: ' . ($hit ?? 'n/d') . '% • conexões ' . $conns . '/' . $metrics['max_connections']);
        if ($hit !== null && $hit < 95) {
            $this->finding($hit < 90 ? 'high' : 'medium', 'sizing', "Cache hit ratio baixo ($hit%)", 'O working set não cabe em shared_buffers/cache do SO: mais I/O de disco.');
        }
        if ($metrics['temp_bytes'] > 1024 ** 3) {
            $this->finding('medium', 'sizing', 'Uso elevado de arquivos temporários (' . human_bytes($metrics['temp_bytes']) . ')', 'Ordenações/hash spilling para disco. Avalie work_mem ou as queries envolvidas.');
        }
        if ($metrics['deadlocks'] > 0) {
            $this->finding('medium', 'locks', "{$metrics['deadlocks']} deadlocks registrados", 'Padronize a ordem de acesso às linhas nas transações da aplicação.');
        }
        return $this->result(['settings' => $settings, 'stats' => $metrics], ['hit' => $hit, 'conns' => $conns]);
    }

    private static function toBytes(string $v, ?string $unit): ?int
    {
        if (!is_numeric($v)) {
            return null;
        }
        $mult = match ($unit) {
            '8kB' => 8192, 'kB' => 1024, 'MB' => 1024 ** 2, 'GB' => 1024 ** 3, '16MB' => 16 * 1024 ** 2, 'B' => 1, default => null,
        };
        return $mult ? (int) ((float) $v * $mult) : null;
    }
}
