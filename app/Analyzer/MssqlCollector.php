<?php
declare(strict_types=1);

namespace App\Analyzer;

/**
 * Coletor para Microsoft SQL Server 2016+ (também atende Azure SQL Database/Managed Instance).
 * Objetos de sistema (is_ms_shipped, schemas sys/INFORMATION_SCHEMA/cdc, tabelas de replicação e do
 * diagramador) são excluídos na origem: nunca viram achado nem script de correção.
 * Permissões recomendadas: VIEW SERVER STATE + VIEW DATABASE STATE + VIEW DEFINITION (ou VIEW SERVER PERFORMANCE STATE no 2022).
 */
final class MssqlCollector extends Collector
{
    /** Filtro de objetos de usuário aplicado a sys.tables/sys.objects com alias t e schema s. */
    private const USER_OBJ = "t.is_ms_shipped = 0 AND s.name NOT IN ('sys','INFORMATION_SCHEMA','cdc','guest')
        AND t.name NOT IN ('sysdiagrams','systranschemas','sysarticles','sysschemaarticles','syspublications','syssubscriptions',
                           'sysarticleupdates','sysextendedarticlesview','sysreplservers','sysarticlecolumns')
        AND t.name NOT LIKE 'MSpeer[_]%' AND t.name NOT LIKE 'MSpub[_]%' AND t.name NOT LIKE 'MSreplication[_]%'
        AND t.name NOT LIKE 'MSmerge[_]%' AND t.name NOT LIKE 'MSsync[_]%'
        AND NOT EXISTS (SELECT 1 FROM sys.extended_properties ep WHERE ep.class = 1 AND ep.major_id = t.object_id AND ep.minor_id = 0
                        AND ep.name = 'microsoft_database_tools_support')";

    private ?int $uptime = null;
    private int $majorVersion = 0;

    /** Só leitura: o SQL Server não tem sessão READ ONLY, então barramos qualquer coisa que não seja consulta. */
    protected function q(string $sql, array $params = []): array
    {
        if (!preg_match('/^\s*(\(\s*)*(SELECT|WITH)\b/i', $sql)) {
            throw new \LogicException('Somente SELECT/WITH são permitidos pelo analisador');
        }
        return parent::q($sql, $params);
    }

    protected function tableNames(): array
    {
        return array_map(fn($r) => [$r['s'], $r['t']], $this->q('SELECT s.name AS s, t.name AS t FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id WHERE ' . self::USER_OBJ));
    }

    private static function b(string $ident): string
    {
        return '[' . str_replace(']', ']]', $ident) . ']';
    }

    private static function fq(string $schema, string $name): string
    {
        return self::b($schema) . '.' . self::b($name);
    }

    public function connect(): array
    {
        $v = $this->q("SELECT @@VERSION AS banner, CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(64)) AS version,
                              CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) AS edition, CAST(SERVERPROPERTY('EngineEdition') AS int) AS engine_edition,
                              CAST(SERVERPROPERTY('ProductLevel') AS nvarchar(32)) AS level, SUSER_SNAME() AS usr, DB_NAME() AS db,
                              CAST((SELECT SUM(CAST(size AS bigint)) FROM sys.database_files) * 8192 AS bigint) AS db_size,
                              CAST(DATABASEPROPERTYEX(DB_NAME(), 'Updateability') AS nvarchar(32)) AS updateability")[0];
        $this->majorVersion = (int) explode('.', (string) $v['version'])[0];
        $up = $this->tryQ('sys.dm_os_sys_info (VIEW SERVER STATE)', 'SELECT DATEDIFF(SECOND, sqlserver_start_time, SYSDATETIME()) AS s FROM sys.dm_os_sys_info');
        $this->uptime = $up ? (int) $up[0]['s'] : null;
        $first = trim(strtok((string) $v['banner'], "\n"));
        $this->log('✔ Handshake OK — ' . $first);
        $this->log("• Edição {$v['edition']} ({$v['level']}) • login {$v['usr']}");
        $this->log('✔ Coleta somente leitura: apenas SELECT, READ UNCOMMITTED, LOCK_TIMEOUT 3s');
        $this->log('• Banco ' . $this->database . ' — ' . human_bytes((int) $v['db_size']) . ($v['updateability'] === 'READ_ONLY' ? ' (somente leitura)' : ''));

        $db = $this->tryQ('sys.databases', "SELECT recovery_model_desc AS recovery, compatibility_level AS compat, is_auto_shrink_on AS auto_shrink,
                    is_auto_close_on AS auto_close, page_verify_option_desc AS page_verify, is_auto_create_stats_on AS auto_create_stats,
                    is_auto_update_stats_on AS auto_update_stats, is_read_committed_snapshot_on AS rcsi, snapshot_isolation_state_desc AS si,
                    is_query_store_on AS query_store, state_desc AS state
               FROM sys.databases WHERE database_id = DB_ID()")[0] ?? [];
        $q = self::b($this->database);
        if ($db) {
            if ((int) $db['auto_shrink']) {
                $this->finding('high', 'config', 'AUTO_SHRINK ligado em ' . $this->database,
                    'Encolher arquivos automaticamente fragmenta todos os índices e gera ciclos de crescimento/encolhimento com I/O pesado.',
                    "ALTER DATABASE $q SET AUTO_SHRINK OFF;", $this->database);
            }
            if ((int) $db['auto_close']) {
                $this->finding('medium', 'config', 'AUTO_CLOSE ligado em ' . $this->database,
                    'O banco é fechado quando a última conexão sai: cada nova conexão paga a abertura e o cache de planos é descartado.',
                    "ALTER DATABASE $q SET AUTO_CLOSE OFF;", $this->database);
            }
            if ($db['page_verify'] !== 'CHECKSUM') {
                $this->finding('medium', 'config', "PAGE_VERIFY = {$db['page_verify']} em {$this->database}",
                    'Sem CHECKSUM a corrupção de páginas em disco passa despercebida até ser tarde.', "ALTER DATABASE $q SET PAGE_VERIFY CHECKSUM WITH NO_WAIT;", $this->database);
            }
            if (!(int) $db['auto_create_stats'] || !(int) $db['auto_update_stats']) {
                $this->finding('medium', 'statistics', 'Criação/atualização automática de estatísticas desligada',
                    'O otimizador passa a decidir com estatísticas ausentes ou velhas.',
                    "ALTER DATABASE $q SET AUTO_CREATE_STATISTICS ON;\nALTER DATABASE $q SET AUTO_UPDATE_STATISTICS ON;", $this->database);
            }
            $serverCompat = $this->majorVersion * 10;
            if ($serverCompat >= 130 && (int) $db['compat'] < $serverCompat - 10) {
                $this->finding('low', 'config', "Nível de compatibilidade {$db['compat']} (servidor suporta $serverCompat)",
                    'O banco não usa as melhorias recentes do otimizador (cardinality estimator, intelligent query processing). Teste antes em homologação.',
                    "-- Teste antes: a mudança altera planos de execução\nALTER DATABASE $q SET COMPATIBILITY_LEVEL = $serverCompat;", $this->database);
            }
        }
        // Backups (msdb). Sem permissão em msdb a checagem é pulada.
        $bk = $this->tryQ('histórico de backup (msdb)', "SELECT MAX(CASE WHEN type = 'D' THEN backup_finish_date END) AS last_full,
                    MAX(CASE WHEN type = 'L' THEN backup_finish_date END) AS last_log,
                    DATEDIFF(HOUR, MAX(CASE WHEN type = 'D' THEN backup_finish_date END), GETDATE()) AS full_age_h,
                    DATEDIFF(MINUTE, MAX(CASE WHEN type = 'L' THEN backup_finish_date END), GETDATE()) AS log_age_min
               FROM msdb.dbo.backupset WHERE database_name = DB_NAME()");
        if ($bk && (int) ($v['engine_edition'] ?? 0) !== 5) { // 5 = Azure SQL Database (backup gerenciado)
            $b = $bk[0];
            if ($b['last_full'] === null || (int) $b['full_age_h'] > 24 * 7) {
                $this->finding('critical', 'backup', 'Sem backup FULL nos últimos 7 dias',
                    'Último backup completo: ' . ($b['last_full'] ?: 'nunca registrado em msdb') . '. Uma falha de disco significa perda de dados.',
                    "BACKUP DATABASE $q TO DISK = N'/var/opt/mssql/backup/" . addslashes($this->database) . ".bak' WITH COMPRESSION, CHECKSUM, STATS = 10;", $this->database);
            }
            if (($db['recovery'] ?? '') === 'FULL' && ($b['last_log'] === null || (int) $b['log_age_min'] > 24 * 60)) {
                $this->finding('high', 'backup', 'Recovery FULL sem backup de log recente',
                    'Em FULL o log de transações só é truncado pelo backup de log: ele cresce sem limite e o point-in-time recovery não está garantido.',
                    "BACKUP LOG $q TO DISK = N'/var/opt/mssql/backup/" . addslashes($this->database) . "_log.trn' WITH COMPRESSION, CHECKSUM;\n-- ou, se point-in-time não for necessário: ALTER DATABASE $q SET RECOVERY SIMPLE;", $this->database);
            }
        }
        return $this->result([
            'version' => "SQL Server {$v['version']} {$v['edition']} {$v['level']}", 'banner' => $v['banner'], 'version_num' => $this->majorVersion, 'product_version' => (string) $v['version'],
            'db_size' => (int) $v['db_size'], 'uptime_s' => $this->uptime, 'user' => $v['usr'], 'database' => $db,
            'backups' => $bk[0] ?? null,
        ], ['db_size' => (int) $v['db_size']]);
    }

    public function schemas(): array
    {
        $tables = $this->q("
            SELECT s.name AS [schema], t.name AS name, t.object_id AS oid,
                   COALESCE((SELECT SUM(p.rows) FROM sys.partitions p WHERE p.object_id = t.object_id AND p.index_id IN (0,1)), 0) AS [rows],
                   COALESCE((SELECT SUM(CAST(au.used_pages AS bigint)) FROM sys.partitions p JOIN sys.allocation_units au ON au.container_id = p.hobt_id
                              WHERE p.object_id = t.object_id AND p.index_id IN (0,1)), 0) * 8192 AS data_bytes,
                   COALESCE((SELECT SUM(CAST(au.used_pages AS bigint)) FROM sys.partitions p JOIN sys.allocation_units au ON au.container_id = p.hobt_id
                              WHERE p.object_id = t.object_id AND p.index_id > 1), 0) * 8192 AS index_bytes,
                   CASE WHEN EXISTS (SELECT 1 FROM sys.indexes i WHERE i.object_id = t.object_id AND i.is_primary_key = 1) THEN 1 ELSE 0 END AS has_pk,
                   CASE WHEN EXISTS (SELECT 1 FROM sys.indexes i WHERE i.object_id = t.object_id AND i.index_id = 0) THEN 1 ELSE 0 END AS is_heap,
                   (SELECT MIN(STATS_DATE(st.object_id, st.stats_id)) FROM sys.stats st WHERE st.object_id = t.object_id) AS oldest_stats,
                   t.temporal_type AS temporal_type
              FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id
             WHERE " . self::USER_OBJ . "
             ORDER BY data_bytes + index_bytes DESC
            OFFSET 0 ROWS FETCH NEXT 2000 ROWS ONLY");

        // Uso desde o último restart (VIEW SERVER STATE); sem permissão, segue sem esta métrica
        $usage = [];
        foreach ($this->tryQ('sys.dm_db_index_usage_stats', "SELECT object_id AS oid, SUM(user_seeks + user_lookups) AS seeks, SUM(user_scans) AS scans
                   FROM sys.dm_db_index_usage_stats WHERE database_id = DB_ID() AND index_id IN (0,1) GROUP BY object_id") ?? [] as $u) {
            $usage[(int) $u['oid']] = $u;
        }

        $fkRows = $this->q("
            SELECT fk.object_id AS fk_id, fk.name, s.name AS [schema], t.name AS table_name, rs.name AS ref_schema, rt.name AS ref_table,
                   c.name AS col, fkc.constraint_column_id AS pos, fk.is_disabled, fk.is_not_trusted
              FROM sys.foreign_keys fk
              JOIN sys.tables t ON t.object_id = fk.parent_object_id JOIN sys.schemas s ON s.schema_id = t.schema_id
              JOIN sys.tables rt ON rt.object_id = fk.referenced_object_id JOIN sys.schemas rs ON rs.schema_id = rt.schema_id
              JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
              JOIN sys.columns c ON c.object_id = fkc.parent_object_id AND c.column_id = fkc.parent_column_id
             WHERE " . self::USER_OBJ . "
             ORDER BY fk.object_id, fkc.constraint_column_id");
        $fks = [];
        foreach ($fkRows as $r) {
            $id = (int) $r['fk_id'];
            $fks[$id] ??= ['name' => $r['name'], 'schema' => $r['schema'], 'table_name' => $r['table_name'], 'ref_schema' => $r['ref_schema'],
                'ref_table' => $r['ref_table'], 'columns' => '', 'disabled' => (bool) $r['is_disabled'], 'not_trusted' => (bool) $r['is_not_trusted']];
            $fks[$id]['columns'] .= ($fks[$id]['columns'] === '' ? '' : ',') . $r['col'];
        }
        $fks = array_values($fks);
        $this->log('• ' . count($tables) . ' tabelas de usuário mapeadas, ' . count($fks) . ' chaves estrangeiras');

        $linked = [];
        foreach ($fks as $fk) {
            $linked[$fk['schema'] . '.' . $fk['table_name']] = $linked[$fk['ref_schema'] . '.' . $fk['ref_table']] = true;
            $tq = self::fq($fk['schema'], $fk['table_name']);
            if ($fk['disabled']) {
                $this->finding('medium', 'relationships', "FK desabilitada: {$fk['schema']}.{$fk['table_name']}.{$fk['name']}",
                    'A integridade referencial não está sendo garantida: dados órfãos podem existir.',
                    "-- Verifique órfãos antes; a validação lê a tabela inteira\nALTER TABLE $tq WITH CHECK CHECK CONSTRAINT " . self::b($fk['name']) . ';', "{$fk['schema']}.{$fk['table_name']}");
            } elseif ($fk['not_trusted']) {
                $this->finding('low', 'relationships', "FK não confiável (NOT TRUSTED): {$fk['schema']}.{$fk['table_name']}.{$fk['name']}",
                    'Foi reabilitada sem WITH CHECK: o otimizador ignora a FK e não elimina JOINs desnecessários.',
                    "ALTER TABLE $tq WITH CHECK CHECK CONSTRAINT " . self::b($fk['name']) . ';', "{$fk['schema']}.{$fk['table_name']}");
            }
        }

        $out = [];
        $noPk = 0;
        $uptimeOk = ($this->uptime ?? 0) > 7 * 86400 || $this->uptime === null;
        foreach ($tables as $t) {
            $fq = $t['schema'] . '.' . $t['name'];
            $tq = self::fq($t['schema'], $t['name']);
            $rows = (int) $t['rows'];
            $this->log("  ↳ $fq (" . number_format($rows, 0, ',', '.') . ' linhas, ' . human_bytes((int) $t['data_bytes']) . ')');
            $isHistory = (int) $t['temporal_type'] === 1; // tabela de histórico de temporal table: sem PK por definição
            if (!(int) $t['has_pk'] && !$isHistory) {
                $noPk++;
                $this->finding($rows > 10000 ? 'high' : 'medium', 'schema', "Tabela sem chave primária: $fq",
                    'Sem PK não há como identificar linhas de forma única: duplicidades passam, replicação transacional e CDC ficam limitados.',
                    "-- Avalie a coluna candidata antes de aplicar\nALTER TABLE $tq ADD id bigint IDENTITY(1,1) NOT NULL CONSTRAINT " . self::b(substr('PK_' . $t['name'], 0, 128)) . ' PRIMARY KEY CLUSTERED;', $fq);
            }
            if ((int) $t['is_heap'] && (int) $t['has_pk'] && $rows > 10000) {
                $this->finding('medium', 'schema', "Tabela heap (sem índice clustered): $fq",
                    'Heaps acumulam forwarded records e espaço não reaproveitado; a PK existe mas é NONCLUSTERED.',
                    "-- Crie um índice clustered na chave mais usada em buscas por faixa (pode ser a PK); a operação reescreve a tabela\n-- CREATE CLUSTERED INDEX CX_" . preg_replace('/\W+/', '_', $t['name']) . " ON $tq (<coluna>) WITH (ONLINE = ON);", $fq);
            }
            if ($rows > 50000 && $t['oldest_stats'] !== null && strtotime((string) $t['oldest_stats']) < time() - 30 * 86400) {
                $this->finding('medium', 'statistics', "Estatísticas com mais de 30 dias em $fq",
                    'Estatística mais antiga: ' . $t['oldest_stats'] . '. Em tabelas grandes o auto update dispara tarde (limiar de 20% ou sqrt(1000*n)).',
                    "UPDATE STATISTICS $tq WITH SAMPLE 25 PERCENT;", $fq);
            }
            $u = $usage[(int) $t['oid']] ?? null;
            if ($u && $uptimeOk && $rows > 100000 && (int) $u['scans'] > 10 * max(1, (int) $u['seeks'])) {
                $this->finding('medium', 'queries', "Varreduras completas predominantes em $fq",
                    "user_scans={$u['scans']} vs seeks/lookups=" . (int) $u['seeks'] . '. Provável falta de índice para filtros frequentes (veja a etapa de índices sugeridos).', null, $fq);
            }
            $out[] = [
                'schema' => $t['schema'], 'name' => $t['name'], 'rows' => $rows, 'data_bytes' => (int) $t['data_bytes'], 'index_bytes' => (int) $t['index_bytes'],
                'has_pk' => (bool) $t['has_pk'], 'heap' => (bool) $t['is_heap'], 'seq_scan' => (int) ($u['scans'] ?? 0), 'idx_scan' => (int) ($u['seeks'] ?? 0),
                'last_stats' => $t['oldest_stats'], 'isolated' => !isset($linked[$fq]),
            ];
        }

        $smells = $this->tryQ('tipos de dados', "
            SELECT s.name AS [schema], t.name AS table_name, c.name AS col, ty.name AS type, c.max_length
              FROM sys.columns c JOIN sys.tables t ON t.object_id = c.object_id JOIN sys.schemas s ON s.schema_id = t.schema_id
              JOIN sys.types ty ON ty.user_type_id = c.user_type_id
             WHERE " . self::USER_OBJ . "
               AND ( ty.name IN ('text','ntext','image')
                  OR (ty.name IN ('float','real') AND (c.name LIKE '%price%' OR c.name LIKE '%preco%' OR c.name LIKE '%valor%' OR c.name LIKE '%amount%'
                                                     OR c.name LIKE '%total%' OR c.name LIKE '%saldo%'))
                  OR ((c.name LIKE '%[_]id' OR c.name = 'id') AND ty.name IN ('varchar','nvarchar','char','nchar')) )
             ORDER BY s.name, t.name
            OFFSET 0 ROWS FETCH NEXT 200 ROWS ONLY") ?? [];
        foreach ($smells as $s) {
            $fq = "{$s['schema']}.{$s['table_name']}.{$s['col']}";
            [$why, $fix] = match (true) {
                in_array($s['type'], ['text', 'ntext', 'image'], true) => ['Tipo obsoleto desde o SQL Server 2005: não funciona com várias funções de string e será removido.',
                    ['text' => 'varchar(max)', 'ntext' => 'nvarchar(max)', 'image' => 'varbinary(max)'][$s['type']]],
                in_array($s['type'], ['float', 'real'], true) => ['Ponto flutuante para valores monetários causa erros de arredondamento.', 'decimal(14,2)'],
                default => ['Identificador armazenado como texto: maior e mais lento em JOINs e índices.', 'bigint'],
            };
            $this->finding('low', 'types', "Tipo inadequado: $fq ({$s['type']})", $why,
                'ALTER TABLE ' . self::fq($s['schema'], $s['table_name']) . ' ALTER COLUMN ' . self::b($s['col']) . " $fix; -- reescreve a tabela; mantenha NULL/NOT NULL atual e agende janela", $fq);
        }

        return $this->result(['tables' => $out, 'foreign_keys' => $fks, 'type_smells' => $smells],
            ['tables' => count($out), 'fks' => count($fks), 'no_pk' => $noPk, 'rows' => array_sum(array_column($out, 'rows'))]);
    }

    public function indexes(): array
    {
        $rows = $this->q("
            SELECT s.name AS [schema], t.name AS table_name, t.object_id AS oid, i.index_id, i.name, i.type_desc AS type, i.is_unique, i.is_primary_key AS is_pk,
                   i.is_unique_constraint AS is_uc, i.has_filter, i.filter_definition AS filter, i.is_disabled,
                   COALESCE((SELECT SUM(CAST(au.used_pages AS bigint)) FROM sys.partitions p JOIN sys.allocation_units au ON au.container_id = p.hobt_id
                              WHERE p.object_id = i.object_id AND p.index_id = i.index_id), 0) * 8192 AS bytes,
                   ic.key_ordinal, ic.is_included_column AS incl, ic.is_descending_key AS descending, c.name AS col
              FROM sys.indexes i
              JOIN sys.tables t ON t.object_id = i.object_id JOIN sys.schemas s ON s.schema_id = t.schema_id
              LEFT JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
              LEFT JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
             WHERE i.index_id > 0 AND i.is_hypothetical = 0 AND i.type IN (1,2) AND " . self::USER_OBJ . "
             ORDER BY t.object_id, i.index_id, ic.is_included_column, ic.key_ordinal, c.name");
        $idx = [];
        foreach ($rows as $r) {
            $k = $r['oid'] . ':' . $r['index_id'];
            $idx[$k] ??= ['schema' => $r['schema'], 'table' => $r['table_name'], 'oid' => (int) $r['oid'], 'index_id' => (int) $r['index_id'], 'name' => $r['name'],
                'type' => $r['type'], 'unique' => (bool) $r['is_unique'], 'primary' => (bool) $r['is_pk'], 'uc' => (bool) $r['is_uc'],
                'filter' => $r['has_filter'] ? $r['filter'] : null, 'disabled' => (bool) $r['is_disabled'], 'bytes' => (int) $r['bytes'], 'keys' => [], 'include' => [], 'scans' => 0, 'updates' => 0];
            if ($r['col'] === null) {
                continue;
            }
            if ((int) $r['incl']) {
                $idx[$k]['include'][] = $r['col'];
            } elseif ((int) $r['key_ordinal'] > 0) {
                $idx[$k]['keys'][] = $r['col'] . ((int) $r['descending'] ? ' DESC' : '');
            }
        }
        foreach ($idx as &$i) {
            sort($i['include']);
        }
        unset($i);
        $usage = $this->tryQ('sys.dm_db_index_usage_stats', "SELECT object_id AS oid, index_id, user_seeks + user_scans + user_lookups AS reads, user_updates AS writes
                   FROM sys.dm_db_index_usage_stats WHERE database_id = DB_ID()");
        foreach ($usage ?? [] as $u) {
            if (isset($idx[$u['oid'] . ':' . $u['index_id']])) {
                $idx[$u['oid'] . ':' . $u['index_id']]['scans'] = (int) $u['reads'];
                $idx[$u['oid'] . ':' . $u['index_id']]['updates'] = (int) $u['writes'];
            }
        }
        $this->log('• ' . count($idx) . ' índices rowstore encontrados');

        $drop = fn(array $i) => 'DROP INDEX ' . self::b($i['name']) . ' ON ' . self::fq($i['schema'], $i['table']) . ';';
        $byTable = [];
        foreach ($idx as $i) {
            $byTable[$i['oid']][] = $i;
        }
        // Duplicados (mesmas chaves, includes e filtro) e redundantes (chaves são prefixo de outro índice)
        $dups = 0;
        $flagged = [];
        foreach ($byTable as $list) {
            foreach ($list as $a) {
                if ($a['primary'] || $a['unique'] || $a['type'] !== 'NONCLUSTERED' || isset($flagged[$a['name']])) {
                    continue;
                }
                foreach ($list as $b) {
                    if ($a['name'] === $b['name'] || isset($flagged[$b['name']]) || $a['filter'] !== $b['filter']) {
                        continue;
                    }
                    $ka = implode(',', $a['keys']);
                    $kb = implode(',', $b['keys']);
                    $sameIncl = $a['include'] === $b['include'] || !array_diff($a['include'], array_merge($b['include'], array_map(fn($x) => preg_replace('/ DESC$/', '', $x), $b['keys'])));
                    $isDup = $ka === $kb && $sameIncl && ($b['unique'] || $b['primary'] || $b['type'] === 'CLUSTERED' || strcmp($a['name'], $b['name']) > 0);
                    $isPrefix = $ka !== $kb && str_starts_with($kb . ',', $ka . ',') && $sameIncl && $b['type'] === 'NONCLUSTERED';
                    if ($isDup || $isPrefix) {
                        $dups++;
                        $flagged[$a['name']] = true;
                        $fq = "{$a['schema']}.{$a['table']}.{$a['name']}";
                        $this->finding($isDup ? 'high' : 'medium', 'indexes', ($isDup ? 'Índice duplicado' : 'Índice redundante') . ": $fq ($ka)",
                            ($isDup ? 'Idêntico a ' : 'Suas chaves são prefixo de ') . "{$b['name']} ($kb). Consome " . human_bytes($a['bytes']) . ' e custo extra em cada escrita.',
                            $drop($a), $fq);
                        break;
                    }
                }
            }
        }
        // Nunca utilizados desde o último restart
        $unused = [];
        $uptime = $this->uptime ?? 0;
        if ($usage !== null) {
            foreach ($idx as $i) {
                if (!$i['unique'] && !$i['primary'] && $i['type'] === 'NONCLUSTERED' && $i['scans'] === 0 && !$i['disabled']) {
                    $unused[] = $i;
                    if ($i['bytes'] >= 1024 * 1024 && $uptime > 7 * 86400 && !isset($flagged[$i['name']])) {
                        $this->finding('medium', 'indexes', "Índice nunca utilizado: {$i['schema']}.{$i['table']}.{$i['name']}",
                            'Nenhum seek/scan/lookup desde o último restart (' . round($uptime / 86400) . " dias), {$i['updates']} atualizações pagas. Ocupa " . human_bytes($i['bytes']) . '. Confirme em réplicas/AG secundários antes de remover.',
                            "-- Alternativa reversível: ALTER INDEX " . self::b($i['name']) . ' ON ' . self::fq($i['schema'], $i['table']) . " DISABLE;\n" . $drop($i), "{$i['schema']}.{$i['table']}");
                    }
                }
            }
            if ($uptime <= 7 * 86400) {
                $this->log('ℹ Uptime < 7 dias: análise de índices não usados é pouco confiável');
            }
        }
        foreach ($idx as $i) {
            if ($i['disabled'] && $i['type'] === 'NONCLUSTERED') {
                $this->finding('low', 'indexes', "Índice desabilitado: {$i['schema']}.{$i['table']}.{$i['name']}", 'Ocupa metadados e confunde a manutenção; reconstrua ou remova.',
                    'ALTER INDEX ' . self::b($i['name']) . ' ON ' . self::fq($i['schema'], $i['table']) . " REBUILD;\n-- ou: " . $drop($i), "{$i['schema']}.{$i['table']}");
            }
        }

        // FKs sem índice cujas colunas iniciais coincidam
        $fkNoIdx = [];
        $fkRows = $this->q("
            SELECT fk.object_id AS fk_id, fk.name AS fk, s.name AS [schema], t.name AS table_name, t.object_id AS oid, c.name AS col,
                   COALESCE((SELECT SUM(p.rows) FROM sys.partitions p WHERE p.object_id = t.object_id AND p.index_id IN (0,1)), 0) AS [rows]
              FROM sys.foreign_keys fk JOIN sys.tables t ON t.object_id = fk.parent_object_id JOIN sys.schemas s ON s.schema_id = t.schema_id
              JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
              JOIN sys.columns c ON c.object_id = fkc.parent_object_id AND c.column_id = fkc.parent_column_id
             WHERE " . self::USER_OBJ . " ORDER BY fk.object_id, fkc.constraint_column_id");
        $fkCols = [];
        foreach ($fkRows as $r) {
            $fkCols[$r['fk_id']] ??= ['fk' => $r['fk'], 'schema' => $r['schema'], 'table_name' => $r['table_name'], 'oid' => (int) $r['oid'], 'rows' => (int) $r['rows'], 'cols' => []];
            $fkCols[$r['fk_id']]['cols'][] = $r['col'];
        }
        foreach ($fkCols as $f) {
            $covered = false;
            foreach ($byTable[$f['oid']] ?? [] as $i) {
                $keys = array_map(fn($k) => preg_replace('/ DESC$/', '', $k), $i['keys']);
                if (array_slice($keys, 0, count($f['cols'])) == $f['cols'] || (count($keys) >= count($f['cols']) && !array_diff($f['cols'], array_slice($keys, 0, count($f['cols']))))) {
                    $covered = true;
                    break;
                }
            }
            if (!$covered) {
                $cols = implode(', ', $f['cols']);
                $fkNoIdx[] = ['schema' => $f['schema'], 'table_name' => $f['table_name'], 'fk' => $f['fk'], 'cols' => $cols, 'rows' => $f['rows']];
                $name = substr('IX_' . $f['table_name'] . '_' . implode('_', $f['cols']), 0, 128);
                $this->finding($f['rows'] > 10000 ? 'high' : 'medium', 'relationships', "FK sem índice: {$f['schema']}.{$f['table_name']} ($cols)",
                    "A constraint {$f['fk']} não tem índice de apoio: DELETE/UPDATE na tabela pai varre a tabela filha inteira e segura locks.",
                    'CREATE INDEX ' . self::b($name) . ' ON ' . self::fq($f['schema'], $f['table_name']) . ' (' . implode(', ', array_map([self::class, 'b'], $f['cols'])) . ')'
                    . " WITH (ONLINE = ON); -- ONLINE exige Enterprise/Developer/Azure", "{$f['schema']}.{$f['table_name']}");
            }
        }

        // Fragmentação (modo LIMITED: lê só páginas de nível superior; filtra índices pequenos)
        $frag = $this->tryQ('sys.dm_db_index_physical_stats', "
            SELECT s.name AS [schema], t.name AS table_name, i.name, ps.avg_fragmentation_in_percent AS pct, ps.page_count AS pages
              FROM sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'LIMITED') ps
              JOIN sys.indexes i ON i.object_id = ps.object_id AND i.index_id = ps.index_id
              JOIN sys.tables t ON t.object_id = i.object_id JOIN sys.schemas s ON s.schema_id = t.schema_id
             WHERE ps.index_id > 0 AND ps.alloc_unit_type_desc = 'IN_ROW_DATA' AND ps.page_count > 1000 AND ps.avg_fragmentation_in_percent > 30
               AND " . self::USER_OBJ . "
             ORDER BY ps.page_count DESC OFFSET 0 ROWS FETCH NEXT 30 ROWS ONLY") ?? [];
        foreach ($frag as $f) {
            $pct = round((float) $f['pct'], 1);
            $this->finding($pct > 60 && (int) $f['pages'] > 100000 ? 'medium' : 'low', 'bloat', "Fragmentação de $pct% em {$f['schema']}.{$f['table_name']}.{$f['name']}",
                number_format((int) $f['pages'], 0, ',', '.') . ' páginas. Em SSD o impacto é menor; priorize se houver varreduras por faixa.',
                'ALTER INDEX ' . self::b($f['name']) . ' ON ' . self::fq($f['schema'], $f['table_name']) . " REBUILD WITH (ONLINE = ON, SORT_IN_TEMPDB = ON);\n-- Standard edition: ALTER INDEX ... REORGANIZE;",
                "{$f['schema']}.{$f['table_name']}");
        }

        // Índices sugeridos pelo próprio otimizador
        $missing = $this->tryQ('sys.dm_db_missing_index_details', "
            SELECT TOP 10 d.statement AS tbl, d.equality_columns AS eq, d.inequality_columns AS ineq, d.included_columns AS incl,
                   s.user_seeks AS seeks, CAST(s.avg_user_impact AS decimal(5,1)) AS impact,
                   CAST(s.avg_total_user_cost * s.avg_user_impact * (s.user_seeks + s.user_scans) AS bigint) AS score
              FROM sys.dm_db_missing_index_details d
              JOIN sys.dm_db_missing_index_groups g ON g.index_handle = d.index_handle
              JOIN sys.dm_db_missing_index_group_stats s ON s.group_handle = g.index_group_handle
             WHERE d.database_id = DB_ID() AND d.object_id NOT IN (SELECT t.object_id FROM sys.tables t JOIN sys.schemas s2 ON s2.schema_id = t.schema_id
                                                                 WHERE t.is_ms_shipped = 1 OR s2.name IN ('sys','cdc'))
             ORDER BY score DESC") ?? [];
        foreach ($missing as $m) {
            if ((int) $m['seeks'] < 100 || (float) $m['impact'] < 50) {
                continue;
            }
            $keys = trim(implode(', ', array_filter([$m['eq'], $m['ineq']])));
            $tbl = (string) $m['tbl'];
            $short = preg_replace('/^\[[^\]]+\]\./', '', $tbl);
            $name = substr('IX_' . preg_replace('/\W+/', '_', trim($short . '_' . str_replace(['[', ']'], '', $keys), '_')), 0, 128);
            $this->finding('medium', 'indexes', "Índice sugerido pelo otimizador em $short",
                "{$m['seeks']} buscas teriam ~{$m['impact']}% de ganho estimado. Revise antes: a sugestão não considera índices existentes nem custo de escrita.",
                "CREATE INDEX " . self::b($name) . " ON $short ($keys)" . ($m['incl'] ? " INCLUDE ({$m['incl']})" : '') . ' WITH (ONLINE = ON);', $short);
        }

        $list = array_map(fn($i) => [
            'schema' => $i['schema'], 'table' => $i['table'], 'name' => $i['name'], 'bytes' => $i['bytes'], 'scans' => $i['scans'], 'unique' => $i['unique'],
            'primary' => $i['primary'], 'def' => ($i['unique'] ? 'UNIQUE ' : '') . $i['type'] . ' (' . implode(', ', $i['keys']) . ')'
                . ($i['include'] ? ' INCLUDE (' . implode(', ', $i['include']) . ')' : '') . ($i['filter'] ? ' WHERE ' . $i['filter'] : ''),
        ], array_values($idx));
        usort($list, fn($a, $b) => $b['bytes'] <=> $a['bytes']);
        return $this->result(['indexes' => array_slice($list, 0, 500), 'unused' => count($unused), 'duplicates' => $dups, 'fk_without_index' => $fkNoIdx,
            'fragmented' => $frag, 'missing_indexes' => $missing],
            ['indexes' => count($idx), 'unused' => count($unused), 'fk_no_idx' => count($fkNoIdx)]);
    }

    public function queries(): array
    {
        $top = $this->tryQ('sys.dm_exec_query_stats (VIEW SERVER STATE)', "
            SELECT TOP 15
                   LEFT(SUBSTRING(st.text, (qs.statement_start_offset / 2) + 1,
                        ((CASE qs.statement_end_offset WHEN -1 THEN DATALENGTH(st.text) ELSE qs.statement_end_offset END - qs.statement_start_offset) / 2) + 1), 2000) AS query,
                   qs.execution_count AS calls, CAST(qs.total_elapsed_time / 1000.0 AS decimal(18,1)) AS total_ms,
                   CAST(qs.total_elapsed_time / 1000.0 / NULLIF(qs.execution_count, 0) AS decimal(18,2)) AS mean_ms,
                   qs.total_logical_reads AS logical_reads, qs.total_physical_reads AS physical_reads, qs.total_rows AS [rows],
                   CONVERT(varchar(64), qs.query_hash, 1) AS query_hash
              FROM sys.dm_exec_query_stats qs
             CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) st
             CROSS APPLY (SELECT CONVERT(int, pa.value) AS dbid FROM sys.dm_exec_plan_attributes(qs.plan_handle) pa WHERE pa.attribute = 'dbid') a
             WHERE a.dbid = DB_ID() AND st.text NOT LIKE '%db-oraculo-analyzer%' AND st.text NOT LIKE '%sys.dm[_]exec[_]query[_]stats%'
             ORDER BY qs.total_elapsed_time DESC");
        if ($top !== null) {
            $this->log('✔ Cache de planos: ' . count($top) . ' queries mais custosas deste banco');
        }
        foreach ($top ?? [] as $t) {
            if ((float) $t['mean_ms'] > 500) {
                $this->finding('high', 'queries', 'Query lenta (média ' . $t['mean_ms'] . ' ms, ' . $t['calls'] . ' execuções)',
                    mb_substr(preg_replace('/\s+/', ' ', (string) $t['query']), 0, 400) . "\nLeituras lógicas: " . $t['logical_reads'],
                    "-- Plano real: execute em homologação com\nSET STATISTICS IO, TIME ON;\n-- e inclua o plano de execução real (SSMS: Ctrl+M) para:\n" . mb_substr((string) $t['query'], 0, 2000));
            }
        }
        $qs = $this->tryQ('Query Store', 'SELECT actual_state_desc AS state, desired_state_desc AS desired FROM sys.database_query_store_options');
        if ($qs !== null && ($qs[0]['state'] ?? 'OFF') === 'OFF' && $this->majorVersion >= 13) {
            $this->finding('medium', 'observability', 'Query Store desligado',
                'Sem ele não há histórico de planos e desempenho por query; regressões de plano passam despercebidas.',
                'ALTER DATABASE ' . self::b($this->database) . " SET QUERY_STORE = ON (OPERATION_MODE = READ_WRITE, QUERY_CAPTURE_MODE = AUTO);");
        }

        // Sessões: requisições longas e transações abertas ociosas neste banco
        $act = $this->tryQ('sys.dm_exec_sessions/requests', "
            SELECT s.session_id AS pid, s.login_name AS usename, COALESCE(r.status, s.status) AS state, r.wait_type AS wait_event,
                   r.blocking_session_id AS blocked_by, s.open_transaction_count AS open_tran,
                   DATEDIFF(SECOND, COALESCE(r.start_time, s.last_request_end_time), GETDATE()) AS query_s,
                   DATEDIFF(SECOND, (SELECT MIN(at.transaction_begin_time) FROM sys.dm_tran_session_transactions tst
                                       JOIN sys.dm_tran_active_transactions at ON at.transaction_id = tst.transaction_id
                                      WHERE tst.session_id = s.session_id), GETDATE()) AS xact_s,
                   s.host_name AS client, s.program_name AS app,
                   LEFT((SELECT t.text FROM sys.dm_exec_sql_text(COALESCE(r.sql_handle, (SELECT c.most_recent_sql_handle FROM sys.dm_exec_connections c WHERE c.session_id = s.session_id))) t), 500) AS query
              FROM sys.dm_exec_sessions s LEFT JOIN sys.dm_exec_requests r ON r.session_id = s.session_id
             WHERE s.is_user_process = 1 AND s.database_id = DB_ID() AND s.session_id <> @@SPID
               AND ( (r.session_id IS NOT NULL AND DATEDIFF(SECOND, r.start_time, GETDATE()) > 30)
                  OR (r.session_id IS NULL AND s.open_transaction_count > 0)
                  OR r.blocking_session_id > 0 )
             ORDER BY query_s DESC OFFSET 0 ROWS FETCH NEXT 30 ROWS ONLY") ?? [];
        $blocked = 0;
        foreach ($act as $a) {
            if ((int) $a['blocked_by'] > 0) {
                $blocked++;
            }
            if ($a['state'] === 'sleeping' && (int) $a['open_tran'] > 0 && (int) $a['xact_s'] > 60) {
                $this->finding('high', 'locks', "Transação aberta e ociosa há {$a['xact_s']}s (sessão {$a['pid']}, {$a['app']})",
                    'A sessão abriu transação e não fez COMMIT/ROLLBACK: segura locks, impede truncar o log e bloqueia outras sessões.',
                    "-- Confirme com o dono da aplicação antes\nKILL {$a['pid']};");
            }
        }
        if ($blocked > 0) {
            $this->finding('medium', 'locks', "$blocked sessões bloqueadas no momento da coleta", 'Investigue a cadeia de bloqueio (blocking_session_id).',
                "SELECT session_id, blocking_session_id, wait_type, wait_time, DB_NAME(database_id) AS db FROM sys.dm_exec_requests WHERE blocking_session_id <> 0;");
        }
        $this->log('• ' . count($act) . ' sessões longas/ociosas, ' . $blocked . ' bloqueadas');
        return $this->result(['top_queries' => $top ?? [], 'activity' => $act, 'locks_waiting' => $blocked, 'query_store' => $qs[0]['state'] ?? null],
            ['queries' => count($top ?? []), 'long_sessions' => count($act), 'locks' => $blocked]);
    }

    public function sizing(): array
    {
        $names = ['max server memory (MB)', 'min server memory (MB)', 'max degree of parallelism', 'cost threshold for parallelism',
            'optimize for ad hoc workloads', 'max worker threads', 'backup compression default', 'user connections', 'fill factor (%)',
            'remote admin connections', 'priority boost', 'lightweight pooling'];
        $settings = [];
        $rows = $this->tryQ('sys.configurations', 'SELECT name, CAST(value_in_use AS bigint) AS value FROM sys.configurations WHERE name IN (' . implode(',', array_fill(0, count($names), '?')) . ')', $names) ?? [];
        foreach ($rows as $r) {
            $settings[$r['name']] = ['value' => (string) $r['value'], 'bytes' => str_ends_with($r['name'], '(MB)') ? (int) $r['value'] * 1024 ** 2 : null];
            $this->log("  ↳ {$r['name']} = {$r['value']}");
        }
        $sys = $this->tryQ('sys.dm_os_sys_info', 'SELECT cpu_count, CAST(physical_memory_kb AS bigint) * 1024 AS ram, CAST(committed_kb AS bigint) * 1024 AS committed,
                    CAST(committed_target_kb AS bigint) * 1024 AS target FROM sys.dm_os_sys_info')[0] ?? null;
        $tempdb = (int) ($this->tryQ('arquivos do tempdb', "SELECT COUNT(*) AS n FROM tempdb.sys.database_files WHERE type = 0")[0]['n'] ?? 0);
        if ($tempdb) {
            $settings['tempdb data files'] = ['value' => (string) $tempdb, 'bytes' => null];
        }
        $pc = [];
        foreach ($this->tryQ('sys.dm_os_performance_counters', "SELECT RTRIM(counter_name) AS name, RTRIM(instance_name) AS inst, cntr_value AS v
                   FROM sys.dm_os_performance_counters
                  WHERE counter_name IN ('Buffer cache hit ratio','Buffer cache hit ratio base','Page life expectancy','User Connections',
                                         'Number of Deadlocks/sec','Batch Requests/sec','Memory Grants Pending')
                    AND (object_name LIKE '%Buffer Manager%' OR object_name LIKE '%General Statistics%' OR object_name LIKE '%Locks%' OR object_name LIKE '%SQL Statistics%'
                         OR object_name LIKE '%Memory Manager%')
                    AND (instance_name = '' OR instance_name = '_Total')") ?? [] as $r) {
            $pc[$r['name']] = (float) $r['v'];
        }
        $hit = ($pc['Buffer cache hit ratio base'] ?? 0) > 0 ? round($pc['Buffer cache hit ratio'] * 100 / $pc['Buffer cache hit ratio base'], 2) : null;
        $ple = isset($pc['Page life expectancy']) ? (int) $pc['Page life expectancy'] : null;
        $metrics = [
            'cache_hit_ratio' => $hit, 'page_life_expectancy' => $ple, 'connections' => (int) ($pc['User Connections'] ?? 0),
            'deadlocks' => (int) ($pc['Number of Deadlocks/sec'] ?? 0), 'memory_grants_pending' => (int) ($pc['Memory Grants Pending'] ?? 0),
            'cpu_count' => $sys ? (int) $sys['cpu_count'] : null, 'server_ram' => $sys ? (int) $sys['ram'] : null,
            'committed_memory' => $sys ? (int) $sys['committed'] : null, 'uptime_s' => $this->uptime, 'tempdb_files' => $tempdb ?: null,
        ];
        $this->log('✔ Buffer cache hit: ' . ($hit ?? 'n/d') . '% • PLE ' . ($ple ?? 'n/d') . ' s • ' . $metrics['connections'] . ' conexões');

        $maxMem = isset($settings['max server memory (MB)']) ? (int) $settings['max server memory (MB)']['value'] : null;
        if ($maxMem !== null && $maxMem >= 2147483647) {
            $this->finding('high', 'config', 'max server memory sem limite (padrão)',
                'O SQL Server pode tomar quase toda a RAM e deixar o SO e outros processos paginando. Defina um teto deixando memória para o SO.',
                "-- Ajuste o valor conforme o veredito de dimensionamento\nEXEC sp_configure 'show advanced options', 1; RECONFIGURE;\nEXEC sp_configure 'max server memory (MB)', <valor>; RECONFIGURE;");
        }
        $cpu = $metrics['cpu_count'] ?? 0;
        $maxdop = isset($settings['max degree of parallelism']) ? (int) $settings['max degree of parallelism']['value'] : null;
        if ($maxdop === 0 && $cpu > 8) {
            $this->finding('medium', 'config', "MAXDOP = 0 com $cpu CPUs",
                'Uma única query pode usar todos os núcleos e gerar esperas CXPACKET/CXCONSUMER. A recomendação da Microsoft é até 8.',
                "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;\nEXEC sp_configure 'max degree of parallelism', 8; RECONFIGURE;");
        }
        if (isset($settings['cost threshold for parallelism']) && (int) $settings['cost threshold for parallelism']['value'] <= 5) {
            $this->finding('medium', 'config', 'cost threshold for parallelism = 5 (padrão de 1997)',
                'Queries baratas viram paralelas e disputam CPU. Valores entre 30 e 50 são o ponto de partida usual.',
                "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;\nEXEC sp_configure 'cost threshold for parallelism', 50; RECONFIGURE;");
        }
        if (isset($settings['optimize for ad hoc workloads']) && (int) $settings['optimize for ad hoc workloads']['value'] === 0) {
            $this->finding('low', 'config', 'optimize for ad hoc workloads desligado',
                'Planos de queries executadas uma única vez ocupam o cache de planos inteiro.',
                "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;\nEXEC sp_configure 'optimize for ad hoc workloads', 1; RECONFIGURE;");
        }
        if ($tempdb === 1 && $cpu >= 4) {
            $this->finding('medium', 'config', 'tempdb com um único arquivo de dados',
                'Contenção de alocação (PAGELATCH em PFS/GAM/SGAM) sob carga. Use um arquivo por núcleo, até 8, todos do mesmo tamanho.',
                "ALTER DATABASE tempdb ADD FILE (NAME = tempdev2, FILENAME = '<caminho>/tempdb2.ndf', SIZE = <igual ao primeiro>, FILEGROWTH = 512MB);");
        }
        if ($hit !== null && $hit < 95) {
            $this->finding($hit < 90 ? 'high' : 'medium', 'sizing', "Buffer cache hit ratio baixo ($hit%)", 'O working set não cabe no buffer pool: mais leitura física.');
        }
        if ($ple !== null && $ple < 300) {
            $this->finding('medium', 'sizing', "Page life expectancy baixo ($ple s)", 'Páginas saem do buffer pool em poucos minutos: pressão de memória ou varreduras grandes.');
        }
        if ($metrics['memory_grants_pending'] > 0) {
            $this->finding('high', 'sizing', "{$metrics['memory_grants_pending']} queries aguardando memory grant", 'Queries estão esperando memória para executar (ordenações/hash grandes).');
        }
        if ($metrics['deadlocks'] > 0) {
            $this->finding('medium', 'locks', "{$metrics['deadlocks']} deadlocks desde o último restart", 'Analise o system_health (Extended Events) e padronize a ordem de acesso às tabelas.',
                "SELECT XEvent.query('(event/data/value/deadlock)[1]') AS deadlock_graph\n  FROM (SELECT CAST(target_data AS XML) AS t FROM sys.dm_xe_session_targets st JOIN sys.dm_xe_sessions s ON s.address = st.event_session_address\n        WHERE s.name = 'system_health' AND st.target_name = 'ring_buffer') AS d\n CROSS APPLY t.nodes('RingBufferTarget/event[@name=\"xml_deadlock_report\"]') AS x(XEvent);");
        }
        return $this->result(['settings' => $settings, 'stats' => $metrics], ['hit' => $hit, 'conns' => $metrics['connections']]);
    }
}
