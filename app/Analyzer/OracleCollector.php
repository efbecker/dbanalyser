<?php
declare(strict_types=1);

namespace App\Analyzer;

/**
 * Coletor para Oracle Database 12.2+ (19c, 21c, 23ai). O "banco" escolhido na tela é o schema (owner).
 * Toda consulta filtra pelo owner escolhido, e os schemas mantidos pela Oracle (ORACLE_MAINTAINED = 'Y')
 * nem aparecem na lista. Dentro do schema ainda descartamos objetos gerados pelo próprio banco:
 * lixeira (BIN$), logs de materialized view (MLOG$/RUPD$), Oracle Text (DR$), tabelas aninhadas/secundárias,
 * overflow de IOT e índices de LOB/domínio.
 * Permissões recomendadas: CREATE SESSION + SELECT_CATALOG_ROLE (ou SELECT ANY DICTIONARY).
 */
final class OracleCollector extends Collector
{
    private const TAB_FILTER = "t.table_name NOT LIKE 'BIN$%' AND t.table_name NOT LIKE 'MLOG$%' AND t.table_name NOT LIKE 'RUPD$%'
        AND t.table_name NOT LIKE 'DR$%' AND t.table_name NOT LIKE 'SYS_IOT_%' AND t.table_name NOT LIKE 'SYS_EXPORT_%'
        AND t.table_name NOT LIKE 'AQ$%' AND t.nested = 'NO' AND t.secondary = 'N' AND t.temporary = 'N' AND t.dropped = 'NO'
        AND (t.iot_type IS NULL OR t.iot_type = 'IOT')";

    /** @var array<string, array>|null tabelas de usuário do schema (já sem externas e containers de MV), por nome */
    private ?array $tables = null;

    /** 'dba' com SELECT_CATALOG_ROLE; 'all' quando só enxergamos o que o usuário tem acesso. */
    private string $dict = 'dba';
    private ?int $uptime = null;

    protected function q(string $sql, array $params = []): array
    {
        if (!preg_match('/^\s*(\(\s*)*(SELECT|WITH)\b/i', $sql)) {
            throw new \LogicException('Somente SELECT/WITH são permitidos pelo analisador');
        }
        return parent::q(str_replace('{d}', $this->dict, $sql), $params);
    }

    private bool $dictKnown = false;

    private function detectDict(): void
    {
        if ($this->dictKnown) {
            return;
        }
        $this->dictKnown = true;
        try {
            parent::q('SELECT 1 AS x FROM dba_tables WHERE ROWNUM = 1');
            $this->dict = 'dba';
        } catch (\Throwable) {
            $this->dict = 'all';
        }
    }

    /**
     * Tabelas de usuário do schema. Consultas simples por owner (sem subconsultas correlacionadas no dicionário,
     * que em schemas grandes estouram o timeout); tamanhos, PK e estatísticas são cruzados em PHP.
     */
    private function userTables(): array
    {
        if ($this->tables !== null) {
            return $this->tables;
        }
        $this->detectDict();
        $o = [$this->owner()];
        $rows = $this->q("SELECT t.owner AS schema_name, t.table_name AS name, NVL(t.num_rows, 0) AS num_rows, t.last_analyzed, NVL(t.blocks, 0) AS blocks,
                                 NVL(t.avg_row_len, 0) AS avg_row_len, t.partitioned, t.iot_type
                            FROM {d}_tables t WHERE t.owner = ? AND " . self::TAB_FILTER, $o);
        $skip = [];
        foreach ($this->tryQ('tabelas externas', 'SELECT table_name AS n FROM {d}_external_tables WHERE owner = ?', $o) ?? [] as $r) {
            $skip[$r['n']] = true;
        }
        foreach ($this->tryQ('materialized views', 'SELECT container_name AS n FROM {d}_mviews WHERE owner = ?', $o) ?? [] as $r) {
            $skip[$r['n']] = true;
        }
        $pk = array_flip(array_column($this->q("SELECT table_name AS n FROM {d}_constraints WHERE owner = ? AND constraint_type = 'P'", $o), 'n'));
        $stale = array_column($this->tryQ('estatísticas', "SELECT table_name AS n, stale_stats AS s FROM {d}_tab_statistics WHERE owner = ? AND object_type = 'TABLE'", $o) ?? [], 's', 'n');
        $tseg = $iseg = [];
        if ($this->dict === 'dba') {
            $idxTable = array_column($this->q('SELECT index_name AS i, table_name AS t FROM dba_indexes WHERE owner = ?', $o), 't', 'i');
            foreach ($this->q("SELECT segment_name AS n, segment_type AS t, SUM(bytes) AS b FROM dba_segments WHERE owner = ?
                                 AND (segment_type LIKE 'TABLE%' OR segment_type LIKE 'INDEX%') GROUP BY segment_name, segment_type", $o) as $g) {
                if (str_starts_with($g['t'], 'TABLE')) {
                    $tseg[$g['n']] = ($tseg[$g['n']] ?? 0) + (int) $g['b'];
                } elseif (isset($idxTable[$g['n']])) {
                    $iseg[$idxTable[$g['n']]] = ($iseg[$idxTable[$g['n']]] ?? 0) + (int) $g['b'];
                }
            }
        }
        $out = [];
        foreach ($rows as $r) {
            if (isset($skip[$r['name']])) {
                continue;
            }
            $r['data_bytes'] = $tseg[$r['name']] ?? (int) $r['blocks'] * 8192;
            $r['index_bytes'] = $iseg[$r['name']] ?? 0;
            $r['has_pk'] = isset($pk[$r['name']]);
            $r['stale'] = $stale[$r['name']] ?? null;
            $out[$r['name']] = $r;
        }
        uasort($out, fn($a, $b) => ($b['data_bytes'] + $b['index_bytes']) <=> ($a['data_bytes'] + $a['index_bytes']));
        return $this->tables = $out;
    }

    protected function tableNames(): array
    {
        return array_map(fn($t) => [$t['schema_name'], $t['name']], array_values($this->userTables()));
    }

    private function owner(): string
    {
        return $this->database;
    }

    private static function fq(string $owner, string $name): string
    {
        return self::qi($owner) . '.' . self::qi($name);
    }

    public function connect(): array
    {
        $this->detectDict();
        $banner = $this->tryQ('v$version', "SELECT banner_full AS b FROM v\$version WHERE ROWNUM = 1")
            ?? $this->tryQ('v$version', "SELECT banner AS b FROM v\$version WHERE ROWNUM = 1");
        $inst = $this->tryQ('v$instance', "SELECT version_full AS version, instance_name, host_name, ROUND((SYSDATE - startup_time) * 86400) AS uptime_s,
                    status FROM v\$instance")
            ?? $this->tryQ('v$instance', "SELECT version, instance_name, host_name, ROUND((SYSDATE - startup_time) * 86400) AS uptime_s, status FROM v\$instance");
        $ctx = $this->q("SELECT SYS_CONTEXT('USERENV','SESSION_USER') AS usr, SYS_CONTEXT('USERENV','CON_NAME') AS con,
                                SYS_CONTEXT('USERENV','DB_NAME') AS db FROM dual")[0];
        $size = $this->dict === 'dba'
            ? (int) ($this->q('SELECT NVL(SUM(bytes), 0) AS s FROM dba_segments WHERE owner = ?', [$this->owner()])[0]['s'] ?? 0)
            : (int) ($this->q('SELECT NVL(SUM(blocks), 0) * 8192 AS s FROM all_tables WHERE owner = ?', [$this->owner()])[0]['s'] ?? 0);
        $this->uptime = isset($inst[0]['uptime_s']) ? (int) $inst[0]['uptime_s'] : null;
        $ver = $inst[0]['version'] ?? ($this->pdo instanceof OracleConnection ? $this->pdo->version : '');
        $bannerLine = trim(strtok((string) ($banner[0]['b'] ?? "Oracle $ver"), "\n"));
        $this->log('✔ Handshake OK — ' . $bannerLine . ' (driver thin, sem Instant Client)');
        $this->log("• Container {$ctx['con']} • usuário {$ctx['usr']} • schema analisado {$this->owner()}");
        $this->log('✔ Transação SET TRANSACTION READ ONLY, apenas SELECT, call_timeout ativo');
        if ($this->dict === 'all') {
            $this->log('⚠ Sem SELECT_CATALOG_ROLE: usando visões ALL_* (tamanhos e uso de índices ficam aproximados)');
        }
        $this->log('• Schema ' . $this->owner() . ' — ' . human_bytes($size));

        $dbi = $this->tryQ('v$database', 'SELECT log_mode, force_logging, flashback_on, open_mode, database_role FROM v$database')[0] ?? null;
        if ($dbi && $dbi['log_mode'] === 'NOARCHIVELOG' && ($dbi['database_role'] ?? 'PRIMARY') === 'PRIMARY') {
            $this->finding('high', 'backup', 'Banco em NOARCHIVELOG',
                'Sem archivelog não há backup online nem recuperação até um ponto no tempo: só é possível voltar ao último backup frio.',
                "-- Requer reinício em MOUNT; planeje a janela e o destino dos archives\nSHUTDOWN IMMEDIATE;\nSTARTUP MOUNT;\nALTER DATABASE ARCHIVELOG;\nALTER DATABASE OPEN;");
        }
        $bk = $this->tryQ('v$rman_backup_job_details', "SELECT MAX(end_time) AS last_full, ROUND(SYSDATE - MAX(end_time)) AS age_d FROM v\$rman_backup_job_details
                  WHERE status LIKE 'COMPLETED%' AND input_type IN ('DB FULL','DB INCR')");
        if ($bk && $dbi && ($bk[0]['last_full'] === null || (int) $bk[0]['age_d'] > 7)) {
            $this->finding('high', 'backup', 'Sem backup RMAN do banco nos últimos 7 dias',
                'Último backup registrado no controlfile: ' . ($bk[0]['last_full'] ?: 'nenhum') . '. Se o backup é feito por snapshot de storage, ignore.',
                "-- No RMAN (rman target /):\nBACKUP AS COMPRESSED BACKUPSET DATABASE PLUS ARCHIVELOG;");
        }
        return $this->result([
            'version' => 'Oracle ' . $ver, 'version_full' => (string) $ver, 'banner' => $banner[0]['b'] ?? null, 'db_size' => $size, 'uptime_s' => $this->uptime,
            'user' => $ctx['usr'], 'container' => $ctx['con'], 'instance' => $inst[0] ?? null, 'database' => $dbi, 'dictionary' => $this->dict,
        ], ['db_size' => $size]);
    }

    public function schemas(): array
    {
        $this->detectDict();
        $tables = array_slice($this->userTables(), 0, 2000);

        $fkRows = $this->q("
            SELECT c.constraint_name AS name, c.owner AS schema_name, c.table_name, r.owner AS ref_schema, r.table_name AS ref_table,
                   cc.column_name AS col, cc.position, c.status, c.validated
              FROM {d}_constraints c
              JOIN {d}_constraints r ON r.owner = c.r_owner AND r.constraint_name = c.r_constraint_name
              JOIN {d}_cons_columns cc ON cc.owner = c.owner AND cc.constraint_name = c.constraint_name
             WHERE c.owner = ? AND c.constraint_type = 'R' AND c.table_name NOT LIKE 'BIN$%'
             ORDER BY c.constraint_name, cc.position", [$this->owner()]);
        $fks = [];
        $known = $this->userTables();
        foreach ($fkRows as $r) {
            if (!isset($known[$r['table_name']])) {
                continue;
            }
            $fks[$r['name']] ??= ['name' => $r['name'], 'schema' => $r['schema_name'], 'table_name' => $r['table_name'], 'ref_schema' => $r['ref_schema'],
                'ref_table' => $r['ref_table'], 'columns' => '', 'status' => $r['status'], 'validated' => $r['validated']];
            $fks[$r['name']]['columns'] .= ($fks[$r['name']]['columns'] === '' ? '' : ',') . $r['col'];
        }
        $fks = array_values($fks);
        $this->log('• ' . count($tables) . ' tabelas mapeadas, ' . count($fks) . ' chaves estrangeiras');

        $linked = [];
        foreach ($fks as $fk) {
            $linked[$fk['schema'] . '.' . $fk['table_name']] = $linked[$fk['ref_schema'] . '.' . $fk['ref_table']] = true;
            $tq = self::fq($fk['schema'], $fk['table_name']);
            if ($fk['status'] === 'DISABLED') {
                $this->finding('medium', 'relationships', "FK desabilitada: {$fk['schema']}.{$fk['table_name']}.{$fk['name']}",
                    'A integridade referencial não está sendo garantida: dados órfãos podem existir.',
                    "-- Verifique órfãos antes; VALIDATE lê a tabela inteira\nALTER TABLE $tq ENABLE VALIDATE CONSTRAINT " . self::qi($fk['name']) . ';', "{$fk['schema']}.{$fk['table_name']}");
            } elseif ($fk['validated'] === 'NOT VALIDATED') {
                $this->finding('low', 'relationships', "FK não validada: {$fk['schema']}.{$fk['table_name']}.{$fk['name']}",
                    'Habilitada com NOVALIDATE: linhas antigas podem violar a FK e o otimizador não confia nela.',
                    "ALTER TABLE $tq ENABLE VALIDATE CONSTRAINT " . self::qi($fk['name']) . ';', "{$fk['schema']}.{$fk['table_name']}");
            }
        }

        $out = [];
        $noPk = 0;
        foreach ($tables as $t) {
            $fq = $t['schema_name'] . '.' . $t['name'];
            $tq = self::fq($t['schema_name'], $t['name']);
            $rows = (int) $t['num_rows'];
            $data = (int) $t['data_bytes'];
            $this->log("  ↳ $fq (~" . number_format($rows, 0, ',', '.') . ' linhas, ' . human_bytes($data) . ')');
            if (!$t['has_pk']) {
                $noPk++;
                $this->finding($rows > 10000 ? 'high' : 'medium', 'schema', "Tabela sem chave primária: $fq",
                    'Sem PK não há identificação única das linhas: duplicidades passam e GoldenGate/replicação lógica ficam caros (supplemental logging de todas as colunas).',
                    "-- Avalie a coluna candidata antes de aplicar (IDENTITY exige 12c+)\nALTER TABLE $tq ADD (id NUMBER GENERATED BY DEFAULT AS IDENTITY);\nALTER TABLE $tq ADD CONSTRAINT " . self::qi(substr('PK_' . $t['name'], 0, 128)) . ' PRIMARY KEY (id) USING INDEX ONLINE;', $fq);
            }
            $analyzed = $t['last_analyzed'] !== null;
            if (!$analyzed && $data > 10 * 1024 ** 2) {
                $this->finding('medium', 'statistics', "Estatísticas nunca coletadas em $fq", 'O otimizador usa amostragem dinâmica a cada parse e pode escolher planos ruins.',
                    "BEGIN DBMS_STATS.GATHER_TABLE_STATS(ownname => '" . str_replace("'", "''", $t['schema_name']) . "', tabname => '" . str_replace("'", "''", $t['name']) . "', cascade => TRUE); END;", $fq);
            } elseif ($t['stale'] === 'YES' && $rows > 50000) {
                $this->finding('medium', 'statistics', "Estatísticas desatualizadas (STALE) em $fq", 'Mais de 10% das linhas mudaram desde a última coleta.',
                    "BEGIN DBMS_STATS.GATHER_TABLE_STATS(ownname => '" . str_replace("'", "''", $t['schema_name']) . "', tabname => '" . str_replace("'", "''", $t['name']) . "', cascade => TRUE); END;", $fq);
            }
            // Espaço alocado muito acima do necessário (deleções em massa / HWM alta)
            $need = $rows * (int) $t['avg_row_len'];
            $alloc = (int) $t['blocks'] * 8192;
            if ($analyzed && $alloc > 256 * 1024 ** 2 && $need < $alloc * 0.4 && $t['iot_type'] === null) {
                $pct = round((1 - $need / $alloc) * 100, 1);
                $this->finding('medium', 'bloat', "Espaço desperdiçado em $fq (~$pct%)",
                    human_bytes($alloc) . ' abaixo da high water mark para ~' . human_bytes($need) . ' de dados. Full scans leem os blocos vazios.',
                    "-- 12.2+: reorganização online (reconstrói índices)\nALTER TABLE $tq MOVE ONLINE;\n-- alternativa: ALTER TABLE $tq ENABLE ROW MOVEMENT; ALTER TABLE $tq SHRINK SPACE CASCADE;", $fq);
            }
            $out[] = [
                'schema' => $t['schema_name'], 'name' => $t['name'], 'rows' => $rows, 'data_bytes' => $data, 'index_bytes' => (int) $t['index_bytes'],
                'has_pk' => $t['has_pk'], 'last_analyzed' => $t['last_analyzed'], 'stale_stats' => $t['stale'] === 'YES',
                'partitioned' => $t['partitioned'] === 'YES', 'isolated' => !isset($linked[$fq]),
            ];
        }

        // Objetos inválidos do schema (views, procedures, packages, triggers)
        $invalid = $this->tryQ('objetos inválidos', "SELECT object_type AS type, object_name AS name FROM {d}_objects
                 WHERE owner = ? AND status = 'INVALID' AND object_name NOT LIKE 'BIN$%' AND ROWNUM <= 100 ORDER BY object_type, object_name", [$this->owner()]) ?? [];
        foreach ($invalid as $o) {
            $kw = match ($o['type']) {
                'PACKAGE BODY' => ['PACKAGE', ' COMPILE BODY'], 'TYPE BODY' => ['TYPE', ' COMPILE BODY'],
                'VIEW', 'PROCEDURE', 'FUNCTION', 'PACKAGE', 'TRIGGER', 'TYPE', 'SYNONYM', 'MATERIALIZED VIEW' => [$o['type'], ' COMPILE'],
                default => null,
            };
            $this->finding('medium', 'schema', "Objeto inválido: {$o['type']} {$this->owner()}.{$o['name']}",
                'Chamadas a este objeto falham ou forçam recompilação em tempo de execução.',
                $kw ? "ALTER {$kw[0]} " . self::fq($this->owner(), $o['name']) . "{$kw[1]};" : null, "{$this->owner()}.{$o['name']}");
        }

        $smells = $this->tryQ('tipos de dados', "
            SELECT c.owner AS schema_name, c.table_name, c.column_name AS col, c.data_type AS type, c.data_precision, c.data_scale
              FROM {d}_tab_columns c
             WHERE c.owner = ?
               AND ( c.data_type IN ('LONG','LONG RAW')
                  OR (c.data_type IN ('FLOAT','BINARY_FLOAT','BINARY_DOUBLE') AND REGEXP_LIKE(c.column_name, '(PRICE|PRECO|VALOR|AMOUNT|TOTAL|SALDO)', 'i'))
                  OR (REGEXP_LIKE(c.column_name, '(_ID|^ID)$', 'i') AND c.data_type IN ('VARCHAR2','NVARCHAR2','CHAR','NCHAR')) )
               AND ROWNUM <= 400", [$this->owner()]) ?? [];
        $smells = array_values(array_filter($smells, fn($x) => isset($known[$x['table_name']])));
        foreach ($smells as $s) {
            $fq = "{$s['schema_name']}.{$s['table_name']}.{$s['col']}";
            [$why, $fix] = match (true) {
                $s['type'] === 'LONG' => ['LONG é obsoleto: uma por tabela, sem funções de string, bloqueia ALTER TABLE MOVE e redefinição online.', 'CLOB'],
                $s['type'] === 'LONG RAW' => ['LONG RAW é obsoleto: use BLOB.', 'BLOB'],
                str_contains($s['type'], 'FLOAT') || str_contains($s['type'], 'DOUBLE') => ['Ponto flutuante binário para valores monetários causa erros de arredondamento.', 'NUMBER(14,2)'],
                default => ['Identificador armazenado como texto: maior e mais lento em JOINs e índices.', 'NUMBER(19)'],
            };
            $sql = str_starts_with($s['type'], 'LONG')
                ? 'ALTER TABLE ' . self::fq($s['schema_name'], $s['table_name']) . ' MODIFY (' . self::qi($s['col']) . " $fix); -- reescreve a tabela e invalida índices"
                : '-- Converter tipo com dados exige coluna nova + cópia ou DBMS_REDEFINITION; planeje a janela';
            $this->finding('low', 'types', "Tipo inadequado: $fq ({$s['type']})", $why, $sql, $fq);
        }

        return $this->result(['tables' => $out, 'foreign_keys' => $fks, 'type_smells' => $smells, 'invalid_objects' => $invalid],
            ['tables' => count($out), 'fks' => count($fks), 'no_pk' => $noPk, 'rows' => array_sum(array_column($out, 'rows'))]);
    }

    public function indexes(): array
    {
        $this->detectDict();
        $known = $this->userTables();
        $iseg = [];
        if ($this->dict === 'dba') {
            $iseg = array_column($this->q("SELECT segment_name AS n, SUM(bytes) AS b FROM dba_segments WHERE owner = ? AND segment_type LIKE 'INDEX%' GROUP BY segment_name", [$this->owner()]), 'b', 'n');
        }
        $cons = [];
        foreach ($this->q("SELECT index_name AS i, constraint_type AS t FROM {d}_constraints WHERE owner = ? AND constraint_type IN ('P','U') AND index_name IS NOT NULL", [$this->owner()]) as $r) {
            $cons[$r['i']] = ($cons[$r['i']] ?? '') === 'P' ? 'P' : $r['t'];
        }
        $rows = $this->q("
            SELECT i.owner AS schema_name, i.table_name, i.index_name AS name, i.index_type AS type, i.uniqueness, i.status, i.visibility,
                   i.partitioned, NVL(i.leaf_blocks, 0) * 8192 AS est_bytes, ic.column_name AS col, ic.column_position AS pos, ic.descend
              FROM {d}_indexes i
              JOIN {d}_ind_columns ic ON ic.index_owner = i.owner AND ic.index_name = i.index_name
             WHERE i.table_owner = ? AND i.owner = i.table_owner AND i.index_type IN ('NORMAL','NORMAL/REV','BITMAP','FUNCTION-BASED NORMAL','FUNCTION-BASED BITMAP')
               AND i.index_name NOT LIKE 'BIN$%'
             ORDER BY i.table_name, i.index_name, ic.column_position", [$this->owner()]);
        $idx = [];
        foreach ($rows as $r) {
            if (!isset($known[$r['table_name']])) {
                continue;
            }
            $r['backs'] = $cons[$r['name']] ?? null;
            $r['bytes'] = $iseg[$r['name']] ?? $r['est_bytes'];
            $k = $r['schema_name'] . '.' . $r['name'];
            $idx[$k] ??= ['schema' => $r['schema_name'], 'table' => $r['table_name'], 'name' => $r['name'], 'type' => $r['type'],
                'unique' => $r['uniqueness'] === 'UNIQUE', 'primary' => $r['backs'] === 'P', 'constraint' => $r['backs'] !== null,
                'status' => $r['status'], 'visible' => $r['visibility'] !== 'INVISIBLE', 'partitioned' => $r['partitioned'] === 'YES',
                'bytes' => (int) $r['bytes'], 'cols' => [], 'scans' => null];
            $idx[$k]['cols'][] = $r['col'] . ($r['descend'] === 'DESC' ? ' DESC' : '');
        }
        $this->log('• ' . count($idx) . ' índices encontrados');

        // Uso de índices (DBA_INDEX_USAGE, 12.2+, rastreamento por amostragem habilitado por padrão)
        $usage = $this->dict === 'dba'
            ? $this->tryQ('dba_index_usage', 'SELECT owner, name, total_access_count AS n, last_used FROM dba_index_usage WHERE owner = ?', [$this->owner()])
            : null;
        foreach ($usage ?? [] as $u) {
            if (isset($idx[$u['owner'] . '.' . $u['name']])) {
                $idx[$u['owner'] . '.' . $u['name']]['scans'] = (int) $u['n'];
            }
        }
        if ($usage !== null) {
            foreach ($idx as &$i) {
                $i['scans'] ??= 0;
            }
            unset($i);
        }

        $byTable = [];
        foreach ($idx as $i) {
            $byTable[$i['table']][] = $i;
        }
        $dups = 0;
        $flagged = [];
        $isPlain = fn(array $i) => in_array($i['type'], ['NORMAL', 'NORMAL/REV'], true);
        foreach ($byTable as $list) {
            foreach ($list as $a) {
                if ($a['unique'] || $a['constraint'] || !$isPlain($a) || isset($flagged[$a['name']])) {
                    continue;
                }
                foreach ($list as $b) {
                    if ($a['name'] === $b['name'] || isset($flagged[$b['name']]) || !$isPlain($b)) {
                        continue;
                    }
                    $ka = implode(',', $a['cols']);
                    $kb = implode(',', $b['cols']);
                    $isDup = $ka === $kb && ($b['unique'] || $b['constraint'] || strcmp($a['name'], $b['name']) > 0);
                    $isPrefix = $ka !== $kb && str_starts_with($kb . ',', $ka . ',');
                    if ($isDup || $isPrefix) {
                        $dups++;
                        $flagged[$a['name']] = true;
                        $this->finding($isDup ? 'high' : 'medium', 'indexes', ($isDup ? 'Índice duplicado' : 'Índice redundante') . ": {$a['schema']}.{$a['name']} ($ka)",
                            ($isDup ? 'Idêntico a ' : 'Suas colunas são prefixo de ') . "{$b['name']} ($kb). Consome " . human_bytes($a['bytes']) . ' e custo extra em cada escrita.',
                            '-- Teste antes tornando invisível: ALTER INDEX ' . self::fq($a['schema'], $a['name']) . " INVISIBLE;\nDROP INDEX " . self::fq($a['schema'], $a['name']) . ' ONLINE;',
                            "{$a['schema']}.{$a['name']}");
                        break;
                    }
                }
            }
        }

        $unused = [];
        foreach ($idx as $i) {
            if ($i['status'] === 'UNUSABLE') {
                $this->finding('high', 'indexes', "Índice UNUSABLE: {$i['schema']}.{$i['name']}",
                    'O otimizador ignora o índice e, se for de constraint UNIQUE, DML na tabela falha. Costuma sobrar de MOVE/SPLIT de partição.',
                    'ALTER INDEX ' . self::fq($i['schema'], $i['name']) . ' REBUILD ONLINE;', "{$i['schema']}.{$i['table']}");
            }
            if ($i['scans'] === 0 && !$i['unique'] && !$i['constraint'] && $i['visible']) {
                $unused[] = $i;
                if ($i['bytes'] >= 1024 * 1024 && ($this->uptime ?? 0) > 7 * 86400 && !isset($flagged[$i['name']])) {
                    $this->finding('medium', 'indexes', "Índice sem uso registrado: {$i['schema']}.{$i['name']}",
                        'Não aparece em DBA_INDEX_USAGE (rastreamento por amostragem). Ocupa ' . human_bytes($i['bytes']) . '. Torne invisível e observe um ciclo completo (mês/fechamento) antes de remover.',
                        'ALTER INDEX ' . self::fq($i['schema'], $i['name']) . " INVISIBLE;\n-- após o período de observação: DROP INDEX " . self::fq($i['schema'], $i['name']) . ' ONLINE;', "{$i['schema']}.{$i['table']}");
                }
            }
        }

        // FKs sem índice (no Oracle, DELETE/UPDATE da PK pai trava a tabela filha inteira com lock TM)
        $fkRows = $this->q("
            SELECT c.constraint_name AS fk, c.table_name, cc.column_name AS col
              FROM {d}_constraints c JOIN {d}_cons_columns cc ON cc.owner = c.owner AND cc.constraint_name = c.constraint_name
             WHERE c.owner = ? AND c.constraint_type = 'R'
             ORDER BY c.constraint_name, cc.position", [$this->owner()]);
        $fkCols = [];
        foreach ($fkRows as $r) {
            if (!isset($known[$r['table_name']])) {
                continue;
            }
            $fkCols[$r['fk']] ??= ['fk' => $r['fk'], 'table_name' => $r['table_name'], 'rows' => (int) $known[$r['table_name']]['num_rows'], 'cols' => []];
            $fkCols[$r['fk']]['cols'][] = $r['col'];
        }
        $fkNoIdx = [];
        foreach ($fkCols as $f) {
            $covered = false;
            foreach ($byTable[$f['table_name']] ?? [] as $i) {
                $lead = array_map(fn($c) => preg_replace('/ DESC$/', '', $c), array_slice($i['cols'], 0, count($f['cols'])));
                if (count($lead) === count($f['cols']) && !array_diff($f['cols'], $lead)) {
                    $covered = true;
                    break;
                }
            }
            if (!$covered) {
                $cols = implode(', ', $f['cols']);
                $fkNoIdx[] = ['schema' => $this->owner(), 'table_name' => $f['table_name'], 'fk' => $f['fk'], 'cols' => $cols, 'rows' => $f['rows']];
                $name = substr('IX_' . $f['table_name'] . '_' . implode('_', $f['cols']), 0, 128);
                $this->finding($f['rows'] > 10000 ? 'high' : 'medium', 'relationships', "FK sem índice: {$this->owner()}.{$f['table_name']} ($cols)",
                    "A constraint {$f['fk']} não tem índice: DELETE/UPDATE da chave na tabela pai adquire lock na tabela filha inteira e varre a tabela.",
                    'CREATE INDEX ' . self::fq($this->owner(), $name) . ' ON ' . self::fq($this->owner(), $f['table_name']) . ' (' . implode(', ', array_map([self::class, 'qi'], $f['cols'])) . ') ONLINE;',
                    "{$this->owner()}.{$f['table_name']}");
            }
        }

        $list = array_map(fn($i) => [
            'schema' => $i['schema'], 'table' => $i['table'], 'name' => $i['name'], 'bytes' => $i['bytes'], 'scans' => (int) ($i['scans'] ?? 0),
            'unique' => $i['unique'], 'primary' => $i['primary'], 'def' => ($i['unique'] ? 'UNIQUE ' : '') . $i['type'] . ' (' . implode(', ', $i['cols']) . ')'
                . ($i['visible'] ? '' : ' INVISIBLE') . ($i['status'] === 'UNUSABLE' ? ' UNUSABLE' : ''),
        ], array_values($idx));
        usort($list, fn($a, $b) => $b['bytes'] <=> $a['bytes']);
        return $this->result(['indexes' => array_slice($list, 0, 500), 'unused' => count($unused), 'duplicates' => $dups, 'fk_without_index' => $fkNoIdx],
            ['indexes' => count($idx), 'unused' => count($unused), 'fk_no_idx' => count($fkNoIdx)]);
    }

    public function queries(): array
    {
        $top = $this->tryQ('v$sqlarea', "
            SELECT * FROM (
              SELECT sql_id, SUBSTR(sql_text, 1, 1000) AS query, executions AS calls, ROUND(elapsed_time / 1000, 1) AS total_ms,
                     ROUND(elapsed_time / 1000 / NULLIF(executions, 0), 2) AS mean_ms, buffer_gets, disk_reads, rows_processed AS num_rows
                FROM v\$sqlarea
               WHERE parsing_schema_name = ? AND command_type IN (2, 3, 6, 7, 47, 189)
               ORDER BY elapsed_time DESC)
             WHERE ROWNUM <= 15", [$this->owner()]);
        if ($top !== null) {
            $this->log('✔ v$sqlarea: ' . count($top) . ' instruções mais custosas do schema');
        }
        foreach ($top ?? [] as $t) {
            if ((float) $t['mean_ms'] > 500) {
                $this->finding('high', 'queries', 'SQL lento (média ' . $t['mean_ms'] . ' ms, ' . $t['calls'] . ' execuções, sql_id ' . $t['sql_id'] . ')',
                    mb_substr(preg_replace('/\s+/', ' ', (string) $t['query']), 0, 400) . "\nBuffer gets: " . $t['buffer_gets'],
                    "SELECT * FROM TABLE(DBMS_XPLAN.DISPLAY_CURSOR('{$t['sql_id']}', NULL, 'ALLSTATS LAST +PEEKED_BINDS'));\n-- Diagnóstico guiado (licença Tuning Pack): DBMS_SQLTUNE.CREATE_TUNING_TASK(sql_id => '{$t['sql_id']}')");
            }
        }

        $act = $this->tryQ('v$session', "
            SELECT * FROM (
              SELECT s.sid AS pid, s.serial# AS serial, s.username AS usename, s.status AS state, s.event AS wait_event, s.blocking_session AS blocked_by,
                     s.last_call_et AS query_s, CASE WHEN s.taddr IS NOT NULL THEN 1 ELSE 0 END AS in_tx, s.machine AS client, s.program AS app,
                     (SELECT SUBSTR(q.sql_text, 1, 500) FROM v\$sql q WHERE q.sql_id = NVL(s.sql_id, s.prev_sql_id) AND ROWNUM = 1) AS query
                FROM v\$session s
               WHERE s.type = 'USER' AND (s.schemaname = ? OR s.username = ?) AND s.sid <> SYS_CONTEXT('USERENV', 'SID')
                 AND ((s.status = 'ACTIVE' AND s.last_call_et > 30) OR (s.status = 'INACTIVE' AND s.taddr IS NOT NULL) OR s.blocking_session IS NOT NULL)
               ORDER BY s.last_call_et DESC)
             WHERE ROWNUM <= 30", [$this->owner(), $this->owner()]) ?? [];
        $blocked = 0;
        foreach ($act as $a) {
            if ($a['blocked_by'] !== null) {
                $blocked++;
            }
            if ($a['state'] === 'INACTIVE' && (int) $a['in_tx'] && (int) $a['query_s'] > 60) {
                $this->finding('high', 'locks', "Transação aberta e ociosa há {$a['query_s']}s (sid {$a['pid']}, {$a['app']})",
                    'A sessão tem transação ativa sem COMMIT/ROLLBACK: segura locks de linha e gera undo crescente.',
                    "-- Confirme com o dono da aplicação antes\nALTER SYSTEM KILL SESSION '{$a['pid']},{$a['serial']}' IMMEDIATE;");
            }
        }
        if ($blocked > 0) {
            $this->finding('medium', 'locks', "$blocked sessões bloqueadas no momento da coleta", 'Investigue a cadeia em v$session.blocking_session / final_blocking_session.',
                "SELECT sid, serial#, blocking_session, final_blocking_session, event, seconds_in_wait FROM v\$session WHERE blocking_session IS NOT NULL;");
        }
        $this->log('• ' . count($act) . ' sessões longas/ociosas, ' . $blocked . ' bloqueadas');
        return $this->result(['top_queries' => $top ?? [], 'activity' => $act, 'locks_waiting' => $blocked],
            ['queries' => count($top ?? []), 'long_sessions' => count($act), 'locks' => $blocked]);
    }

    public function sizing(): array
    {
        $names = ['sga_target', 'sga_max_size', 'pga_aggregate_target', 'pga_aggregate_limit', 'memory_target', 'memory_max_target', 'db_cache_size',
            'shared_pool_size', 'processes', 'sessions', 'open_cursors', 'cpu_count', 'parallel_max_servers', 'optimizer_mode', 'cursor_sharing',
            'statistics_level', 'db_block_size', 'filesystemio_options', 'use_large_pages', 'undo_retention', 'db_file_multiblock_read_count', 'inmemory_size'];
        $settings = [];
        $rows = $this->tryQ('v$parameter', 'SELECT name, value, type, isdefault FROM v$parameter WHERE name IN (' . implode(',', array_fill(0, count($names), '?')) . ')', $names) ?? [];
        $bytesParams = ['sga_target', 'sga_max_size', 'pga_aggregate_target', 'pga_aggregate_limit', 'memory_target', 'memory_max_target', 'db_cache_size', 'shared_pool_size', 'inmemory_size'];
        foreach ($rows as $r) {
            $settings[$r['name']] = ['value' => (string) $r['value'], 'bytes' => in_array($r['name'], $bytesParams, true) && is_numeric($r['value']) ? (int) $r['value'] : null];
            $this->log("  ↳ {$r['name']} = {$r['value']}");
        }
        $st = [];
        foreach ($this->tryQ('v$sysstat', "SELECT name, value FROM v\$sysstat WHERE name IN ('physical reads cache','db block gets from cache','consistent gets from cache',
                    'enqueue deadlocks','user commits','user rollbacks','sorts (disk)','sorts (memory)','parse count (hard)','parse count (total)')") ?? [] as $r) {
            $st[$r['name']] = (float) $r['value'];
        }
        $logical = ($st['db block gets from cache'] ?? 0) + ($st['consistent gets from cache'] ?? 0);
        $hit = $logical > 0 ? round((1 - ($st['physical reads cache'] ?? 0) / $logical) * 100, 2) : null;
        $sessions = (int) ($this->tryQ('v$session', "SELECT COUNT(*) AS c FROM v\$session WHERE type = 'USER'")[0]['c'] ?? 0);
        $pga = $this->tryQ('v$pgastat', "SELECT name, value FROM v\$pgastat WHERE name IN ('maximum PGA allocated','total PGA allocated','over allocation count')") ?? [];
        $pgaMap = array_column($pga, 'value', 'name');
        $hard = $st['parse count (hard)'] ?? 0;
        $parses = $st['parse count (total)'] ?? 0;
        $metrics = [
            'cache_hit_ratio' => $hit, 'connections' => $sessions, 'max_connections' => (int) ($settings['sessions']['value'] ?? 0),
            'deadlocks' => (int) ($st['enqueue deadlocks'] ?? 0), 'hard_parse_pct' => $parses > 0 ? round($hard * 100 / $parses, 2) : null,
            'disk_sorts' => (int) ($st['sorts (disk)'] ?? 0), 'pga_max_allocated' => isset($pgaMap['maximum PGA allocated']) ? (int) $pgaMap['maximum PGA allocated'] : null,
            'pga_over_allocation' => isset($pgaMap['over allocation count']) ? (int) $pgaMap['over allocation count'] : null, 'uptime_s' => $this->uptime,
            'rollback_ratio' => (($st['user commits'] ?? 0) + ($st['user rollbacks'] ?? 0)) > 0 ? round(($st['user rollbacks'] ?? 0) * 100 / (($st['user commits'] ?? 0) + ($st['user rollbacks'] ?? 0)), 2) : 0,
        ];
        $this->log('✔ Buffer cache hit: ' . ($hit ?? 'n/d') . "% • sessões $sessions/" . ($metrics['max_connections'] ?: 'n/d') . ' • hard parse ' . ($metrics['hard_parse_pct'] ?? 'n/d') . '%');

        if ($hit !== null && $hit < 95) {
            $this->finding($hit < 90 ? 'high' : 'medium', 'sizing', "Buffer cache hit ratio baixo ($hit%)", 'Muita leitura física: avalie o tamanho da SGA (db_cache) e as queries com mais disk_reads.');
        }
        if (($metrics['hard_parse_pct'] ?? 0) > 20 && $parses > 100000) {
            $this->finding('medium', 'queries', "Hard parse elevado ({$metrics['hard_parse_pct']}% dos parses)",
                'A aplicação provavelmente concatena literais em vez de usar bind variables: CPU gasta em parse e contenção no shared pool.',
                "-- Corrija na aplicação (bind variables). Paliativo, teste antes:\nALTER SYSTEM SET cursor_sharing = FORCE SCOPE = BOTH;");
        }
        if (($metrics['pga_over_allocation'] ?? 0) > 0) {
            $this->finding('medium', 'sizing', 'PGA acima do alvo (over allocation count > 0)', 'pga_aggregate_target é pequeno para a carga: ordenações e hash joins vão para o temp.');
        }
        if (($settings['statistics_level']['value'] ?? '') === 'BASIC') {
            $this->finding('medium', 'observability', 'statistics_level = BASIC', 'Desliga advisors, coleta automática de estatísticas e métricas de tempo.',
                "ALTER SYSTEM SET statistics_level = TYPICAL SCOPE = BOTH;");
        }
        if ((int) ($settings['memory_target']['value'] ?? 0) > 0 && ($settings['use_large_pages']['value'] ?? '') !== 'FALSE') {
            $this->finding('low', 'config', 'memory_target (AMM) em uso',
                'No Linux, AMM é incompatível com HugePages: com SGA grande, prefira ASMM (sga_target + pga_aggregate_target) e HugePages.',
                "-- Valores conforme o veredito de dimensionamento; requer restart\nALTER SYSTEM SET memory_target = 0 SCOPE = SPFILE;\nALTER SYSTEM SET sga_target = <valor> SCOPE = SPFILE;\nALTER SYSTEM SET pga_aggregate_target = <valor> SCOPE = SPFILE;");
        }
        if ($metrics['max_connections'] > 0 && $sessions / $metrics['max_connections'] > 0.85) {
            $this->finding('high', 'sizing', 'Sessões próximas do limite', "$sessions de {$metrics['max_connections']} sessões. Revise o pool de conexões da aplicação ou aumente processes/sessions.");
        }
        if ($metrics['deadlocks'] > 0) {
            $this->finding('medium', 'locks', "{$metrics['deadlocks']} deadlocks desde o startup", 'O alert log registra o grafo (ORA-00060): padronize a ordem de acesso e indexe as FKs.');
        }
        return $this->result(['settings' => $settings, 'stats' => $metrics], ['hit' => $hit, 'conns' => $sessions]);
    }
}
