<?php
declare(strict_types=1);

namespace App\Analyzer;

use App\Ai\AiClient;
use App\Core\{Audit, Config, Crypto, Database};

/**
 * Executa uma análise inteira no servidor, fora da requisição web (bin/console analysis:run ID).
 *
 * O progresso vai para analyses.progress_json como uma fila de eventos numerados (seq): o navegador só acompanha,
 * pode sair e voltar, e várias abas podem assistir à mesma análise. As credenciais do alvo ficam em secrets_enc
 * (cifradas com a app_key) apenas enquanto a análise roda.
 */
final class Runner
{
    public const STAGES = [
        'connect' => 'Conectando',
        'schemas' => 'Mapeando Schemas',
        'indexes' => 'Analisando Índices',
        'queries' => 'Avaliando Queries',
        'sizing'  => 'Checando Hardware/Buffers',
        'os'      => 'Coletando SO via SSH',
        'vulns'   => 'Checando Vulnerabilidades',
        'ai'      => 'Consultando IA',
        'report'  => 'Gerando Laudo Técnico',
    ];

    /** Peso de cada etapa no percentual e duração típica (s), para o progresso andar de forma suave na etapa corrente. */
    private const WEIGHT = ['connect' => 4, 'schemas' => 12, 'indexes' => 11, 'queries' => 11, 'sizing' => 8, 'os' => 8, 'vulns' => 5, 'ai' => 36, 'report' => 5];
    private const EXPECT = ['connect' => 3, 'schemas' => 8, 'indexes' => 6, 'queries' => 6, 'sizing' => 4, 'os' => 12, 'vulns' => 2, 'ai' => 90, 'report' => 1];

    /** Um runner sem batimento há mais que isso é considerado morto e a análise pode ser retomada. */
    public const STALE_SECONDS = 600;
    private const MAX_EVENTS = 600;

    private array $a;
    private array $p;
    private array $secrets;
    private array $user;
    private bool $cancelNow = false;

    private function __construct(array $a)
    {
        $this->a = $a;
        $this->p = self::progress($a);
        $this->secrets = json_decode((string) Crypto::decrypt($a['secrets_enc'] ?? null), true) ?: [];
        $this->user = Database::one('SELECT * FROM users WHERE id = ?', [$a['user_id']]) ?? ['id' => $a['user_id'], 'username' => '?'];
    }

    /* ------------------------------------------------------------------ */
    /* Fila / estado                                                       */
    /* ------------------------------------------------------------------ */

    /** Cria a análise na fila. As credenciais (já decifradas) são recifradas num único blob. */
    public static function enqueue(array $user, array $conn, string $db, array $hw, ?array $ssh): int
    {
        $p = ['seq' => 0, 'stages' => array_map(fn() => ['state' => 'pending'], self::STAGES), 'counters' => [], 'events' => [], 'graph' => null];
        return Database::insert('analyses', [
            'user_id' => $user['id'], 'engine' => $conn['engine'], 'host' => $conn['host'], 'port' => $conn['port'],
            'database_name' => $db, 'hardware_json' => json_encode($hw), 'metrics_json' => '{}', 'findings_json' => '[]',
            'secrets_enc' => Crypto::encrypt(json_encode(['conn' => $conn, 'ssh' => $ssh])),
            'progress_json' => json_encode($p), 'current_stage' => 'connect',
        ]);
    }

    public static function progress(array $a): array
    {
        $p = json_decode((string) ($a['progress_json'] ?? ''), true) ?: [];
        $p += ['seq' => 0, 'stages' => [], 'counters' => [], 'events' => [], 'graph' => null];
        foreach (self::STAGES as $k => $_) {
            $p['stages'][$k] ??= ['state' => 'pending'];
        }
        return $p;
    }

    /** Percentual (0–100) ponderado pelas etapas, com avanço suave dentro da etapa corrente. */
    public static function percent(array $a, ?array $p = null): int
    {
        if ($a['status'] === 'done') {
            return 100;
        }
        $p ??= self::progress($a);
        $done = 0.0;
        foreach (self::STAGES as $k => $_) {
            $st = $p['stages'][$k] ?? [];
            if (in_array($st['state'] ?? '', ['done', 'skipped'], true)) {
                $done += self::WEIGHT[$k];
            } elseif (($st['state'] ?? '') === 'running' && !empty($st['t0'])) {
                $el = max(0, microtime(true) - (float) $st['t0']);
                $done += self::WEIGHT[$k] * 0.92 * (1 - exp(-$el / self::EXPECT[$k]));
            }
        }
        return (int) min(99, floor($done));
    }

    /** Resumo para a interface (lista, painel, barra lateral). */
    public static function summary(array $a): array
    {
        $p = self::progress($a);
        $stage = $a['current_stage'] ?: 'connect';
        $t0 = $p['stages'][$stage]['t0'] ?? null;
        return [
            'id' => (int) $a['id'], 'status' => $a['status'], 'engine' => $a['engine'], 'host' => $a['host'], 'database' => $a['database_name'],
            'stage' => $stage, 'stage_label' => self::STAGES[$stage] ?? $stage, 'percent' => self::percent($a, $p),
            'stage_elapsed' => $t0 ? (int) (microtime(true) - (float) $t0) : 0,
            'queued' => empty($a['worker_pid']) && !array_filter($p['stages'], fn($s) => $s['state'] !== 'pending'),
            'cancelling' => (int) ($a['cancel_requested'] ?? 0) === 1,
            'stale' => self::isStale($a),
        ];
    }

    public static function isStale(array $a): bool
    {
        if ($a['status'] !== 'running' || empty($a['worker_pid'])) {
            return false;
        }
        $hb = strtotime(($a['heartbeat_at'] ?? '') . ' UTC') ?: 0;
        if (time() - $hb > self::STALE_SECONDS) {
            return true;
        }
        // Mesmo host: processo inexistente e sem batimento recente
        return function_exists('posix_kill') && time() - $hb > 20 && !@posix_kill((int) $a['worker_pid'], 0);
    }

    /* ------------------------------------------------------------------ */
    /* Despacho                                                            */
    /* ------------------------------------------------------------------ */

    /** O serviço db-analyzer-worker está vivo? (batimento gravado a cada ciclo) */
    public static function workerAlive(): bool
    {
        $hb = (string) Database::value("SELECT value FROM settings WHERE key = 'worker_heartbeat'");
        return $hb !== '' && time() - (int) $hb < 15;
    }

    /** Dispara o runner como processo separado, desacoplado da requisição/worker que o criou. */
    public static function spawn(int $id): bool
    {
        $php = is_executable(PHP_BINDIR . '/php') ? PHP_BINDIR . '/php' : 'php';
        $cmd = escapeshellarg($php) . ' ' . escapeshellarg(APP_ROOT . '/bin/console') . ' analysis:run ' . $id;
        $cmd = (is_executable('/usr/bin/setsid') ? '/usr/bin/setsid ' : '') . $cmd . ' > /dev/null 2>&1 &';
        if (!function_exists('exec')) {
            return false;
        }
        @exec($cmd, $o, $rc);
        return $rc === 0;
    }

    /** Usado pela requisição web: entrega ao worker se ele estiver vivo; senão dispara o runner diretamente. */
    public static function dispatch(int $id): void
    {
        if (!self::workerAlive()) {
            self::spawn($id);
        }
    }

    /** Ciclo do worker: lança runners para análises na fila ou órfãs. Retorna quantas foram lançadas. */
    public static function tick(int $maxConcurrent): int
    {
        Database::exec("INSERT INTO settings(key, value, updated_at) VALUES ('worker_heartbeat', ?, datetime('now'))
                        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at", [(string) time()]);
        $rows = Database::all("SELECT * FROM analyses WHERE status = 'running' ORDER BY id");
        $active = 0;
        $todo = [];
        foreach ($rows as $a) {
            if (!empty($a['worker_pid']) && !self::isStale($a)) {
                $active++;
            } else {
                $todo[] = $a;
            }
        }
        $n = 0;
        foreach ($todo as $a) {
            if ($active + $n >= $maxConcurrent) {
                break;
            }
            if (self::spawn((int) $a['id'])) {
                $n++;
            }
        }
        return $n;
    }

    /* ------------------------------------------------------------------ */
    /* Execução                                                            */
    /* ------------------------------------------------------------------ */

    /** Ponto de entrada do processo runner. Retorna o código de saída. */
    public static function run(int $id): int
    {
        // Reivindica a análise de forma atômica: só um runner por análise
        $claimed = Database::exec("UPDATE analyses SET worker_pid = :pid, heartbeat_at = datetime('now')
                                    WHERE id = :id AND status = 'running'
                                      AND (worker_pid IS NULL OR heartbeat_at IS NULL OR heartbeat_at < datetime('now', :stale))",
            ['pid' => getmypid(), 'id' => $id, 'stale' => '-' . self::STALE_SECONDS . ' seconds']);
        if (!$claimed) {
            $a = Database::one('SELECT * FROM analyses WHERE id = ?', [$id]);
            if (!$a || !self::isStale($a)) {
                return 0; // outro runner cuida dela (ou já terminou)
            }
            $claimed = Database::exec("UPDATE analyses SET worker_pid = ?, heartbeat_at = datetime('now') WHERE id = ? AND worker_pid = ? AND status = 'running'",
                [getmypid(), $id, $a['worker_pid']]);
            if (!$claimed) {
                return 0;
            }
        }
        $a = Database::one('SELECT * FROM analyses WHERE id = ?', [$id]);
        return (new self($a))->execute();
    }

    private function execute(): int
    {
        $id = (int) $this->a['id'];
        if (!$this->secrets || empty($this->secrets['conn'])) {
            $this->fail('connect', 'Credenciais da análise indisponíveis (expiradas ou app_key trocada). Refaça a análise.');
            return 1;
        }
        $resumed = (bool) array_filter($this->p['stages'], fn($s) => $s['state'] !== 'pending');
        if ($resumed) {
            $this->emit(['k' => 'log', 't' => '• Runner retomou a análise no servidor (processo anterior interrompido).']);
        }
        foreach (self::STAGES as $stage => $label) {
            if (in_array($this->p['stages'][$stage]['state'], ['done', 'skipped'], true)) {
                continue;
            }
            $this->reload();
            if ((int) $this->a['cancel_requested'] === 1) {
                $this->cancel($stage);
                return 0;
            }
            $this->p['stages'][$stage] = ['state' => 'running', 't0' => microtime(true)];
            $this->emit(['k' => 'stage', 'stage' => $stage, 'state' => 'running'], ['current_stage' => $stage, 'heartbeat_at' => gmdate('Y-m-d H:i:s')]);
            $t0 = microtime(true);
            try {
                $res = match ($stage) {
                    'vulns' => $this->stageVulns(),
                    'ai' => $this->stageAi(),
                    'report' => $this->stageReport(),
                    'os' => $this->stageOs(),
                    default => $this->stageCollect($stage),
                };
            } catch (\Throwable $e) {
                if ($this->cancelNow) {
                    $this->cancel($stage);
                    return 0;
                }
                $this->fail($stage, $e->getMessage(), self::friendly($e));
                return 1;
            }
            $ms = (int) ((microtime(true) - $t0) * 1000);
            $lines = $res['log'] ?? [];
            foreach (array_slice($lines, 0, 120) as $l) {
                $this->push(['k' => 'log', 't' => $l]);
            }
            if (count($lines) > 120) {
                $this->push(['k' => 'log', 't' => '  … +' . (count($lines) - 120) . ' linhas', 'c' => 't-dim']);
            }
            $c = $res['counters'] ?? [];
            if (!empty($res['findings'])) {
                $c['findings'] = (int) ($this->p['counters']['findings'] ?? 0) + (int) $res['findings'];
            }
            if ($c) {
                $this->p['counters'] = array_replace($this->p['counters'], $c);
                $this->push(['k' => 'counters', 'c' => $c]);
            }
            if (isset($res['graph'])) {
                $this->p['graph'] = $res['graph'];
                $this->push(['k' => 'graph']);
            }
            $this->p['stages'][$stage] = ['state' => 'done', 'ms' => $ms];
            $done = ['k' => 'stage', 'stage' => $stage, 'state' => 'done', 'ms' => $ms];
            if ($stage === 'report') {
                $this->push($done);
                $this->emit(['k' => 'done', 'url' => url('/reports/' . $id)], [
                    'status' => 'done', 'finished_at' => gmdate('Y-m-d H:i:s'), 'secrets_enc' => null, 'worker_pid' => null, 'current_stage' => 'report',
                ]);
                Audit::log('analysis.done', "Análise #$id concluída (score {$this->a['score']})", 'INFO', [], $this->user);
                return 0;
            }
            $this->emit($done);
        }
        return 0;
    }

    private function reload(): void
    {
        $this->a = Database::one('SELECT * FROM analyses WHERE id = ?', [$this->a['id']]) ?? $this->a;
    }

    /** Acrescenta um evento à fila em memória (sem gravar). */
    private function push(array $ev): void
    {
        $ev['s'] = ++$this->p['seq'];
        $this->p['events'][] = $ev;
        if (count($this->p['events']) > self::MAX_EVENTS) {
            $this->p['events'] = array_slice($this->p['events'], -self::MAX_EVENTS);
        }
    }

    /** Acrescenta e grava o progresso (mais colunas opcionais), atualizando o batimento. */
    private function emit(?array $ev = null, array $cols = []): void
    {
        if ($ev) {
            $this->push($ev);
        }
        $cols += ['heartbeat_at' => gmdate('Y-m-d H:i:s')];
        $cols['progress_json'] = json_encode($this->p, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        Database::update('analyses', $cols, 'id = :id', ['id' => $this->a['id']]);
    }

    private function fail(string $stage, string $raw, ?string $friendly = null): void
    {
        $id = (int) $this->a['id'];
        $this->p['stages'][$stage] = ['state' => 'error'];
        $this->push(['k' => 'stage', 'stage' => $stage, 'state' => 'error']);
        $this->emit(['k' => 'error', 'msg' => $friendly ?? $raw, 'stage' => $stage], [
            'status' => 'failed', 'error' => "[$stage] " . mb_substr($raw, 0, 1000), 'finished_at' => gmdate('Y-m-d H:i:s'),
            'secrets_enc' => null, 'worker_pid' => null,
        ]);
        Audit::log('analysis.error', "Análise #$id falhou em '$stage': $raw", 'ERROR', [], $this->user);
    }

    private function cancel(string $stage): void
    {
        $id = (int) $this->a['id'];
        $this->p['stages'][$stage] = ['state' => 'pending'];
        $this->emit(['k' => 'cancelled', 'stage' => $stage], [
            'status' => 'failed', 'error' => 'Cancelada pelo usuário', 'finished_at' => gmdate('Y-m-d H:i:s'), 'secrets_enc' => null, 'worker_pid' => null,
        ]);
        Audit::log('analysis.cancelled', "Análise #$id cancelada antes da etapa '$stage'", 'INFO', [], $this->user);
    }

    /* ------------------------------------------------------------------ */
    /* Etapas                                                              */
    /* ------------------------------------------------------------------ */

    private function json(mixed $v): string
    {
        return json_encode($v, JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
    }

    private function stageCollect(string $stage): array
    {
        $a = $this->a;
        $t0 = microtime(true);
        $pdo = Connector::connect($this->secrets['conn'], $a['database_name']);
        $latency = (int) ((microtime(true) - $t0) * 1000);
        $collector = Connector::collector($pdo, $a['engine'], $a['database_name']);
        $out = $collector->{$stage}();

        $metrics = json_decode((string) $a['metrics_json'], true) ?: [];
        $metrics[$stage] = $out['metrics'];
        $findings = array_values(array_filter(json_decode((string) $a['findings_json'], true) ?: [], fn($f) => ($f['stage'] ?? '') !== $stage));
        foreach ($out['findings'] as $f) {
            $findings[] = $f + ['stage' => $stage];
        }
        $upd = ['metrics_json' => $this->json($metrics), 'findings_json' => $this->json($findings)];
        if ($stage === 'connect') {
            $upd['server_version'] = mb_substr((string) $out['metrics']['version'], 0, 200);
        }
        Database::update('analyses', $upd, 'id = :id', ['id' => $a['id']]);

        $resp = ['log' => $out['log'], 'counters' => $out['counters'] + ($stage === 'connect' ? ['latency' => $latency] : []), 'findings' => count($out['findings'])];
        if ($stage === 'schemas') {
            // Grafo para a animação de varredura (limitado para manter fluidez)
            $tables = array_slice($out['metrics']['tables'], 0, 60);
            $names = array_flip(array_map(fn($t) => $t['schema'] . '.' . $t['name'], $tables));
            $resp['graph'] = [
                'nodes' => array_map(fn($t) => ['id' => $t['schema'] . '.' . $t['name'], 'label' => $t['name'], 'size' => $t['data_bytes'] + $t['index_bytes'], 'pk' => $t['has_pk']], $tables),
                'edges' => array_values(array_filter(array_map(function ($f) use ($a) {
                    $src = ($f['schema'] ?? $a['database_name']) . '.' . $f['table_name'];
                    $dst = ($f['ref_schema'] ?? $a['database_name']) . '.' . $f['ref_table'];
                    return ['from' => $src, 'to' => $dst];
                }, $out['metrics']['foreign_keys']), fn($e) => isset($names[$e['from']], $names[$e['to']]))),
            ];
        }
        $this->reload();
        return $resp;
    }

    /**
     * Coleta do SO via SSH (opcional). Falhas aqui não derrubam a análise: o laudo segue sem os dados do SO.
     * Também preenche/corrige o hardware com o que foi detectado no servidor.
     */
    private function stageOs(): array
    {
        $a = $this->a;
        $sshC = $this->secrets['ssh'] ?? null;
        if (!$sshC) {
            return ['log' => ['• Coleta via SSH não habilitada — etapa ignorada (o laudo vai listar os comandos de SO a rodar manualmente).']];
        }
        $ssh = new SshClient($sshC);
        $log = ['→ ssh ' . $ssh->label() . ' (somente leitura, ' . count(OsCollector::COMMANDS) . ' comandos fixos, ' . ($ssh->sudo() ? 'sudo só para ler o log do kernel' : 'sem sudo') . ')'];
        $metrics = json_decode((string) $a['metrics_json'], true) ?: [];
        $dataDir = $this->dataDirectory();
        try {
            $r = (new OsCollector($ssh))->collect($dataDir);
        } catch (\Throwable $e) {
            Audit::log('ssh.collect_failed', "Análise #{$a['id']}: " . $e->getMessage(), 'WARNING', [], $this->user);
            $metrics['os'] = ['error' => mb_substr($e->getMessage(), 0, 400), 'target' => $ssh->label()];
            Database::update('analyses', ['metrics_json' => $this->json($metrics)], 'id = :id', ['id' => $a['id']]);
            $this->reload();
            return ['log' => array_merge($log, ['⚠ Coleta SSH falhou: ' . mb_substr($e->getMessage(), 0, 300), '• Seguindo sem dados do SO.'])];
        }
        $p = $r['parsed'];
        $log[] = "✔ Coleta recebida em {$r['ms']} ms" . ($r['fingerprint'] ? " · host key {$r['fingerprint']}" : '');
        foreach ($r['raw'] as $k => $x) {
            if ($x['rc'] !== 0 && !in_array($k, ['oom'], true)) {
                $log[] = '⚠ ' . (OsCollector::COMMANDS[$k][0] ?? $k) . ' indisponível: ' . mb_substr(strtok($x['out'], "\n") ?: "código {$x['rc']}", 0, 120);
            }
        }
        if (isset($p['mem']['total'])) {
            $log[] = sprintf('  ↳ RAM %s · disponível %s · swap %s/%s', human_bytes($p['mem']['total']), human_bytes($p['mem']['available']), human_bytes($p['mem']['swap_used']), human_bytes($p['mem']['swap_total']));
        }
        if (isset($p['load'])) {
            $log[] = "  ↳ {$p['vcpu']} vCPU · load {$p['load']['1m']} / {$p['load']['5m']} / {$p['load']['15m']}";
        }
        if (isset($p['vmstat'])) {
            $v = $p['vmstat'];
            $log[] = "  ↳ vmstat: us {$v['us']}% sy {$v['sy']}% wa {$v['wa']}% · si/so {$v['si']}/{$v['so']}";
        }
        if (isset($p['data_dir']['used_pct'])) {
            $log[] = "  ↳ dados em {$p['data_dir']['path']}: {$p['data_dir']['used_pct']}% usado, " . human_bytes($p['data_dir']['avail']) . ' livres';
        }
        $log[] = $p['oom_access'] ?? true ? '  ↳ eventos de OOM no kernel: ' . count($p['oom_events'] ?? []) . (!empty($p['oom_via_sudo']) ? ' (lido via sudo)' : '')
            : '⚠ sem permissão para ler o log do kernel (OOM não verificado)' . (($p['sudo'] ?? null) === 'negado' ? ': sudo recusado' : '');
        if (!empty($r['hardware']['disk_note'])) {
            $log[] = '• ' . $r['hardware']['disk_note'] . ': mantido o tipo de disco informado no formulário';
        }

        // Hardware: o detectado no servidor prevalece sobre o digitado
        $hw = json_decode((string) $a['hardware_json'], true) ?: [];
        $det = $r['hardware'];
        foreach ($det as $k => $v) {
            if (isset($hw[$k]) && $hw[$k] != $v) {
                $log[] = "• $k informado ({$hw[$k]}) difere do detectado ($v): usando o detectado";
            }
        }
        $hw = ['source' => 'ssh'] + array_replace($hw, $det);

        $findings = Scorer::sort(OsCollector::findings($p, $a['engine'], $metrics['sizing']['settings'] ?? []));
        $metrics['os'] = ['target' => $ssh->label(), 'fingerprint' => $r['fingerprint'], 'collected_ms' => $r['ms'], 'parsed' => $p, 'raw' => $r['raw']];
        $all = array_values(array_filter(json_decode((string) $a['findings_json'], true) ?: [], fn($f) => ($f['stage'] ?? '') !== 'os'));
        foreach ($findings as $f) {
            $all[] = $f + ['stage' => 'os'];
        }
        Database::update('analyses', ['hardware_json' => json_encode($hw), 'metrics_json' => $this->json($metrics), 'findings_json' => $this->json($all)], 'id = :id', ['id' => $a['id']]);
        Audit::log('ssh.collect', "Análise #{$a['id']}: SO coletado via SSH em " . $ssh->label(), 'INFO', [], $this->user);
        foreach (array_slice($findings, 0, 8) as $f) {
            $log[] = '⚠ [' . strtoupper($f['severity']) . '] ' . $f['title'];
        }
        $this->reload();
        return ['log' => $log, 'findings' => count($findings)];
    }

    /** Diretório de dados do SGBD (para medir o disco certo). Sem privilégio para ler, cai nos caminhos padrão. */
    private function dataDirectory(): ?string
    {
        $a = $this->a;
        try {
            $pdo = Connector::connect($this->secrets['conn'], $a['database_name']);
            $dir = match ($a['engine']) {
                'postgresql' => $pdo->query("SELECT setting FROM pg_settings WHERE name = 'data_directory'")->fetchColumn(),
                'mysql', 'mariadb' => $pdo->query('SELECT @@datadir')->fetchColumn(),
                'sqlserver' => $pdo->query("SELECT CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS nvarchar(260)) AS d")->fetchColumn(),
                'oracle' => ($pdo->query("SELECT SUBSTR(file_name, 1, INSTR(file_name, '/', -1) - 1) AS d FROM dba_data_files WHERE ROWNUM = 1")->fetchAll()[0]['d'] ?? null),
                default => null,
            };
            if ($dir) {
                return (string) $dir;
            }
        } catch (\Throwable) {
        }
        return match ($a['engine']) {
            'postgresql' => '/var/lib/postgresql',
            'mysql', 'mariadb' => '/var/lib/mysql',
            'sqlserver' => '/var/opt/mssql',
            'oracle' => '/opt/oracle/oradata',
            default => null,
        };
    }

    /** CVEs e ciclo de vida da versão coletada. Usa só a base local: não depende de internet e nunca derruba a análise. */
    private function stageVulns(): array
    {
        $a = $this->a;
        $metrics = json_decode((string) $a['metrics_json'], true) ?: [];
        try {
            $out = VulnCheck::evaluate((string) $a['engine'], $metrics['connect'] ?? []);
        } catch (\Throwable $e) {
            $out = ['metrics' => ['status' => 'error', 'error' => $e->getMessage()], 'findings' => [], 'log' => ['⚠ Checagem de vulnerabilidades indisponível: ' . mb_substr($e->getMessage(), 0, 160)]];
        }
        $metrics['vulns'] = $out['metrics'];
        $findings = array_values(array_filter(json_decode((string) $a['findings_json'], true) ?: [], fn($f) => ($f['stage'] ?? '') !== 'vulns'));
        foreach ($out['findings'] as $f) {
            $findings[] = $f + ['stage' => 'vulns'];
        }
        Database::update('analyses', ['metrics_json' => $this->json($metrics), 'findings_json' => $this->json($findings)], 'id = :id', ['id' => $a['id']]);
        $this->reload();
        return ['log' => $out['log'], 'counters' => ['cves' => (int) ($out['metrics']['cve_total'] ?? 0)], 'findings' => count($out['findings'])];
    }

    private function stageAi(): array
    {
        $a = $this->a;
        $metrics = json_decode((string) $a['metrics_json'], true) ?: [];
        $findings = Scorer::sort(json_decode((string) $a['findings_json'], true) ?: []);
        $hw = json_decode((string) $a['hardware_json'], true) ?: [];
        $flavor = $a['engine'] === 'postgresql' ? 'postgresql' : ($metrics['connect']['flavor'] ?? $a['engine']);
        $tuning = Sizing::evaluate($flavor, $metrics['sizing']['settings'] ?? [], $metrics['sizing']['stats'] ?? [], $hw, (int) ($metrics['connect']['db_size'] ?? 0), $metrics['connect']['extensions'] ?? [], $metrics['os']['parsed'] ?? []);
        $score = Scorer::score($findings, $tuning);
        $upd = ['tuning_json' => json_encode($tuning, JSON_UNESCAPED_UNICODE), 'score' => $score, 'findings_json' => $this->json($findings)];
        $log = [];
        // Estas linhas saem já, antes da chamada à IA (que pode levar minutos)
        $this->push(['k' => 'log', 't' => '• Veredito heurístico: ' . mb_strtoupper($tuning['verdict'])]);
        $this->push(['k' => 'log', 't' => '• Score técnico calculado: ' . $score . '/100']);
        $this->p['counters']['score'] = $score;
        $this->push(['k' => 'counters', 'c' => ['score' => $score]]);

        $user = $this->user;
        $client = AiClient::forUser($user);
        $tokens = ['in' => 0, 'out' => 0];
        if (!$client) {
            $log[] = '⚠ Nenhuma IA configurada — laudo gerado apenas com regras determinísticas. Configure em /admin/ai.';
        } else {
            $this->emit(['k' => 'log', 't' => "→ Enviando coleta para {$client->provider} / {$client->model}… (pode levar alguns minutos; a análise continua mesmo se você sair desta página)"]);
            // Enquanto espera a IA: mantém o batimento e atende um cancelamento na hora
            $beat = time();
            $client->abort = function () use (&$beat): bool {
                if (time() - $beat >= 30) {
                    $beat = time();
                    Database::exec("UPDATE analyses SET heartbeat_at = datetime('now') WHERE id = ?", [$this->a['id']]);
                }
                return $this->cancelNow = (int) Database::value('SELECT cancel_requested FROM analyses WHERE id = ?', [$this->a['id']]) === 1;
            };
            try {
                $a['hardware_json'] = json_encode($hw);
                $r = $client->chat(Prompt::system(), Prompt::user($a, $metrics, $findings, $tuning));
                $upd += ['ai_report_md' => $r['text'], 'ai_provider' => $client->provider, 'ai_model' => $client->model];
                $tokens = ['in' => $r['tokens_in'], 'out' => $r['tokens_out']];
                Database::insert('ai_usage', ['user_id' => $user['id'], 'analysis_id' => $a['id'], 'provider' => $client->provider, 'model' => $client->model,
                    'tokens_in' => $r['tokens_in'], 'tokens_out' => $r['tokens_out'], 'latency_ms' => $r['latency_ms']]);
                Audit::log('ai.usage', "Análise #{$a['id']}: {$r['tokens_in']} tokens entrada / {$r['tokens_out']} saída", 'INFO', ['provider' => $client->provider, 'model' => $client->model], $user);
                $log[] = "✔ Laudo da IA recebido em {$r['latency_ms']} ms ({$r['tokens_in']}+{$r['tokens_out']} tokens)";
            } catch (\Throwable $e) {
                if ($this->cancelNow) {
                    throw $e;
                }
                Audit::log('ai.error', "Falha na IA (análise #{$a['id']}): " . $e->getMessage(), 'ERROR', [], $user);
                $log[] = '✘ IA indisponível: ' . mb_substr($e->getMessage(), 0, 200) . ' — seguindo com laudo heurístico.';
            }
        }
        Database::update('analyses', $upd, 'id = :id', ['id' => $a['id']]);
        $this->reload();
        return ['log' => $log, 'counters' => ['score' => $score, 'tokens' => $tokens['in'] + $tokens['out']]];
    }

    private function stageReport(): array
    {
        return ['log' => ['✔ Laudo técnico #' . $this->a['id'] . ' gerado'], 'counters' => ['score' => (int) $this->a['score']]];
    }

    public static function friendly(\Throwable $e): string
    {
        $m = $e->getMessage();
        return match (true) {
            str_contains($m, 'pg_hba.conf') => 'O pg_hba.conf do servidor não libera este usuário/IP no banco tentado (o analisador já tenta o banco informado, postgres, o banco com o nome do usuário e template1). '
                . 'Informe em "Banco inicial" um banco liberado para o usuário (ex.: zabbix) ou adicione uma linha no pg_hba.conf para o IP deste servidor.',
            str_contains($m, 'password authentication failed'), str_contains($m, 'autenticação do tipo senha falhou'), str_contains($m, 'Access denied') => 'Usuário ou senha recusados pelo servidor de banco.',
            str_contains($m, 'Connection refused') => 'Conexão recusada: verifique host, porta e firewall.',
            str_contains($m, 'timeout'), str_contains($m, 'timed out') => 'Tempo de conexão esgotado: host inacessível ou firewall bloqueando.',
            str_contains($m, 'could not translate host'), str_contains($m, 'getaddrinfo') => 'Não foi possível resolver o nome do host.',
            str_contains($m, 'could not find driver (pdo_dblib)') => 'Driver do SQL Server ausente: instale php8.4-sybase (FreeTDS) e reinicie o php-fpm, ou rode o install.sh de novo.',
            str_contains($m, 'python-oracledb não instalado'), str_contains($m, 'driver Oracle') => 'Driver do Oracle ausente: rode o install.sh de novo (instala python3-oracledb, modo thin, sem Instant Client).',
            str_contains($m, 'could not find driver') => 'Driver PDO ausente no servidor (php-pgsql/php-mysql/php-sybase).',
            str_contains($m, 'Login failed'), str_contains($m, 'ORA-01017') => 'Usuário ou senha recusados pelo servidor de banco.',
            str_contains($m, 'ORA-01045') => 'O usuário não tem CREATE SESSION no Oracle.',
            str_contains($m, 'ORA-28000') => 'Conta bloqueada no Oracle (ORA-28000).',
            str_contains($m, 'Nenhum service name padrão') => $m,
            str_contains($m, 'ORA-12514'), str_contains($m, 'DPY-6001') => 'Service name não registrado no listener: informe o service name correto (ex.: ORCLPDB1) em "Banco inicial".',
            str_contains($m, 'DPY-6005'), str_contains($m, 'ORA-12541') => 'Nenhum listener Oracle respondeu: verifique host, porta (1521) e firewall.',
            str_contains($m, 'Unable to connect'), str_contains($m, 'Adaptive Server is unavailable') => 'Não foi possível conectar ao SQL Server: verifique host, porta (1433), firewall e se o TCP/IP está habilitado.',
            default => mb_substr($m, 0, 300),
        };
    }
}
