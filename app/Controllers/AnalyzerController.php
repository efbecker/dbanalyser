<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Ai\AiClient;
use App\Analyzer\{Connector, OsCollector, Prompt, Scorer, Sizing, SshClient, VulnCheck};
use App\Core\{Audit, Auth, Crypto, Database, Http, View};

final class AnalyzerController
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

    public function index(): void
    {
        $u = Auth::user();
        $infra = json_decode((string) ($u['infra_json'] ?? ''), true) ?: [];
        View::render('analyzer/index', [
            'title' => 'Analisador', 'engines' => Connector::ENGINES, 'stages' => self::STAGES, 'infra' => $infra,
            'ai' => AiClient::forUser($u),
        ]);
    }

    private function connInput(): array
    {
        $in = Http::input();
        $engine = (string) ($in['engine'] ?? '');
        if (!isset(Connector::ENGINES[$engine])) {
            throw new \InvalidArgumentException('Selecione o motor do SGBD.');
        }
        $host = trim((string) ($in['host'] ?? ''));
        $user = trim((string) ($in['username'] ?? ''));
        if ($host === '' || $user === '') {
            throw new \InvalidArgumentException('Host e usuário são obrigatórios.');
        }
        return [
            'engine' => $engine, 'host' => $host, 'port' => (int) ($in['port'] ?? 0) ?: Connector::ENGINES[$engine]['port'],
            'username' => $user, 'password' => (string) ($in['password'] ?? ''), 'ssl' => (string) ($in['ssl'] ?? 'prefer'),
        ];
    }

    /** POST /api/analyzer/databases — valida credenciais e lista bancos. */
    public function listDatabases(): void
    {
        try {
            $c = $this->connInput();
            $t0 = microtime(true);
            [$pdo, $usedDb] = Connector::connectAny($c, Http::str('initial_db') ?: null);
            $latency = (int) ((microtime(true) - $t0) * 1000);
            $dbs = Connector::listDatabases($pdo, $c['engine']);
            $_SESSION['analyzer_conn'] = Crypto::encrypt(json_encode($c));
            Audit::log('db.connect', "Conexão em {$c['engine']}://{$c['username']}@{$c['host']}:{$c['port']}", 'INFO', ['databases' => count($dbs)]);
            Http::json(['ok' => true, 'latency_ms' => $latency, 'connected_db' => $usedDb, 'databases' => array_map(fn($d) => ['name' => $d['name'], 'size' => human_bytes((int) $d['size'])], $dbs)]);
        } catch (\Throwable $e) {
            Audit::log('db.connect_failed', 'Falha de conexão: ' . $e->getMessage(), 'WARNING', ['host' => $c['host'] ?? null]);
            Http::json(['ok' => false, 'error' => self::friendly($e)], 200);
        }
    }

    /** Credenciais SSH do formulário (ou as já testadas nesta sessão), cifradas para guardar na sessão. */
    private function sshInput(bool $required): ?string
    {
        $in = Http::input();
        if (empty($in['ssh_enabled'])) {
            return null;
        }
        $fresh = ($in['ssh_password'] ?? '') !== '' || trim((string) ($in['ssh_key'] ?? '')) !== '';
        if (!$fresh && !$required && !empty($_SESSION['analyzer_ssh'])) {
            return $_SESSION['analyzer_ssh'];
        }
        $conn = json_decode((string) Crypto::decrypt($_SESSION['analyzer_conn'] ?? null), true) ?: [];
        $c = SshClient::fromInput($in, (string) ($conn['host'] ?? ''));
        return $_SESSION['analyzer_ssh'] = Crypto::encrypt(json_encode($c));
    }

    /** POST /api/analyzer/ssh — testa o SSH e detecta vCPU, RAM, clock e tipo de disco. */
    public function testSsh(): void
    {
        try {
            $enc = $this->sshInput(true);
            if (!$enc) {
                throw new \InvalidArgumentException('Marque a opção de coleta via SSH.');
            }
            $ssh = new SshClient(json_decode((string) Crypto::decrypt($enc), true));
            $r = (new OsCollector($ssh))->collect(null, true);
            $p = $r['parsed'];
            Audit::log('ssh.test', 'SSH testado em ' . $ssh->label(), 'INFO', ['fingerprint' => $r['fingerprint']]);
            Http::json(['ok' => true, 'latency_ms' => $r['ms'], 'fingerprint' => $r['fingerprint'], 'hardware' => $r['hardware'],
                'info' => array_filter(['kernel' => $p['kernel'] ?? null, 'cpu' => $p['cpu_model'] ?? null, 'virt' => $p['virtualization'] ?? null,
                    'ram' => isset($p['mem']['total']) ? human_bytes($p['mem']['total']) : null])]);
        } catch (\Throwable $e) {
            unset($_SESSION['analyzer_ssh']);
            Audit::log('ssh.failed', 'Falha SSH: ' . $e->getMessage(), 'WARNING');
            Http::json(['ok' => false, 'error' => mb_substr($e->getMessage(), 0, 400)]);
        }
    }

    /** POST /api/analyzer/start — cria a análise. */
    public function start(): void
    {
        $conn = json_decode((string) Crypto::decrypt($_SESSION['analyzer_conn'] ?? null), true);
        $db = Http::str('database');
        if (!$conn || $db === '') {
            Http::json(['error' => 'Conecte e selecione um banco primeiro.'], 422);
            return;
        }
        $in = Http::input();
        $hw = array_filter([
            'vcpu' => (int) ($in['vcpu'] ?? 0) ?: null,
            'clock_ghz' => (float) str_replace(',', '.', (string) ($in['clock_ghz'] ?? '')) ?: null,
            'ram_gb' => (float) str_replace(',', '.', (string) ($in['ram_gb'] ?? '')) ?: null,
            'disk' => in_array($in['disk'] ?? '', ['nvme', 'ssd', 'hdd', 'san'], true) ? $in['disk'] : null,
            'dedicated' => !empty($in['dedicated']),
        ], fn($v) => $v !== null);
        try {
            $ssh = $this->sshInput(false);
        } catch (\InvalidArgumentException $e) {
            Http::json(['error' => 'SSH: ' . $e->getMessage()], 422);
            return;
        }
        $id = Database::insert('analyses', [
            'user_id' => Auth::user()['id'], 'engine' => $conn['engine'], 'host' => $conn['host'], 'port' => $conn['port'],
            'database_name' => $db, 'hardware_json' => json_encode($hw), 'metrics_json' => '{}', 'findings_json' => '[]',
        ]);
        $_SESSION['analyses'][$id] = ['conn' => $_SESSION['analyzer_conn'], 'db' => $db, 'ssh' => $ssh];
        Audit::log('analysis.started', "Análise #$id de {$conn['host']}/$db");
        Http::json(['id' => $id, 'stages' => self::STAGES]);
    }

    /** POST /api/analyzer/step — executa uma etapa e devolve telemetria. */
    public function step(): void
    {
        $id = (int) Http::str('id');
        $stage = Http::str('stage');
        $a = Database::one('SELECT * FROM analyses WHERE id = ?', [$id]);
        if (!$a || ((int) $a['user_id'] !== (int) Auth::user()['id']) || !isset(self::STAGES[$stage]) || $a['status'] !== 'running') {
            Http::json(['error' => 'Análise inválida ou já finalizada.'], 404);
            return;
        }
        $t0 = microtime(true);
        try {
            $res = match ($stage) {
                'vulns' => $this->stageVulns($a),
                'ai' => $this->stageAi($a),
                'report' => $this->stageReport($a),
                'os' => $this->stageOs($a),
                default => $this->stageCollect($a, $stage),
            };
            $res['elapsed_ms'] = (int) ((microtime(true) - $t0) * 1000);
            Http::json($res);
        } catch (\Throwable $e) {
            Database::update('analyses', ['status' => 'failed', 'error' => "[$stage] " . $e->getMessage(), 'finished_at' => gmdate('Y-m-d H:i:s')], 'id = :id', ['id' => $id]);
            Audit::log('analysis.error', "Análise #$id falhou em '$stage': " . $e->getMessage(), 'ERROR');
            unset($_SESSION['analyses'][$id]);
            Http::json(['error' => self::friendly($e), 'stage' => $stage], 500);
        }
    }

    private function stageCollect(array $a, string $stage): array
    {
        $ctx = $_SESSION['analyses'][$a['id']] ?? null;
        $conn = $ctx ? json_decode((string) Crypto::decrypt($ctx['conn']), true) : null;
        if (!$conn) {
            throw new \RuntimeException('Sessão de conexão expirada. Reconecte.');
        }
        $pdo = Connector::connect($conn, $a['database_name']);
        $collector = Connector::collector($pdo, $a['engine'], $a['database_name']);
        $out = $collector->{$stage}();

        $metrics = json_decode((string) $a['metrics_json'], true) ?: [];
        $metrics[$stage] = $out['metrics'];
        $findings = array_values(array_filter(json_decode((string) $a['findings_json'], true) ?: [], fn($f) => ($f['stage'] ?? '') !== $stage));
        foreach ($out['findings'] as $f) {
            $findings[] = $f + ['stage' => $stage];
        }
        $upd = ['metrics_json' => json_encode($metrics, JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE), 'findings_json' => json_encode($findings, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)];
        if ($stage === 'connect') {
            $upd['server_version'] = mb_substr((string) $out['metrics']['version'], 0, 200);
        }
        Database::update('analyses', $upd, 'id = :id', ['id' => $a['id']]);

        $resp = ['log' => $out['log'], 'counters' => $out['counters'], 'findings' => count($out['findings']),
            'severities' => array_count_values(array_column($out['findings'], 'severity'))];
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
        return $resp;
    }

    /**
     * Coleta do SO via SSH (opcional). Falhas aqui não derrubam a análise: o laudo segue sem os dados do SO.
     * Também preenche/corrige o hardware com o que foi detectado no servidor.
     */
    private function stageOs(array $a): array
    {
        $ctx = $_SESSION['analyses'][$a['id']] ?? null;
        $sshC = $ctx && !empty($ctx['ssh']) ? json_decode((string) Crypto::decrypt($ctx['ssh']), true) : null;
        if (!$sshC) {
            return ['log' => ['• Coleta via SSH não habilitada — etapa ignorada (o laudo vai listar os comandos de SO a rodar manualmente).'], 'counters' => [], 'findings' => 0];
        }
        $ssh = new SshClient($sshC);
        $log = ['→ ssh ' . $ssh->label() . ' (somente leitura, ' . count(OsCollector::COMMANDS) . ' comandos fixos, sem sudo)'];
        $metrics = json_decode((string) $a['metrics_json'], true) ?: [];
        $dataDir = $this->dataDirectory($a, $ctx);
        try {
            $r = (new OsCollector($ssh))->collect($dataDir);
        } catch (\Throwable $e) {
            Audit::log('ssh.collect_failed', "Análise #{$a['id']}: " . $e->getMessage(), 'WARNING');
            $metrics['os'] = ['error' => mb_substr($e->getMessage(), 0, 400), 'target' => $ssh->label()];
            Database::update('analyses', ['metrics_json' => json_encode($metrics, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)], 'id = :id', ['id' => $a['id']]);
            return ['log' => array_merge($log, ['⚠ Coleta SSH falhou: ' . mb_substr($e->getMessage(), 0, 300), '• Seguindo sem dados do SO.']), 'counters' => [], 'findings' => 0];
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
        $log[] = $p['oom_access'] ?? true ? '  ↳ eventos de OOM no kernel: ' . count($p['oom_events'] ?? []) : '⚠ sem permissão para ler o log do kernel (OOM não verificado)';

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
        Database::update('analyses', [
            'hardware_json' => json_encode($hw),
            'metrics_json' => json_encode($metrics, JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE),
            'findings_json' => json_encode($all, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE),
        ], 'id = :id', ['id' => $a['id']]);
        Audit::log('ssh.collect', "Análise #{$a['id']}: SO coletado via SSH em " . $ssh->label());
        foreach (array_slice($findings, 0, 8) as $f) {
            $log[] = '⚠ [' . strtoupper($f['severity']) . '] ' . $f['title'];
        }
        return ['log' => $log, 'counters' => [], 'findings' => count($findings), 'severities' => array_count_values(array_column($findings, 'severity')), 'hardware' => $det];
    }

    /** Diretório de dados do SGBD (para medir o disco certo). Sem privilégio para ler, cai nos caminhos padrão. */
    private function dataDirectory(array $a, array $ctx): ?string
    {
        try {
            $conn = json_decode((string) Crypto::decrypt($ctx['conn']), true);
            $pdo = Connector::connect($conn, $a['database_name']);
            $dir = match ($a['engine']) {
                'postgresql' => $pdo->query("SELECT setting FROM pg_settings WHERE name = 'data_directory'")->fetchColumn(),
                'mysql', 'mariadb' => $pdo->query('SELECT @@datadir')->fetchColumn(),
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
            default => null,
        };
    }

    /** CVEs e ciclo de vida da versão coletada. Usa só a base local: não depende de internet e nunca derruba a análise. */
    private function stageVulns(array $a): array
    {
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
        Database::update('analyses', [
            'metrics_json' => json_encode($metrics, JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE),
            'findings_json' => json_encode($findings, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE),
        ], 'id = :id', ['id' => $a['id']]);
        return ['log' => $out['log'], 'counters' => ['cves' => (int) ($out['metrics']['cve_total'] ?? 0)], 'findings' => count($out['findings']),
            'severities' => array_count_values(array_column($out['findings'], 'severity'))];
    }

    private function stageAi(array $a): array
    {
        $metrics = json_decode((string) $a['metrics_json'], true) ?: [];
        $findings = Scorer::sort(json_decode((string) $a['findings_json'], true) ?: []);
        $hw = json_decode((string) $a['hardware_json'], true) ?: [];
        $flavor = $a['engine'] === 'postgresql' ? 'postgresql' : ($metrics['connect']['flavor'] ?? $a['engine']);
        $tuning = Sizing::evaluate($flavor, $metrics['sizing']['settings'] ?? [], $metrics['sizing']['stats'] ?? [], $hw, (int) ($metrics['connect']['db_size'] ?? 0), $metrics['connect']['extensions'] ?? [], $metrics['os']['parsed'] ?? []);
        $score = Scorer::score($findings, $tuning);
        $upd = ['tuning_json' => json_encode($tuning, JSON_UNESCAPED_UNICODE), 'score' => $score, 'findings_json' => json_encode($findings, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)];
        $log = ['• Veredito heurístico: ' . mb_strtoupper($tuning['verdict']), '• Score técnico calculado: ' . $score . '/100'];

        $user = Auth::user();
        $client = AiClient::forUser($user);
        $tokens = ['in' => 0, 'out' => 0];
        if (!$client) {
            $log[] = '⚠ Nenhuma IA configurada — laudo gerado apenas com regras determinísticas. Configure em /admin/ai.';
        } else {
            $log[] = "→ Enviando coleta para {$client->provider} / {$client->model}…";
            try {
                $a['hardware_json'] = json_encode($hw);
                $r = $client->chat(Prompt::system(), Prompt::user($a, $metrics, $findings, $tuning));
                $upd += ['ai_report_md' => $r['text'], 'ai_provider' => $client->provider, 'ai_model' => $client->model];
                $tokens = ['in' => $r['tokens_in'], 'out' => $r['tokens_out']];
                Database::insert('ai_usage', ['user_id' => $user['id'], 'analysis_id' => $a['id'], 'provider' => $client->provider, 'model' => $client->model,
                    'tokens_in' => $r['tokens_in'], 'tokens_out' => $r['tokens_out'], 'latency_ms' => $r['latency_ms']]);
                Audit::log('ai.usage', "Análise #{$a['id']}: {$r['tokens_in']} tokens entrada / {$r['tokens_out']} saída", 'INFO', ['provider' => $client->provider, 'model' => $client->model]);
                $log[] = "✔ Laudo da IA recebido em {$r['latency_ms']} ms ({$r['tokens_in']}+{$r['tokens_out']} tokens)";
            } catch (\Throwable $e) {
                Audit::log('ai.error', "Falha na IA (análise #{$a['id']}): " . $e->getMessage(), 'ERROR');
                $log[] = '✘ IA indisponível: ' . mb_substr($e->getMessage(), 0, 200) . ' — seguindo com laudo heurístico.';
            }
        }
        Database::update('analyses', $upd, 'id = :id', ['id' => $a['id']]);
        return ['log' => $log, 'counters' => ['score' => $score, 'tokens' => $tokens['in'] + $tokens['out']], 'verdict' => $tuning['verdict']];
    }

    private function stageReport(array $a): array
    {
        Database::update('analyses', ['status' => 'done', 'finished_at' => gmdate('Y-m-d H:i:s')], 'id = :id', ['id' => $a['id']]);
        unset($_SESSION['analyses'][$a['id']]);
        Audit::log('analysis.done', "Análise #{$a['id']} concluída (score {$a['score']})");
        return ['log' => ['✔ Laudo técnico #' . $a['id'] . ' gerado'], 'counters' => ['score' => (int) $a['score']], 'url' => url('/reports/' . $a['id'])];
    }

    private static function friendly(\Throwable $e): string
    {
        $m = $e->getMessage();
        return match (true) {
            str_contains($m, 'pg_hba.conf') => 'O pg_hba.conf do servidor não libera este usuário/IP no banco tentado (o analisador já tenta o banco informado, postgres, o banco com o nome do usuário e template1). '
                . 'Informe em "Banco inicial" um banco liberado para o usuário (ex.: zabbix) ou adicione uma linha no pg_hba.conf para o IP deste servidor.',
            str_contains($m, 'password authentication failed'), str_contains($m, 'autenticação do tipo senha falhou'), str_contains($m, 'Access denied') => 'Usuário ou senha recusados pelo servidor de banco.',
            str_contains($m, 'Connection refused') => 'Conexão recusada: verifique host, porta e firewall.',
            str_contains($m, 'timeout'), str_contains($m, 'timed out') => 'Tempo de conexão esgotado: host inacessível ou firewall bloqueando.',
            str_contains($m, 'could not translate host'), str_contains($m, 'getaddrinfo') => 'Não foi possível resolver o nome do host.',
            str_contains($m, 'could not find driver') => 'Driver PDO ausente no servidor (php-pgsql/php-mysql).',
            default => mb_substr($m, 0, 300),
        };
    }
}
