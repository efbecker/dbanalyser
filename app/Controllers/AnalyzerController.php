<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Ai\AiClient;
use App\Analyzer\{Connector, Prompt, Scorer, Sizing};
use App\Core\{Audit, Auth, Crypto, Database, Http, View};

final class AnalyzerController
{
    public const STAGES = [
        'connect' => 'Conectando',
        'schemas' => 'Mapeando Schemas',
        'indexes' => 'Analisando Índices',
        'queries' => 'Avaliando Queries',
        'sizing'  => 'Checando Hardware/Buffers',
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
            $pdo = Connector::connect($c);
            $latency = (int) ((microtime(true) - $t0) * 1000);
            $dbs = Connector::listDatabases($pdo, $c['engine']);
            $_SESSION['analyzer_conn'] = Crypto::encrypt(json_encode($c));
            Audit::log('db.connect', "Conexão em {$c['engine']}://{$c['username']}@{$c['host']}:{$c['port']}", 'INFO', ['databases' => count($dbs)]);
            Http::json(['ok' => true, 'latency_ms' => $latency, 'databases' => array_map(fn($d) => ['name' => $d['name'], 'size' => human_bytes((int) $d['size'])], $dbs)]);
        } catch (\Throwable $e) {
            Audit::log('db.connect_failed', 'Falha de conexão: ' . $e->getMessage(), 'WARNING', ['host' => $c['host'] ?? null]);
            Http::json(['ok' => false, 'error' => self::friendly($e)], 200);
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
        $id = Database::insert('analyses', [
            'user_id' => Auth::user()['id'], 'engine' => $conn['engine'], 'host' => $conn['host'], 'port' => $conn['port'],
            'database_name' => $db, 'hardware_json' => json_encode($hw), 'metrics_json' => '{}', 'findings_json' => '[]',
        ]);
        $_SESSION['analyses'][$id] = ['conn' => $_SESSION['analyzer_conn'], 'db' => $db];
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
                'ai' => $this->stageAi($a),
                'report' => $this->stageReport($a),
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

    private function stageAi(array $a): array
    {
        $metrics = json_decode((string) $a['metrics_json'], true) ?: [];
        $findings = Scorer::sort(json_decode((string) $a['findings_json'], true) ?: []);
        $hw = json_decode((string) $a['hardware_json'], true) ?: [];
        $flavor = $a['engine'] === 'postgresql' ? 'postgresql' : ($metrics['connect']['flavor'] ?? $a['engine']);
        $tuning = Sizing::evaluate($flavor, $metrics['sizing']['settings'] ?? [], $metrics['sizing']['stats'] ?? [], $hw, (int) ($metrics['connect']['db_size'] ?? 0));
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
            str_contains($m, 'password authentication failed'), str_contains($m, 'Access denied') => 'Usuário ou senha recusados pelo servidor de banco.',
            str_contains($m, 'Connection refused') => 'Conexão recusada: verifique host, porta e firewall.',
            str_contains($m, 'timeout'), str_contains($m, 'timed out') => 'Tempo de conexão esgotado: host inacessível ou firewall bloqueando.',
            str_contains($m, 'could not translate host'), str_contains($m, 'getaddrinfo') => 'Não foi possível resolver o nome do host.',
            str_contains($m, 'could not find driver') => 'Driver PDO ausente no servidor (php-pgsql/php-mysql).',
            default => mb_substr($m, 0, 300),
        };
    }
}
