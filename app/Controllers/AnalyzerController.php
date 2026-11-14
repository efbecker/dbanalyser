<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Ai\AiClient;
use App\Analyzer\{Connector, OsCollector, Runner, SshClient};
use App\Core\{Audit, Auth, Crypto, Database, Http, View};

final class AnalyzerController
{
    public const STAGES = Runner::STAGES;

    public function index(): void
    {
        $u = Auth::user();
        $infra = json_decode((string) ($u['infra_json'] ?? ''), true) ?: [];
        // Volta para uma análise em andamento: ?watch=ID ou a mais recente do usuário
        $watch = null;
        if (isset($_GET['watch'])) {
            $watch = self::visible((int) $_GET['watch']);
            if ($watch && $watch['status'] === 'done') {
                Http::redirect('/reports/' . $watch['id']);
                return;
            }
        } else {
            $watch = Database::one("SELECT * FROM analyses WHERE user_id = ? AND status = 'running' ORDER BY id DESC LIMIT 1", [$u['id']]);
        }
        View::render('analyzer/index', [
            'title' => 'Analisador', 'engines' => Connector::ENGINES, 'stages' => self::STAGES, 'infra' => $infra,
            'ai' => AiClient::forUser($u), 'watch' => $watch,
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
            if ($c['engine'] === 'oracle') {
                $c['service'] = $usedDb; // no Oracle o "banco" escolhido é o schema; a conexão segue no service name validado
            }
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
            // Credenciais já testadas: só atualiza a opção de sudo, que pode ter sido marcada depois do teste
            $c = json_decode((string) Crypto::decrypt($_SESSION['analyzer_ssh']), true) ?: [];
            $c['sudo'] = !empty($in['ssh_sudo']);
            $c['sudo_password'] = $c['sudo'] ? ((string) ($in['ssh_sudo_password'] ?? '') ?: ($c['sudo_password'] ?? '') ?: ($c['password'] ?? '')) : '';
            return $_SESSION['analyzer_ssh'] = Crypto::encrypt(json_encode($c));
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

    /** POST /api/analyzer/start — coloca a análise na fila do servidor e devolve o id para acompanhar. */
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
            $sshEnc = $this->sshInput(false);
        } catch (\InvalidArgumentException $e) {
            Http::json(['error' => 'SSH: ' . $e->getMessage()], 422);
            return;
        }
        $ssh = $sshEnc ? json_decode((string) Crypto::decrypt($sshEnc), true) : null;
        $id = Runner::enqueue(Auth::user(), $conn, $db, $hw, $ssh);
        Audit::log('analysis.started', "Análise #$id de {$conn['host']}/$db (segundo plano)");
        Runner::dispatch($id);
        Http::json(['id' => $id, 'stages' => self::STAGES]);
    }

    /** Análise visível para o usuário (dono ou admin). */
    private static function visible(int $id): ?array
    {
        $a = Database::one('SELECT * FROM analyses WHERE id = ?', [$id]);
        return $a && (Auth::isAdmin() || (int) $a['user_id'] === (int) Auth::user()['id']) ? $a : null;
    }

    /** Se o runner morreu (ou nunca subiu, sem o serviço worker), relança. O claim atômico evita runners duplicados. */
    private static function heal(array $a): void
    {
        if ($a['status'] !== 'running' || Runner::workerAlive()) {
            return;
        }
        $orphan = empty($a['worker_pid']) && strtotime($a['started_at'] . ' UTC') < time() - 5;
        if ($orphan || Runner::isStale($a)) {
            Runner::spawn((int) $a['id']);
        }
    }

    /** GET /api/analyzer/progress?id=N&since=SEQ — eventos novos da análise para a animação. */
    public function progress(): void
    {
        $a = self::visible((int) ($_GET['id'] ?? 0));
        if (!$a) {
            Http::json(['error' => 'Análise não encontrada.'], 404);
            return;
        }
        self::heal($a);
        $since = max(0, (int) ($_GET['since'] ?? 0));
        $p = Runner::progress($a);
        $events = array_values(array_filter($p['events'], fn($e) => $e['s'] > $since));
        $stages = [];
        foreach ($p['stages'] as $k => $st) {
            $stages[$k] = ['state' => $st['state'], 'ms' => $st['ms'] ?? null,
                'elapsed' => isset($st['t0']) ? (int) ((microtime(true) - (float) $st['t0']) * 1000) : null];
        }
        $needGraph = $since === 0 || array_filter($events, fn($e) => $e['k'] === 'graph');
        Http::json(Runner::summary($a) + [
            'seq' => $p['seq'], 'first_seq' => $p['events'][0]['s'] ?? 0, 'events' => $events, 'stages' => $stages, 'counters' => $p['counters'],
            'graph' => $needGraph ? $p['graph'] : null, 'url' => $a['status'] === 'done' ? url('/reports/' . $a['id']) : null,
            'error' => $a['status'] === 'failed' ? $a['error'] : null, 'stage_labels' => self::STAGES,
        ]);
    }

    /** GET /api/analyzer/running — análises em andamento (próprias; admin vê todas) para a barra lateral e listas. */
    public function running(): void
    {
        $scope = Auth::isAdmin() ? '' : ' AND user_id = ' . (int) Auth::user()['id'];
        $rows = Database::all("SELECT * FROM analyses WHERE status = 'running'$scope ORDER BY id DESC LIMIT 20");
        foreach ($rows as $a) {
            self::heal($a);
        }
        // Ids pedidos que já terminaram: a interface troca a linha "em andamento" pelo resultado
        $ids = array_slice(array_filter(array_map('intval', explode(',', (string) ($_GET['ids'] ?? '')))), 0, 50);
        $finished = [];
        if ($ids) {
            $in = implode(',', $ids);
            foreach (Database::all("SELECT id, status, score, error FROM analyses WHERE id IN ($in) AND status <> 'running'$scope") as $f) {
                $finished[] = ['id' => (int) $f['id'], 'status' => $f['status'], 'score' => $f['score'] !== null ? (int) $f['score'] : null, 'error' => $f['error'], 'url' => url('/reports/' . $f['id'])];
            }
        }
        Http::json(['items' => array_map([Runner::class, 'summary'], $rows), 'finished' => $finished]);
    }

    /** POST /api/analyzer/cancel — pede o cancelamento; o runner para antes da próxima etapa. */
    public function cancel(): void
    {
        $a = self::visible((int) Http::str('id'));
        if (!$a || $a['status'] !== 'running') {
            Http::json(['error' => 'Análise não está em andamento.'], 404);
            return;
        }
        Database::exec("UPDATE analyses SET cancel_requested = 1 WHERE id = ? AND status = 'running'", [$a['id']]);
        // Sem runner vivo (fila ou órfã), encerra aqui mesmo
        if (empty($a['worker_pid']) || Runner::isStale($a)) {
            Database::exec("UPDATE analyses SET status = 'failed', error = 'Cancelada pelo usuário', finished_at = datetime('now'), secrets_enc = NULL, worker_pid = NULL WHERE id = ? AND status = 'running'", [$a['id']]);
        }
        Audit::log('analysis.cancel', "Cancelamento da análise #{$a['id']} solicitado");
        Http::json(['ok' => true]);
    }

    private static function friendly(\Throwable $e): string
    {
        return Runner::friendly($e);
    }
}
