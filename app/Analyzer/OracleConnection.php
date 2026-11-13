<?php
declare(strict_types=1);

namespace App\Analyzer;

use App\Core\Config;

/**
 * Conexão Oracle via bin/oracle-bridge.py (python-oracledb em modo thin, sem Instant Client).
 * Expõe o subconjunto de PDO usado pelos coletores: prepare()->execute()->fetchAll() e query()->fetchAll().
 * O processo auxiliar vive enquanto este objeto existir (uma conexão por requisição HTTP).
 */
final class OracleConnection
{
    /** @var resource|null */
    private $proc = null;
    /** @var array<int, resource> */
    private array $pipes = [];
    public readonly string $version;

    public function __construct(array $cfg)
    {
        $python = self::python();
        $script = APP_ROOT . '/bin/oracle-bridge.py';
        $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $proc = proc_open([$python, '-I', $script], $spec, $pipes, null, ['PATH' => '/usr/local/bin:/usr/bin:/bin', 'PYTHONIOENCODING' => 'utf-8']);
        if (!is_resource($proc)) {
            throw new \RuntimeException('Não foi possível iniciar o driver Oracle (python3 + python-oracledb).');
        }
        $this->proc = $proc;
        $this->pipes = $pipes;
        stream_set_blocking($pipes[2], false); // stderr só é lido em caso de falha
        $hello = $this->call($cfg);
        if (!($hello['ok'] ?? false)) {
            $err = $hello['error'] ?? trim((string) stream_get_contents($this->pipes[2])) ?: 'falha desconhecida';
            $this->close();
            throw new \PDOException($err);
        }
        $this->version = (string) ($hello['version'] ?? '');
    }

    public static function python(): string
    {
        $cfg = Config::get('oracle_python');
        if ($cfg) {
            return (string) $cfg;
        }
        foreach (['/opt/db-analyzer/venv/bin/python3', '/usr/bin/python3'] as $p) {
            if (is_executable($p)) {
                return $p;
            }
        }
        return 'python3';
    }

    private function call(array $msg): array
    {
        if (!$this->proc) {
            throw new \RuntimeException('Conexão Oracle encerrada.');
        }
        fwrite($this->pipes[0], json_encode($msg, JSON_UNESCAPED_UNICODE) . "\n");
        fflush($this->pipes[0]);
        $line = fgets($this->pipes[1]);
        if ($line === false) {
            $err = trim((string) stream_get_contents($this->pipes[2]));
            throw new \PDOException('Driver Oracle encerrou inesperadamente' . ($err ? ': ' . mb_substr($err, -400) : ''));
        }
        $res = json_decode($line, true);
        return is_array($res) ? $res : ['ok' => false, 'error' => 'Resposta inválida do driver Oracle'];
    }

    /** @return list<array<string, mixed>> */
    public function run(string $sql, array $params = []): array
    {
        $r = $this->call(['sql' => $sql, 'params' => array_values($params)]);
        if (!($r['ok'] ?? false)) {
            // Mensagens do Oracle 23ai trazem uma linha "Help: https://docs.oracle.com/..." que só polui o log
            throw new \PDOException(trim(preg_replace('/\s*Help: https?:\S+/', '', (string) ($r['error'] ?? 'erro Oracle'))));
        }
        return $r['rows'] ?? [];
    }

    public function prepare(string $sql): object
    {
        $conn = $this;
        return new class ($conn, $sql) {
            private array $rows = [];

            public function __construct(private OracleConnection $c, private string $sql)
            {
            }

            public function execute(array $params = []): bool
            {
                $this->rows = $this->c->run($this->sql, $params);
                return true;
            }

            public function fetchAll(): array
            {
                return $this->rows;
            }
        };
    }

    public function query(string $sql): object
    {
        $st = $this->prepare($sql);
        $st->execute();
        return $st;
    }

    public function close(): void
    {
        if ($this->proc) {
            foreach ($this->pipes as $p) {
                @fclose($p);
            }
            @proc_close($this->proc);
            $this->proc = null;
        }
    }

    public function __destruct()
    {
        $this->close();
    }
}
