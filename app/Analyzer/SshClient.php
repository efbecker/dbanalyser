<?php
declare(strict_types=1);

namespace App\Analyzer;

use App\Core\Config;

/**
 * Executa um script fixo no servidor do banco usando o cliente OpenSSH do sistema (ssh + sshpass).
 *
 * - Autenticação por senha (via sshpass, senha passada por variável de ambiente, nunca na linha de comando)
 *   ou por chave privada (gravada em arquivo temporário 0600 e apagada logo após o uso).
 * - Chave do host fixada no primeiro uso (TOFU) em <data_dir>/ssh/known_hosts: se mudar, a conexão é recusada.
 * - Ignora ~/.ssh/config e agentes do sistema para que nada fora desta classe influencie a conexão.
 * - Esta classe NÃO aceita comandos vindos do usuário: só OsCollector monta o script, a partir de constantes.
 */
final class SshClient
{
    private const MAX_OUTPUT = 2_000_000;

    /** @param array{host:string,port:int,username:string,auth:string,password?:?string,private_key?:?string,passphrase?:?string} $c */
    public function __construct(private array $c)
    {
    }

    /** Valida e normaliza a entrada do formulário. */
    public static function fromInput(array $in, string $defaultHost): array
    {
        $host = trim((string) ($in['ssh_host'] ?? '')) ?: $defaultHost;
        if (!preg_match('/^[A-Za-z0-9.\-_:]+$/', $host) || str_starts_with($host, '-')) {
            throw new \InvalidArgumentException('Host SSH inválido.');
        }
        $user = trim((string) ($in['ssh_user'] ?? ''));
        if (!preg_match('/^[A-Za-z0-9._][A-Za-z0-9._\-]{0,63}$/', $user)) {
            throw new \InvalidArgumentException('Usuário SSH inválido.');
        }
        $port = (int) ($in['ssh_port'] ?? 22) ?: 22;
        if ($port < 1 || $port > 65535) {
            throw new \InvalidArgumentException('Porta SSH inválida.');
        }
        $auth = ($in['ssh_auth'] ?? 'password') === 'key' ? 'key' : 'password';
        $c = ['host' => $host, 'port' => $port, 'username' => $user, 'auth' => $auth, 'sudo' => !empty($in['ssh_sudo'])];
        if ($auth === 'key') {
            $key = str_replace("\r\n", "\n", trim((string) ($in['ssh_key'] ?? ''))) . "\n";
            if (!preg_match('/^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\n/', $key)) {
                throw new \InvalidArgumentException('Cole a chave privada completa (bloco -----BEGIN … PRIVATE KEY-----).');
            }
            $c['private_key'] = $key;
            $c['passphrase'] = (string) ($in['ssh_passphrase'] ?? '');
        } else {
            $c['password'] = (string) ($in['ssh_password'] ?? '');
            if ($c['password'] === '') {
                throw new \InvalidArgumentException('Informe a senha SSH (ou use chave privada).');
            }
        }
        if ($c['sudo']) {
            // Vazio: reaproveita a senha SSH (caso comum) ou depende de NOPASSWD no sudoers
            $c['sudo_password'] = (string) ($in['ssh_sudo_password'] ?? '') ?: ($c['password'] ?? '');
        }
        return $c;
    }

    public function sudo(): bool
    {
        return !empty($this->c['sudo']);
    }

    public function sudoPassword(): string
    {
        return (string) ($this->c['sudo_password'] ?? '');
    }

    public function label(): string
    {
        return "{$this->c['username']}@{$this->c['host']}:{$this->c['port']}";
    }

    private static function dir(): string
    {
        $d = rtrim((string) Config::get('data_dir', APP_ROOT . '/storage'), '/') . '/ssh';
        if (!is_dir($d)) {
            @mkdir($d, 0700, true);
        }
        @chmod($d, 0700);
        return $d;
    }

    public static function knownHostsFile(): string
    {
        return self::dir() . '/known_hosts';
    }

    private static function bin(string $name): ?string
    {
        foreach (['/usr/bin/', '/bin/', '/usr/local/bin/'] as $p) {
            if (is_executable($p . $name)) {
                return $p . $name;
            }
        }
        return null;
    }

    /**
     * Executa o script remoto (interpretado por /bin/sh) e devolve stdout, stderr e código de saída.
     * @return array{stdout:string,stderr:string,exit:int,ms:int}
     */
    public function run(string $script, int $timeout = 45, string $stdin = ''): array
    {
        $ssh = self::bin('ssh');
        if (!$ssh) {
            throw new \RuntimeException('Cliente SSH ausente no servidor do analisador. Instale: apt-get install openssh-client sshpass');
        }
        $c = $this->c;
        $args = [$ssh, '-F', '/dev/null', '-T', '-p', (string) $c['port'],
            '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2',
            '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=' . self::knownHostsFile(),
            '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR', '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no',
            '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no', '-o', 'IdentityAgent=none', '-o', 'NumberOfPasswordPrompts=1',
        ];
        $env = ['PATH' => '/usr/bin:/bin', 'LC_ALL' => 'C', 'HOME' => self::dir()];
        $keyFile = null;
        try {
            if ($c['auth'] === 'key') {
                $keyFile = tempnam(self::dir(), 'k');
                chmod($keyFile, 0600);
                file_put_contents($keyFile, $c['private_key']);
                $args = array_merge($args, ['-i', $keyFile, '-o', 'IdentitiesOnly=yes', '-o', 'PasswordAuthentication=no',
                    '-o', 'KbdInteractiveAuthentication=no', '-o', 'PreferredAuthentications=publickey']);
                if (($c['passphrase'] ?? '') !== '') {
                    $args = array_merge([self::sshpass(), '-e', '-P', 'passphrase'], $args);
                    $env['SSHPASS'] = $c['passphrase'];
                } else {
                    $args = array_merge($args, ['-o', 'BatchMode=yes']);
                }
            } else {
                $args = array_merge([self::sshpass(), '-e'], $args, ['-o', 'PubkeyAuthentication=no',
                    '-o', 'PreferredAuthentications=password,keyboard-interactive']);
                $env['SSHPASS'] = $c['password'];
            }
            $args[] = '--';
            $args[] = $c['username'] . '@' . $c['host'];
            $args[] = 'sh -c ' . escapeshellarg($script);
            return $this->exec($args, $env, $timeout, $stdin);
        } finally {
            if ($keyFile && is_file($keyFile)) {
                file_put_contents($keyFile, str_repeat("\0", strlen($c['private_key'] ?? '')));
                @unlink($keyFile);
            }
        }
    }

    private static function sshpass(): string
    {
        return self::bin('sshpass') ?? throw new \RuntimeException('sshpass ausente no servidor do analisador (necessário para senha/passphrase). Instale: apt-get install sshpass');
    }

    private function exec(array $args, array $env, int $timeout, string $stdin = ''): array
    {
        $t0 = microtime(true);
        $p = proc_open($args, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
        if (!is_resource($p)) {
            throw new \RuntimeException('Falha ao iniciar o cliente SSH.');
        }
        // A senha do sudo (quando houver) vai pela entrada padrão da sessão: nunca aparece em argv nem no ps remoto
        if ($stdin !== '') {
            fwrite($pipes[0], $stdin);
        }
        fclose($pipes[0]);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = $err = '';
        $deadline = $t0 + $timeout;
        while (true) {
            $r = [$pipes[1], $pipes[2]];
            $w = $e = null;
            if (feof($pipes[1]) && feof($pipes[2])) {
                break;
            }
            if (microtime(true) > $deadline) {
                proc_terminate($p, 9);
                foreach ([1, 2] as $i) {
                    fclose($pipes[$i]);
                }
                proc_close($p);
                throw new \RuntimeException("Tempo esgotado ({$timeout}s) na coleta via SSH em {$this->label()}.");
            }
            if (@stream_select($r, $w, $e, 0, 200_000) === false) {
                break;
            }
            foreach ($r as $s) {
                $chunk = (string) fread($s, 65536);
                if ($s === $pipes[1]) {
                    $out .= $chunk;
                } else {
                    $err .= $chunk;
                }
            }
            if (strlen($out) > self::MAX_OUTPUT) {
                $out = substr($out, 0, self::MAX_OUTPUT);
                break;
            }
        }
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($p);
        $res = ['stdout' => $out, 'stderr' => trim($err), 'exit' => $code, 'ms' => (int) ((microtime(true) - $t0) * 1000)];
        // 255 = erro do próprio ssh (conexão/autenticação); 5/6 = sshpass (senha incorreta / chave do host)
        if ($code === 255 || ($code >= 1 && $code <= 6 && $out === '')) {
            throw new \RuntimeException(self::friendly($res['stderr'], $code, $this->c['host'], (int) $this->c['port']));
        }
        return $res;
    }

    /** Impressão digital SHA256 da chave do host, já fixada em known_hosts. */
    public function fingerprint(): ?string
    {
        $kg = self::bin('ssh-keygen');
        $host = $this->c['port'] === 22 ? $this->c['host'] : "[{$this->c['host']}]:{$this->c['port']}";
        if (!$kg || !is_file(self::knownHostsFile())) {
            return null;
        }
        $o = shell_exec(escapeshellarg($kg) . ' -l -F ' . escapeshellarg($host) . ' -f ' . escapeshellarg(self::knownHostsFile()) . ' 2>/dev/null');
        return preg_match('/(\d+ SHA256:\S+.*)$/m', (string) $o, $m) ? trim($m[1]) : null;
    }

    public static function forget(string $host, int $port = 22): bool
    {
        $kg = self::bin('ssh-keygen');
        $h = $port === 22 ? $host : "[$host]:$port";
        if (!$kg || !is_file(self::knownHostsFile())) {
            return false;
        }
        exec(escapeshellarg($kg) . ' -R ' . escapeshellarg($h) . ' -f ' . escapeshellarg(self::knownHostsFile()) . ' 2>&1', $o, $rc);
        @unlink(self::knownHostsFile() . '.old');
        return $rc === 0;
    }

    private static function friendly(string $err, int $code, string $host, int $port = 22): string
    {
        $forget = $host . ($port !== 22 ? " --port=$port" : '');
        return match (true) {
            $code === 6 || str_contains($err, 'REMOTE HOST IDENTIFICATION HAS CHANGED') || str_contains($err, 'Host key verification failed') =>
                "A chave SSH do servidor $host mudou desde a primeira conexão (possível reinstalação ou ataque man-in-the-middle). "
                . "Conexão recusada. Se a troca for legítima, um administrador deve rodar: sudo -u www-data php bin/console ssh:forget $forget",
            $code === 5, str_contains($err, 'Permission denied') => 'Usuário, senha ou chave SSH recusados pelo servidor.',
            str_contains($err, 'Connection refused') => "SSH recusado em $host: verifique a porta e se o sshd está ativo.",
            str_contains($err, 'timed out'), str_contains($err, 'Connection timed out') => "Tempo de conexão SSH esgotado: $host inacessível ou firewall bloqueando.",
            str_contains($err, 'Could not resolve hostname') => "Não foi possível resolver o host SSH $host.",
            str_contains($err, 'invalid format'), str_contains($err, 'incorrect passphrase'), str_contains($err, 'bad passphrase') => 'Chave privada inválida ou passphrase incorreta.',
            default => 'Falha SSH: ' . mb_substr($err !== '' ? $err : "código $code", 0, 300),
        };
    }
}
