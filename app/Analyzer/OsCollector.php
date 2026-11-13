<?php
declare(strict_types=1);

namespace App\Analyzer;

/**
 * Coleta do sistema operacional do servidor do banco via SSH, estritamente somente leitura.
 *
 * Os comandos vêm SOMENTE da lista fixa abaixo (nada digitado pelo usuário vira comando). O único valor
 * dinâmico é o diretório de dados do SGBD, lido do próprio banco, validado por regex e escapado.
 * Nada usa sudo: o que exigir privilégio (ex.: dmesg com kernel.dmesg_restrict=1) é registrado como indisponível.
 */
final class OsCollector
{
    /** chave => [descrição, comando sh]. Apenas leitura de /proc, /sys e utilitários de consulta. */
    public const COMMANDS = [
        'uname'     => ['Kernel', 'uname -srm'],
        'os'        => ['Distribuição', 'cat /etc/os-release'],
        'virt'      => ['Virtualização', 'systemd-detect-virt 2>/dev/null || echo unknown'],
        'uptime'    => ['Uptime', 'cat /proc/uptime'],
        'nproc'     => ['vCPUs', 'nproc'],
        'cpuinfo'   => ['CPU', "grep -m1 -E '^model name' /proc/cpuinfo; grep -E '^cpu MHz' /proc/cpuinfo | head -n 64; cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null || true"],
        'loadavg'   => ['Load average', 'cat /proc/loadavg'],
        'meminfo'   => ['/proc/meminfo', 'cat /proc/meminfo'],
        'free'      => ['free -m', 'free -m'],
        'swaps'     => ['Swap', 'cat /proc/swaps'],
        'vm'        => ['sysctl vm.*', 'for k in swappiness overcommit_memory overcommit_ratio nr_hugepages dirty_ratio dirty_background_ratio dirty_bytes dirty_background_bytes zone_reclaim_mode min_free_kbytes; do printf "%s=" "$k"; cat "/proc/sys/vm/$k" 2>/dev/null || echo; done'],
        'thp'       => ['Transparent Huge Pages', 'cat /sys/kernel/mm/transparent_hugepage/enabled /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null'],
        'vmstat'    => ['vmstat 2 5', 'vmstat 2 5'],
        'oom'       => ['Eventos de OOM', "{ if dmesg >/dev/null 2>&1; then dmesg -T 2>/dev/null; elif journalctl -k -q --no-pager -n 1 2>/dev/null | grep -q .; then journalctl -k -q --no-pager --since '-30 days' 2>/dev/null; else echo '__NO_ACCESS__'; fi; } | grep -i -E 'out of memory|oom-kill|oom_reaper|killed process|__NO_ACCESS__' | tail -n 30"],
        'df'        => ['Uso de disco', 'df -P -B1 -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null || df -P -B1'],
        'dfi'       => ['Inodes', 'df -P -i -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null || df -P -i'],
        'lsblk'     => ['Discos', 'lsblk -d -b -n -o NAME,ROTA,TYPE,SIZE,MODEL 2>/dev/null; for f in /sys/block/*/queue/rotational; do printf "%s=" "$f"; cat "$f"; done 2>/dev/null'],
        'ps'        => ['Processos por memória', 'ps -eo rss=,pcpu=,comm= --sort=-rss 2>/dev/null | head -n 15'],
        'limits'    => ['ulimit do usuário', 'ulimit -n'],
    ];

    /** Subconjunto rápido usado no "Testar SSH" para detectar o hardware. */
    private const QUICK = ['uname', 'virt', 'nproc', 'cpuinfo', 'meminfo', 'lsblk'];

    public function __construct(private SshClient $ssh)
    {
    }

    public static function validDataDir(?string $dir): ?string
    {
        return $dir && preg_match('#^/[A-Za-z0-9._/\-]{1,250}$#', $dir) && !str_contains($dir, '..') ? rtrim($dir, '/') ?: '/' : null;
    }

    private static function script(array $keys, ?string $dataDir): string
    {
        $s = "export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C\n";
        foreach ($keys as $k) {
            $s .= "echo '@@@BEGIN $k'\n{ " . self::COMMANDS[$k][1] . "\n} 2>&1\necho \"@@@END $k \$?\"\n";
        }
        if ($dataDir) {
            $d = escapeshellarg($dataDir);
            $s .= "echo '@@@BEGIN datadir'\n{ df -P -B1 $d; df -P -i $d | tail -n 1; findmnt -n -o SOURCE,FSTYPE,OPTIONS -T $d; } 2>&1\necho \"@@@END datadir \$?\"\n";
        }
        return $s;
    }

    /** @return array{raw:array,parsed:array,hardware:array,ms:int,fingerprint:?string} */
    public function collect(?string $dataDir = null, bool $quick = false): array
    {
        $keys = $quick ? self::QUICK : array_keys(self::COMMANDS);
        $dataDir = self::validDataDir($dataDir);
        $res = $this->ssh->run(self::script($keys, $quick ? null : $dataDir), $quick ? 25 : 60);
        $raw = [];
        if (preg_match_all('/^@@@BEGIN (\w+)\n(.*?)^@@@END \1 (\d+)$/ms', $res['stdout'], $mm, PREG_SET_ORDER)) {
            foreach ($mm as $m) {
                $raw[$m[1]] = ['out' => mb_substr(rtrim($m[2]), 0, 20000), 'rc' => (int) $m[3]];
            }
        }
        if (!$raw) {
            throw new \RuntimeException('A sessão SSH abriu mas não devolveu a coleta (shell restrito?). Saída: ' . mb_substr(trim($res['stdout'] . ' ' . $res['stderr']), 0, 200));
        }
        $parsed = self::parse($raw, $dataDir);
        return ['raw' => $raw, 'parsed' => $parsed, 'hardware' => self::hardware($parsed), 'ms' => $res['ms'], 'fingerprint' => $this->ssh->fingerprint()];
    }

    /* ------------------------------------------------------------------ */
    /* Parsing                                                             */
    /* ------------------------------------------------------------------ */

    public static function parse(array $raw, ?string $dataDir = null): array
    {
        $o = fn(string $k): string => (string) ($raw[$k]['out'] ?? '');
        $p = [];

        $p['kernel'] = trim($o('uname')) ?: null;
        if (preg_match('/^PRETTY_NAME="?([^"\n]+)"?/m', $o('os'), $m)) {
            $p['distro'] = $m[1];
        }
        $virt = trim($o('virt'));
        $p['virtualization'] = $virt !== '' && $virt !== 'unknown' ? $virt : null;
        if (preg_match('/^([\d.]+)/', $o('uptime'), $m)) {
            $p['uptime_days'] = round((float) $m[1] / 86400, 1);
        }
        $p['vcpu'] = ctype_digit(trim($o('nproc'))) ? (int) trim($o('nproc')) : null;

        $cpu = $o('cpuinfo');
        if (preg_match('/^model name\s*:\s*(.+)$/m', $cpu, $m)) {
            $p['cpu_model'] = trim(preg_replace('/\s+/', ' ', $m[1]));
        }
        $ghz = null;
        if (preg_match('/@\s*([\d.]+)\s*GHz/i', $p['cpu_model'] ?? '', $m)) {
            $ghz = (float) $m[1];
        } elseif (preg_match('/^(\d{6,8})$/m', $cpu, $m)) {
            $ghz = round((int) $m[1] / 1e6, 2); // cpuinfo_max_freq em kHz
        } elseif (preg_match_all('/^cpu MHz\s*:\s*([\d.]+)/m', $cpu, $mm) && $mm[1]) {
            $ghz = round(max(array_map('floatval', $mm[1])) / 1000, 2);
        }
        $p['clock_ghz'] = $ghz;

        if (preg_match('/^([\d.]+) ([\d.]+) ([\d.]+) (\d+)\/(\d+)/', $o('loadavg'), $m)) {
            $p['load'] = ['1m' => (float) $m[1], '5m' => (float) $m[2], '15m' => (float) $m[3], 'running' => (int) $m[4], 'threads' => (int) $m[5]];
        }

        $mi = [];
        foreach (explode("\n", $o('meminfo')) as $l) {
            if (preg_match('/^(\w+(?:\(\w+\))?):\s+(\d+)(?:\s+kB)?$/', trim($l), $m)) {
                $mi[$m[1]] = (int) $m[2];
            }
        }
        if ($mi) {
            $kb = fn(string $k) => isset($mi[$k]) ? $mi[$k] * 1024 : null;
            $p['mem'] = [
                'total' => $kb('MemTotal'), 'available' => $kb('MemAvailable'), 'free' => $kb('MemFree'),
                'cached' => $kb('Cached'), 'buffers' => $kb('Buffers'), 'shmem' => $kb('Shmem'), 'dirty' => $kb('Dirty'),
                'swap_total' => $kb('SwapTotal'), 'swap_free' => $kb('SwapFree'),
                'swap_used' => isset($mi['SwapTotal'], $mi['SwapFree']) ? ($mi['SwapTotal'] - $mi['SwapFree']) * 1024 : null,
                'committed_as' => $kb('Committed_AS'), 'commit_limit' => $kb('CommitLimit'),
                'hugepages_total' => $mi['HugePages_Total'] ?? null, 'hugepages_free' => $mi['HugePages_Free'] ?? null,
                'hugepage_size' => $kb('Hugepagesize'), 'anon_hugepages' => $kb('AnonHugePages'),
            ];
            if ($p['mem']['total'] && $p['mem']['available'] !== null) {
                $p['mem']['available_pct'] = round(100 * $p['mem']['available'] / $p['mem']['total'], 1);
            }
            if ($p['mem']['swap_total']) {
                $p['mem']['swap_used_pct'] = round(100 * $p['mem']['swap_used'] / $p['mem']['swap_total'], 1);
            }
        }

        $swaps = [];
        foreach (array_slice(explode("\n", trim($o('swaps'))), 1) as $l) {
            $c = preg_split('/\s+/', trim($l));
            if (count($c) >= 4) {
                $swaps[] = ['device' => $c[0], 'type' => $c[1], 'size' => (int) $c[2] * 1024, 'used' => (int) $c[3] * 1024];
            }
        }
        $p['swap_devices'] = $swaps;

        $vm = [];
        foreach (explode("\n", $o('vm')) as $l) {
            if (preg_match('/^(\w+)=(-?\d+)\s*$/', trim($l), $m)) {
                $vm[$m[1]] = (int) $m[2];
            }
        }
        $p['vm'] = $vm;

        $thp = explode("\n", trim($o('thp')));
        $sel = fn(?string $l) => $l && preg_match('/\[(\w+)\]/', $l, $m) ? $m[1] : null;
        $p['thp'] = ['enabled' => $sel($thp[0] ?? null), 'defrag' => $sel($thp[1] ?? null)];

        $p['vmstat'] = self::parseVmstat($o('vmstat'));

        $oom = $o('oom');
        $p['oom_access'] = !str_contains($oom, '__NO_ACCESS__');
        $p['oom_events'] = array_values(array_filter(array_map('trim', explode("\n", str_replace('__NO_ACCESS__', '', $oom)))));
        $p['oom_events'] = array_slice($p['oom_events'], -30);

        $p['filesystems'] = self::parseDf($o('df'), $o('dfi'));

        $disks = [];
        foreach (explode("\n", $o('lsblk')) as $l) {
            if (preg_match('/^(loop|ram|zram|sr|fd)\d|^\/sys\/block\/(loop|ram|zram|sr|fd)\d/', trim($l))) {
                continue;
            }
            if (preg_match('/^(\S+)\s+([01])\s+(disk)\s+(\d+)\s*(.*)$/', trim($l), $m)) {
                $disks[$m[1]] = ['name' => $m[1], 'rotational' => $m[2] === '1', 'size' => (int) $m[4], 'model' => trim($m[5]) ?: null];
            } elseif (preg_match('#^/sys/block/([^/]+)/queue/rotational=([01])#', trim($l), $m) && !isset($disks[$m[1]]) && !preg_match('/^(loop|ram|zram|sr)/', $m[1])) {
                $disks[$m[1]] = ['name' => $m[1], 'rotational' => $m[2] === '1', 'size' => null, 'model' => null];
            }
        }
        $p['disks'] = array_values($disks);

        $procs = [];
        foreach (explode("\n", trim($o('ps'))) as $l) {
            if (preg_match('/^\s*(\d+)\s+([\d.]+)\s+(.+)$/', $l, $m)) {
                $procs[] = ['rss' => (int) $m[1] * 1024, 'cpu_pct' => (float) $m[2], 'command' => trim($m[3])];
            }
        }
        $p['top_processes'] = $procs;
        $p['nofile_limit'] = trim($o('limits')) ?: null;

        if ($dataDir && isset($raw['datadir'])) {
            $lines = explode("\n", trim($raw['datadir']['out']));
            $fs = self::parseDf(implode("\n", array_slice($lines, 0, 2)), "header\n" . ($lines[2] ?? ''));
            $mnt = preg_split('/\s+/', trim($lines[3] ?? ''));
            $p['data_dir'] = ['path' => $dataDir] + ($fs[0] ?? []) + (count($mnt) >= 2 ? ['device' => $mnt[0], 'fstype' => $mnt[1], 'mount_options' => $mnt[2] ?? null] : []);
        }
        return $p;
    }

    private static function parseVmstat(string $out): ?array
    {
        $rows = [];
        $head = null;
        foreach (explode("\n", trim($out)) as $l) {
            $c = preg_split('/\s+/', trim($l));
            if (in_array('si', $c, true) && in_array('wa', $c, true)) {
                $head = $c;
            } elseif ($head && count($c) === count($head) && ctype_digit($c[0])) {
                $rows[] = array_combine($head, array_map('intval', $c));
            }
        }
        if (count($rows) > 1) {
            array_shift($rows); // a primeira linha é a média desde o boot
        }
        if (!$rows) {
            return null;
        }
        $avg = fn(string $k) => round(array_sum(array_column($rows, $k)) / count($rows), 1);
        return ['samples' => count($rows), 'r' => $avg('r'), 'b' => $avg('b'), 'si' => $avg('si'), 'so' => $avg('so'),
            'us' => $avg('us'), 'sy' => $avg('sy'), 'id' => $avg('id'), 'wa' => $avg('wa'), 'st' => isset($rows[0]['st']) ? $avg('st') : null, 'cs' => $avg('cs')];
    }

    private static function parseDf(string $df, string $dfi): array
    {
        $inodes = [];
        foreach (array_slice(explode("\n", trim($dfi)), 1) as $l) {
            $c = preg_split('/\s+/', trim($l));
            if (count($c) >= 6) {
                $inodes[$c[5]] = rtrim($c[4], '%') === '-' ? null : (int) rtrim($c[4], '%');
            }
        }
        $fs = [];
        foreach (array_slice(explode("\n", trim($df)), 1) as $l) {
            $c = preg_split('/\s+/', trim($l));
            if (count($c) >= 6 && is_numeric($c[1]) && (int) $c[1] > 0) {
                $mount = implode(' ', array_slice($c, 5));
                $fs[] = ['filesystem' => $c[0], 'mount' => $mount, 'size' => (int) $c[1], 'used' => (int) $c[2], 'avail' => (int) $c[3],
                    'used_pct' => (int) rtrim($c[4], '%'), 'inodes_pct' => $inodes[$mount] ?? null];
            }
        }
        return $fs;
    }

    /** Hardware detectado, no formato de hardware_json. */
    public static function hardware(array $p): array
    {
        $hw = [];
        if (!empty($p['vcpu'])) {
            $hw['vcpu'] = $p['vcpu'];
        }
        if (!empty($p['clock_ghz'])) {
            $hw['clock_ghz'] = $p['clock_ghz'];
        }
        if (!empty($p['mem']['total'])) {
            // MemTotal desconta a memória reservada pelo kernel; arredonda para o tamanho "comercial"
            $gb = $p['mem']['total'] / 1024 ** 3;
            $hw['ram_gb'] = $gb >= 3 ? (float) ceil($gb - 0.15) : round($gb, 1);
        }
        $disks = array_values(array_filter($p['disks'] ?? [], fn($d) => !preg_match('/^(loop|ram|zram|sr|fd)/', $d['name'])));
        if ($disks) {
            $dataDev = basename((string) ($p['data_dir']['device'] ?? ''));
            $main = null;
            foreach ($disks as $d) {
                if ($dataDev !== '' && str_starts_with($dataDev, $d['name'])) {
                    $main = $d;
                }
            }
            $main ??= $disks[0];
            $hw['disk'] = str_starts_with($main['name'], 'nvme') ? 'nvme' : ($main['rotational'] ? 'hdd' : 'ssd');
            if ($main['rotational'] && !empty($p['virtualization']) && $p['virtualization'] !== 'none') {
                // Em VMs o disco virtual costuma reportar ROTA=1 mesmo sobre SSD/SAN: não afirma HDD.
                unset($hw['disk']);
            }
        }
        return $hw;
    }

    /* ------------------------------------------------------------------ */
    /* Achados                                                             */
    /* ------------------------------------------------------------------ */

    /** @return list<array{severity:string,category:string,title:string,detail:string,object:?string,fix_sql:?string}> */
    public static function findings(array $p, string $engine, array $settings = []): array
    {
        $f = [];
        $add = function (string $sev, string $title, string $detail, ?string $fix = null, ?string $obj = null) use (&$f) {
            $f[] = ['severity' => $sev, 'category' => 'os', 'title' => $title, 'detail' => $detail, 'object' => $obj, 'fix_sql' => $fix];
        };
        $isPg = $engine === 'postgresql';
        $mem = $p['mem'] ?? [];
        $vm = $p['vm'] ?? [];
        $vs = $p['vmstat'] ?? null;

        if (!empty($p['oom_events'])) {
            $killed = array_filter($p['oom_events'], fn($l) => stripos($l, 'killed process') !== false);
            $add('critical', 'OOM killer acionado no servidor',
                count($p['oom_events']) . ' linha(s) de OOM no log do kernel (' . count($killed) . ' processo(s) morto(s)). Última: ' . mb_substr((string) end($p['oom_events']), 0, 220)
                . '. Reduza limites que permitem sobrecomprometer memória (conexões, work_mem/sort_buffer, workers) ou aumente a RAM.');
        } elseif (isset($p['oom_access']) && !$p['oom_access']) {
            $add('low', 'Sem acesso ao log do kernel para verificar OOM',
                'dmesg e journalctl -k foram negados ao usuário SSH (kernel.dmesg_restrict=1). Para incluir o histórico de OOM no laudo, adicione o usuário ao grupo adm/systemd-journal (somente leitura).');
        }

        if (isset($mem['available_pct']) && $mem['available_pct'] < 10) {
            $add('high', 'Memória disponível baixa', "MemAvailable em {$mem['available_pct']}% (" . human_bytes($mem['available']) . ' de ' . human_bytes($mem['total']) . ').');
        }
        if (!empty($mem['swap_total']) && ($mem['swap_used_pct'] ?? 0) > 20) {
            $add(($vs['si'] ?? 0) + ($vs['so'] ?? 0) > 0 ? 'high' : 'medium', 'Swap em uso',
                human_bytes($mem['swap_used']) . " de swap ocupados ({$mem['swap_used_pct']}%)" . ($vs ? ", com si/so médio de {$vs['si']}/{$vs['so']} KB/s na amostra." : '.'));
        } elseif ($vs && ($vs['si'] > 0 || $vs['so'] > 0)) {
            $add('high', 'Atividade de swap durante a coleta', "vmstat mostrou si={$vs['si']} so={$vs['so']} KB/s: há paginação para disco agora, o que derruba a latência do banco.");
        }
        if (empty($mem['swap_total']) && isset($mem['total'])) {
            $add('low', 'Servidor sem swap', 'Sem swap qualquer pico de memória vira OOM imediato. Uma swap pequena (1–2 GB) com vm.swappiness baixo dá margem sem afetar a performance.');
        }
        if (isset($vm['swappiness']) && $vm['swappiness'] > 10) {
            $add('low', "vm.swappiness = {$vm['swappiness']}", 'Para servidor dedicado a banco, use 1–10 para o kernel preferir liberar cache a paginar memória do SGBD.',
                "# /etc/sysctl.d/90-db.conf\nvm.swappiness = 10\n# aplicar: sysctl --system");
        }
        if ($isPg && isset($vm['overcommit_memory']) && $vm['overcommit_memory'] !== 2 && !empty($p['oom_events'])) {
            $add('medium', "vm.overcommit_memory = {$vm['overcommit_memory']} com histórico de OOM",
                'A documentação do PostgreSQL recomenda vm.overcommit_memory=2 para evitar que o OOM killer mate o postmaster. Ajuste vm.overcommit_ratio para que CommitLimit fique próximo da RAM.',
                "# /etc/sysctl.d/90-db.conf\nvm.overcommit_memory = 2\nvm.overcommit_ratio = 90   # revise com a RAM e a swap do servidor\n# aplicar: sysctl --system");
        }
        if (($p['thp']['enabled'] ?? null) === 'always') {
            $add('medium', 'Transparent Huge Pages em "always"',
                ($isPg ? 'PostgreSQL' : 'MySQL/MariaDB') . ' recomenda desativar THP (picos de latência por compactação de memória). Use "never" ou "madvise".',
                "echo never > /sys/kernel/mm/transparent_hugepage/enabled\necho never > /sys/kernel/mm/transparent_hugepage/defrag\n# persistente: transparent_hugepage=never na linha do kernel (GRUB)");
        }
        $sb = (int) ($settings['shared_buffers']['bytes'] ?? 0);
        if ($isPg && $sb >= 8 * 1024 ** 3 && (int) ($mem['hugepages_total'] ?? 0) === 0) {
            $add('low', 'Huge pages não reservadas para shared_buffers de ' . human_bytes($sb),
                'Com shared_buffers grande, reservar huge pages (vm.nr_hugepages) e usar huge_pages=on reduz a tabela de páginas e a latência.',
                "# calcule: (shared_buffers + ~10%) / Hugepagesize\nvm.nr_hugepages = " . (int) ceil($sb * 1.1 / max(1, (int) ($mem['hugepage_size'] ?? 2097152))));
        }

        $cpu = (int) ($p['vcpu'] ?? 0);
        if ($cpu > 0 && isset($p['load']['5m']) && $p['load']['5m'] > $cpu * 1.5) {
            $add('medium', 'Load average alto', "Load de 5 min = {$p['load']['5m']} para $cpu vCPU(s): há fila de processos por CPU ou I/O.");
        }
        if ($vs && $vs['wa'] >= 20) {
            $add('medium', 'I/O wait alto', "iowait médio de {$vs['wa']}% na amostra do vmstat: o disco está limitando o servidor.");
        }
        if ($vs && ($vs['st'] ?? 0) >= 10) {
            $add('medium', 'CPU steal alto (VM)', "steal médio de {$vs['st']}%: o hypervisor está retirando CPU desta VM. Verifique overcommit do host.");
        }

        $checked = [];
        foreach (array_merge(isset($p['data_dir']['mount']) ? [$p['data_dir'] + ['_data' => true]] : [], $p['filesystems'] ?? []) as $fs) {
            if (isset($checked[$fs['mount']])) {
                continue;
            }
            $checked[$fs['mount']] = true;
            $what = !empty($fs['_data']) ? "Diretório de dados ({$fs['path']}, em {$fs['mount']})" : "Sistema de arquivos {$fs['mount']}";
            $u = (int) ($fs['used_pct'] ?? 0);
            if ($u >= 80 && (!empty($fs['_data']) || in_array($fs['mount'], ['/', '/var', '/var/lib', '/tmp'], true))) {
                $add($u >= 95 ? 'critical' : ($u >= 90 ? 'high' : 'medium'), "$what com {$u}% de uso",
                    'Livre: ' . human_bytes($fs['avail']) . ' de ' . human_bytes($fs['size']) . '. Disco cheio para o banco (escrita de WAL/redo falha).', null, $fs['mount']);
            }
            if (($fs['inodes_pct'] ?? 0) >= 85) {
                $add('high', "$what com {$fs['inodes_pct']}% dos inodes usados", 'Sem inodes livres não é possível criar arquivos mesmo com espaço sobrando.', null, $fs['mount']);
            }
        }
        $opts = (string) ($p['data_dir']['mount_options'] ?? '');
        if ($opts !== '' && !str_contains($opts, 'noatime') && !str_contains($opts, 'relatime')) {
            $add('low', 'Diretório de dados montado com atime', "Opções de montagem: $opts. Use noatime para evitar escrita a cada leitura.");
        }

        $dbProc = $isPg ? 'postgres' : 'mysqld|mariadbd';
        $other = array_filter($p['top_processes'] ?? [], fn($x) => !preg_match('/^(' . $dbProc . ')/', $x['command']));
        if (!empty($mem['total']) && $other) {
            $big = array_values(array_filter($other, fn($x) => $x['rss'] > $mem['total'] * 0.10));
            if ($big) {
                $add('medium', 'Outros processos disputando memória com o banco',
                    implode(', ', array_map(fn($x) => $x['command'] . ' (' . human_bytes($x['rss']) . ')', array_slice($big, 0, 4))) . ' usam mais de 10% da RAM cada. Considere isso no dimensionamento ou isole o banco.');
            }
        }
        return $f;
    }

    /** Linhas legíveis (rótulo => valor) para o laudo exportado. */
    public static function humanRows(array $p): array
    {
        $mem = $p['mem'] ?? [];
        $vs = $p['vmstat'] ?? null;
        $dd = $p['data_dir'] ?? [];
        return array_filter([
            'Sistema' => implode(' · ', array_filter([$p['distro'] ?? null, $p['kernel'] ?? null, $p['virtualization'] ?? null])),
            'CPU' => trim(($p['vcpu'] ?? '?') . ' vCPU · ' . ($p['cpu_model'] ?? '')) . (isset($p['load']) ? " · load {$p['load']['1m']} / {$p['load']['5m']} / {$p['load']['15m']}" : ''),
            'Memória' => isset($mem['total']) ? human_bytes($mem['total']) . ' total · ' . human_bytes($mem['available']) . ' disponível'
                . (isset($mem['available_pct']) ? " ({$mem['available_pct']}%)" : '') . ' · cache ' . human_bytes($mem['cached']) : null,
            'Swap' => isset($mem['swap_total']) ? ($mem['swap_total'] ? human_bytes($mem['swap_used']) . ' usada de ' . human_bytes($mem['swap_total']) : 'sem swap') : null,
            'Commit' => isset($mem['committed_as']) ? 'Committed_AS ' . human_bytes($mem['committed_as']) . ' · CommitLimit ' . human_bytes($mem['commit_limit']) : null,
            'sysctl vm' => implode(', ', array_map(fn($k, $v) => "$k=$v", array_keys($p['vm'] ?? []), $p['vm'] ?? [])) ?: null,
            'Huge pages' => isset($mem['hugepages_total']) ? "nr_hugepages {$mem['hugepages_total']} · THP " . ($p['thp']['enabled'] ?? '?') : null,
            'vmstat (média)' => $vs ? "us {$vs['us']}% sy {$vs['sy']}% wa {$vs['wa']}% id {$vs['id']}%" . ($vs['st'] !== null ? " st {$vs['st']}%" : '') . " · si/so {$vs['si']}/{$vs['so']} · r {$vs['r']}" : null,
            'OOM no kernel' => ($p['oom_access'] ?? true) ? count($p['oom_events'] ?? []) . ' evento(s)' : 'sem permissão para ler o log do kernel',
            'Diretório de dados' => isset($dd['size']) ? "{$dd['path']} em {$dd['mount']} (" . ($dd['fstype'] ?? '?') . "): {$dd['used_pct']}% usado, " . human_bytes($dd['avail']) . ' livres de ' . human_bytes($dd['size']) : null,
            'Montagens' => implode(' · ', array_map(fn($fs) => "{$fs['mount']} {$fs['used_pct']}%", $p['filesystems'] ?? [])) ?: null,
        ], fn($v) => $v !== null && $v !== '');
    }

    /** Resumo compacto para o prompt da IA e para o motor de dimensionamento. */
    public static function summary(array $p): array
    {
        $mem = $p['mem'] ?? [];
        return array_filter([
            'kernel' => $p['kernel'] ?? null, 'distro' => $p['distro'] ?? null, 'virtualizacao' => $p['virtualization'] ?? null,
            'uptime_dias' => $p['uptime_days'] ?? null, 'vcpu' => $p['vcpu'] ?? null, 'cpu' => $p['cpu_model'] ?? null, 'clock_ghz' => $p['clock_ghz'] ?? null,
            'load' => $p['load'] ?? null,
            'memoria' => $mem ? array_filter([
                'total' => human_bytes($mem['total']), 'disponivel' => human_bytes($mem['available']) . (isset($mem['available_pct']) ? " ({$mem['available_pct']}%)" : ''),
                'cache' => human_bytes($mem['cached']), 'shmem' => human_bytes($mem['shmem']),
                'swap_total' => human_bytes($mem['swap_total']), 'swap_usada' => human_bytes($mem['swap_used']),
                'committed_as' => human_bytes($mem['committed_as']), 'commit_limit' => human_bytes($mem['commit_limit']),
                'hugepages_total' => $mem['hugepages_total'], 'anon_hugepages' => human_bytes($mem['anon_hugepages']),
            ], fn($v) => $v !== null && $v !== '—') : null,
            'sysctl_vm' => $p['vm'] ?? null, 'transparent_hugepages' => $p['thp'] ?? null,
            'vmstat_media_amostra' => $p['vmstat'] ?? null,
            'oom' => isset($p['oom_access']) && !$p['oom_access'] ? 'sem permissão para ler o log do kernel' : ($p['oom_events'] ?? []),
            'diretorio_dados' => isset($p['data_dir']['size']) ? [
                'caminho' => $p['data_dir']['path'], 'montagem' => $p['data_dir']['mount'] ?? null, 'fs' => $p['data_dir']['fstype'] ?? null,
                'opcoes' => $p['data_dir']['mount_options'] ?? null, 'tamanho' => human_bytes($p['data_dir']['size']),
                'livre' => human_bytes($p['data_dir']['avail']), 'uso_pct' => $p['data_dir']['used_pct'] ?? null, 'inodes_pct' => $p['data_dir']['inodes_pct'] ?? null,
            ] : null,
            'filesystems' => array_map(fn($fs) => "{$fs['mount']}: {$fs['used_pct']}% de " . human_bytes($fs['size']), $p['filesystems'] ?? []),
            'discos' => $p['disks'] ?? null,
            'processos_top_memoria' => array_map(fn($x) => $x['command'] . ' ' . human_bytes($x['rss']) . " cpu {$x['cpu_pct']}%", array_slice($p['top_processes'] ?? [], 0, 10)),
        ], fn($v) => $v !== null && $v !== []);
    }
}
