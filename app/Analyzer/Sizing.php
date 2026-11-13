<?php
declare(strict_types=1);

namespace App\Analyzer;

/**
 * Motor determinístico de dimensionamento: calcula a configuração de referência para
 * o hardware informado e emite um veredito preliminar (a IA refina e explica).
 */
final class Sizing
{
    /** @param array{vcpu?:int,clock_ghz?:float,ram_gb?:float,disk?:string,dedicated?:bool} $hw */
    public static function evaluate(string $engine, array $settings, array $stats, array $hw, int $dbSize): array
    {
        $ram = (float) ($hw['ram_gb'] ?? 0);
        $cpu = (int) ($hw['vcpu'] ?? 0);
        $disk = $hw['disk'] ?? 'ssd';
        if ($ram <= 0 || $cpu <= 0) {
            return ['verdict' => 'indeterminado', 'reasons' => ['Hardware não informado: informe vCPUs e RAM para o veredito de dimensionamento.'], 'recommended' => [], 'config' => ''];
        }
        $ramB = (int) ($ram * 1024 ** 3);
        $rec = $engine === 'postgresql' ? self::postgres($ramB, $cpu, $disk, $settings) : self::mysql($ramB, $cpu, $disk, $settings, $engine === 'mariadb');

        $reasons = [];
        $mistuned = 0;
        foreach ($rec['compare'] as $name => [$current, $target]) {
            if ($current === null || $target <= 0) {
                continue;
            }
            $ratio = $current / $target;
            if ($ratio < 0.5 || $ratio > 2.0) {
                $mistuned++;
                $reasons[] = sprintf('%s atual %s vs. recomendado %s', $name, human_bytes($current), human_bytes($target));
            }
        }
        $hit = $stats['cache_hit_ratio'] ?? null;
        $verdict = 'adequado';
        if ($mistuned >= 1) {
            $verdict = 'mal tunado';
        }
        // Working set maior que a RAM útil e cache ruim mesmo com buffers corretos → falta hardware
        if ($mistuned === 0 && $hit !== null && $hit < 95 && $dbSize > $ramB * 0.6) {
            $verdict = 'subdimensionado';
            $reasons[] = 'Cache hit ' . $hit . '% com buffers já ajustados e banco (' . human_bytes($dbSize) . ') maior que 60% da RAM.';
        }
        if ($verdict === 'adequado' && $dbSize > 0 && $dbSize < $ramB * 0.05 && $ram >= 16 && ($hit ?? 100) > 99.5) {
            $verdict = 'superdimensionado';
            $reasons[] = 'Banco ocupa ' . human_bytes($dbSize) . ' (< 5% da RAM) com cache praticamente perfeito.';
        }
        $peak = $stats['max_used_connections'] ?? $stats['connections'] ?? 0;
        if ($cpu > 0 && $peak > $cpu * 8) {
            $reasons[] = "Pico de $peak conexões para $cpu vCPUs: use pool de conexões (PgBouncer/ProxySQL).";
        }
        return ['verdict' => $verdict, 'reasons' => $reasons, 'recommended' => $rec['values'], 'config' => $rec['config'], 'hardware' => $hw];
    }

    private static function mb(int $bytes): string
    {
        return $bytes >= 1024 ** 3 && $bytes % (1024 ** 3) === 0 ? ($bytes / 1024 ** 3) . 'GB' : max(1, (int) round($bytes / 1024 ** 2)) . 'MB';
    }

    private static function postgres(int $ram, int $cpu, string $disk, array $s): array
    {
        $maxConn = max(20, (int) ($s['max_connections']['value'] ?? 100));
        $shared = (int) min($ram * 0.25, 64 * 1024 ** 3);
        $cache = (int) ($ram * 0.75);
        $maint = (int) min($ram / 16, 2 * 1024 ** 3);
        $work = (int) max(4 * 1024 ** 2, ($ram - $shared) / ($maxConn * 3));
        $ssd = $disk !== 'hdd';
        $v = [
            'shared_buffers' => self::mb($shared), 'effective_cache_size' => self::mb($cache), 'maintenance_work_mem' => self::mb($maint),
            'work_mem' => self::mb($work), 'wal_buffers' => '16MB', 'min_wal_size' => '1GB', 'max_wal_size' => $ram >= 8 * 1024 ** 3 ? '8GB' : '4GB',
            'checkpoint_completion_target' => '0.9', 'random_page_cost' => $ssd ? '1.1' : '4', 'effective_io_concurrency' => $ssd ? '200' : '2',
            'max_worker_processes' => (string) max(8, $cpu), 'max_parallel_workers' => (string) $cpu,
            'max_parallel_workers_per_gather' => (string) max(1, intdiv($cpu, 2)), 'max_parallel_maintenance_workers' => (string) max(1, intdiv($cpu, 2)),
            'default_statistics_target' => '100', 'huge_pages' => $ram >= 32 * 1024 ** 3 ? 'try' : 'off',
            'idle_in_transaction_session_timeout' => '10min',
        ];
        $config = "# postgresql.conf — gerado pelo DB Oráculo Analyzer\n# Hardware: " . round($ram / 1024 ** 3) . " GB RAM, $cpu vCPU, disco " . strtoupper($disk) . "\n";
        foreach ($v as $k => $val) {
            $config .= str_pad($k, 36) . "= " . (is_numeric($val) ? $val : "'$val'") . "\n";
        }
        return ['values' => $v, 'config' => $config, 'compare' => [
            'shared_buffers' => [$s['shared_buffers']['bytes'] ?? null, $shared],
            'effective_cache_size' => [$s['effective_cache_size']['bytes'] ?? null, $cache],
        ]];
    }

    private static function mysql(int $ram, int $cpu, string $disk, array $s, bool $maria = false): array
    {
        $bp = (int) ($ram * ($ram >= 8 * 1024 ** 3 ? 0.70 : 0.50));
        $bp = (int) (floor($bp / (128 * 1024 ** 2)) * 128 * 1024 ** 2);
        $redo = (int) min(max($bp / 4, 512 * 1024 ** 2), 8 * 1024 ** 3);
        $ssd = $disk !== 'hdd';
        $v = [
            'innodb_buffer_pool_size' => self::mb($bp), 'innodb_buffer_pool_instances' => (string) max(1, min(8, (int) floor($bp / 1024 ** 3))),
            ($maria ? 'innodb_log_file_size' : 'innodb_redo_log_capacity') => self::mb($redo), 'innodb_log_buffer_size' => '64MB', 'innodb_flush_method' => 'O_DIRECT',
            'innodb_flush_log_at_trx_commit' => '1', 'innodb_io_capacity' => $ssd ? '2000' : '200', 'innodb_io_capacity_max' => $ssd ? '4000' : '400',
            'innodb_file_per_table' => 'ON', 'thread_cache_size' => (string) min(100, 8 + $cpu * 4), 'tmp_table_size' => '64MB', 'max_heap_table_size' => '64MB',
            'table_open_cache' => '4000', 'innodb_read_io_threads' => (string) max(4, $cpu), 'innodb_write_io_threads' => (string) max(4, $cpu),
            'performance_schema' => 'ON', 'slow_query_log' => 'ON', 'long_query_time' => '1',
        ];
        $config = '# ' . ($maria ? 'MariaDB' : 'MySQL') . " my.cnf [mysqld] — gerado pelo DB Oráculo Analyzer\n# Hardware: " . round($ram / 1024 ** 3) . " GB RAM, $cpu vCPU, disco " . strtoupper($disk) . "\n[mysqld]\n";
        foreach ($v as $k => $val) {
            $config .= str_pad($k, 32) . "= $val\n";
        }
        return ['values' => $v, 'config' => $config, 'compare' => [
            'innodb_buffer_pool_size' => [$s['innodb_buffer_pool_size']['bytes'] ?? null, $bp],
        ]];
    }
}
