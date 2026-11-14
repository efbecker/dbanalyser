<?php
declare(strict_types=1);

namespace App\Analyzer;

use App\Core\Config;

/**
 * Vulnerabilidades conhecidas (CVE) e ciclo de vida (EOL) da versão do SGBD analisado.
 *
 * Funciona 100% offline: lê data/vulndb.json (versionado no repositório) ou, se for mais recente,
 * DATA_DIR/vulndb.json baixado por "php bin/console vulndb:update". Nenhuma consulta externa é feita
 * durante a análise. A base é gerada por tools/build_vulndb.py a partir do NVD + dados do CNA
 * (PostgreSQL, Oracle, Microsoft, MariaDB) e do endoflife.date.
 *
 * Limitação: compara a versão informada pelo servidor. Builds de distribuição com correções
 * retroportadas (ex.: RHEL) podem aparecer como vulneráveis sem estar; o laudo avisa.
 */
final class VulnCheck
{
    public const DEFAULT_URL = 'https://raw.githubusercontent.com/efbecker/dbanalyser/main/data/vulndb.json';
    private const STALE_DAYS = 45;

    private static ?array $db = null;

    public static function bundledPath(): string
    {
        return APP_ROOT . '/data/vulndb.json';
    }

    public static function localPath(): string
    {
        return Config::dataDir() . '/vulndb.json';
    }

    /** Carrega a base mais recente entre a empacotada e a baixada. */
    public static function db(): ?array
    {
        if (self::$db !== null) {
            return self::$db ?: null;
        }
        $best = [];
        foreach ([self::localPath(), self::bundledPath()] as $p) {
            if (!is_file($p)) {
                continue;
            }
            $d = json_decode((string) file_get_contents($p), true);
            if (self::valid($d) && strcmp((string) $d['generated_at'], (string) ($best['generated_at'] ?? '')) > 0) {
                $best = $d + ['_path' => $p];
            }
        }
        self::$db = $best;
        return $best ?: null;
    }

    public static function valid(mixed $d): bool
    {
        return is_array($d) && ($d['format'] ?? null) === 1 && !empty($d['generated_at']) && !empty($d['engines']['postgresql']['cycles']);
    }

    /** Nome do motor na base a partir do motor da análise e da string de versão. */
    public static function engineKey(string $engine, string $version, ?string $flavor = null): ?string
    {
        $e = strtolower($engine);
        return match (true) {
            $e === 'postgresql', $e === 'postgres' => 'postgresql',
            $e === 'mariadb', $flavor === 'mariadb', stripos($version, 'mariadb') !== false && in_array($e, ['mysql', 'mariadb'], true) => 'mariadb',
            $e === 'mysql' => 'mysql',
            in_array($e, ['sqlserver', 'mssql', 'sql_server', 'sqlsrv'], true) => 'sqlserver',
            in_array($e, ['oracle', 'oracledb', 'oci'], true) => 'oracle',
            default => null,
        };
    }

    /** Extrai a versão numérica comparável da string do servidor. */
    public static function parseVersion(string $key, string $version, array $connect = []): ?string
    {
        switch ($key) {
            case 'postgresql':
                $n = (int) ($connect['version_num'] ?? 0);
                if ($n >= 100000) {
                    return intdiv($n, 10000) . '.' . ($n % 10000);
                }
                if ($n > 0) {
                    return intdiv($n, 10000) . '.' . intdiv($n % 10000, 100) . '.' . ($n % 100);
                }
                return preg_match('/(?:PostgreSQL\s+)?\b(\d+\.\d+(?:\.\d+)?)\b/i', $version, $m) ? $m[1] : null;
            case 'mysql':
            case 'mariadb':
                $v = preg_replace('/^5\.5\.5-/', '', trim($version)); // prefixo de compatibilidade do MariaDB
                return preg_match('/(\d+\.\d+\.\d+)/', (string) $v, $m) ? $m[1] : null;
            case 'sqlserver':
                $src = (string) ($connect['product_version'] ?? '') . ' ' . $version;
                return preg_match('/\b(\d{1,2}\.\d+\.\d+\.\d+)\b/', $src, $m) ? $m[1] : null;
            case 'oracle':
                // "Release 19.0.0.0.0 ... Version 19.21.0.0.0": a maior é o RU aplicado (v$instance.version_full, quando houver)
                $src = (string) ($connect['version_full'] ?? '') . ' ' . $version;
                if (!preg_match_all('/\b(\d+\.\d+\.\d+\.\d+(?:\.\d+)?)\b/', $src, $all)) {
                    return preg_match('/\b(\d+\.\d+(?:\.\d+)*)\b/', $src, $m) ? $m[1] : null;
                }
                usort($all[1], fn($a, $b) => self::cmp($b, $a));
                return $all[1][0];
        }
        return null;
    }

    public static function cmp(string $a, string $b): int
    {
        $x = array_map('intval', explode('.', $a));
        $y = array_map('intval', explode('.', $b));
        $n = max(count($x), count($y));
        for ($i = 0; $i < $n; $i++) {
            $c = ($x[$i] ?? 0) <=> ($y[$i] ?? 0);
            if ($c !== 0) {
                return $c;
            }
        }
        return 0;
    }

    private static function inRange(string $v, array $r): bool
    {
        [$lo, $loIncl, $hi, $hiIncl] = $r;
        if ($lo !== null) {
            $c = self::cmp($v, $lo);
            if ($c < 0 || ($c === 0 && !$loIncl)) {
                return false;
            }
        }
        if ($hi !== null) {
            $c = self::cmp($v, $hi);
            if ($c > 0 || ($c === 0 && !$hiIncl)) {
                return false;
            }
        }
        return true;
    }

    private static function bump(string $v): string
    {
        $p = explode('.', $v);
        $p[count($p) - 1] = (string) ((int) end($p) + 1);
        return implode('.', $p);
    }

    /** CVEs que afetam a versão, com a versão que corrige (quando conhecida). */
    public static function match(array $cves, string $v): array
    {
        $out = [];
        foreach ($cves as $c) {
            $fixed = null;
            $hit = false;
            foreach ($c['r'] as $r) {
                if (self::inRange($v, $r)) {
                    $hit = true;
                    $f = $r[2] === null ? null : ($r[3] ? self::bump($r[2]) : $r[2]);
                    if ($f !== null && ($fixed === null || self::cmp($f, $fixed) < 0)) {
                        $fixed = $f;
                    }
                }
            }
            if ($hit) {
                $out[] = ['id' => $c['id'], 'cvss' => $c['cvss'], 'sev' => $c['sev'] ?: self::sevFromScore($c['cvss']),
                    'pub' => $c['pub'], 'summary' => $c['pt'] ?? $c['sum'], 'summary_en' => $c['sum'], 'lang' => isset($c['pt']) ? 'pt' : 'en', 'fixed_in' => $fixed, 'kev' => $c['kev'] ?? null];
            }
        }
        usort($out, fn($a, $b) => [(int) !empty($b['kev']), $b['cvss'] ?? 0, $b['pub']] <=> [(int) !empty($a['kev']), $a['cvss'] ?? 0, $a['pub']]);
        return $out;
    }

    private static function sevFromScore(?float $s): string
    {
        return $s === null ? 'unknown' : ($s >= 9 ? 'critical' : ($s >= 7 ? 'high' : ($s >= 4 ? 'medium' : 'low')));
    }

    /** Ciclo de suporte (major) ao qual a versão pertence. */
    public static function cycle(array $cycles, string $key, string $v): ?array
    {
        $cands = array_values(array_filter($cycles, function ($c) use ($v) {
            $base = preg_replace('/[^\d.].*$/', '', $c['cycle']);
            return $base !== '' && ($v === $base || str_starts_with($v, $base . '.'));
        }));
        if (!$cands) {
            return null;
        }
        if ($key === 'sqlserver' && count($cands) > 1) {
            // SQL Server 2016 tem sub-ciclos (SP2, SP3, SP3 Azure Connect Pack): fica com o de menor build >= atual
            usort($cands, fn($a, $b) => self::cmp(self::latestOf($a, $key, $v) ?? '0', self::latestOf($b, $key, $v) ?? '0'));
            foreach ($cands as $c) {
                if (self::cmp(self::latestOf($c, $key, $v) ?? '0', $v) >= 0) {
                    return $c;
                }
            }
            return end($cands);
        }
        usort($cands, fn($a, $b) => strlen($b['cycle']) <=> strlen($a['cycle']));
        return $cands[0];
    }

    /** Última versão do ciclo. SQL Server: build GDR (x.0.1xxx) segue a linha GDR; CU segue a linha CU. */
    private static function latestOf(array $c, string $key, string $v): ?string
    {
        $norm = fn($s) => preg_match('/^(\d+(?:\.\d+)*)/', (string) $s, $m) ? $m[1] : null;
        if ($key === 'sqlserver') {
            // Linha GDR (só segurança) e linha CU usam faixas de build distintas: 2019 GDR 15.0.2xxx, CU 15.0.4xxx
            $build = (int) (explode('.', $v)[2] ?? 0);
            $gdr = $norm($c['latestGdr'] ?? null);
            if ($gdr && intdiv($build, 1000) === intdiv((int) (explode('.', $gdr)[2] ?? 0), 1000)) {
                return $gdr;
            }
        }
        return $norm($c['latest'] ?? null);
    }

    private static function lifecycle(?array $c): array
    {
        if (!$c) {
            return ['status' => 'unknown'];
        }
        $today = gmdate('Y-m-d');
        $date = fn($k) => isset($c[$k]) && is_string($c[$k]) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $c[$k]) ? $c[$k] : null;
        $eol = $date('eol');
        $eoas = $date('eoas');
        $eoes = $date('eoes');
        $status = 'supported';
        if (($c['eol'] ?? null) === true || ($eol && $eol <= $today)) {
            $status = $eoes && $eoes > $today ? 'extended' : 'eol';
        } elseif ($eoas && $eoas <= $today) {
            $status = 'security';
        }
        return ['status' => $status, 'eol' => $eol, 'eoas' => $eoas, 'eoes' => $eoes, 'lts' => !empty($c['lts']),
            'label' => $c['releaseLabel'] ?? null, 'released' => $date('releaseDate')];
    }

    /** Ciclos suportados mais novos, para sugerir upgrade de major. */
    private static function supportedCycles(array $cycles): array
    {
        $out = [];
        foreach ($cycles as $c) {
            $l = self::lifecycle($c);
            if (in_array($l['status'], ['supported', 'security'], true) && !str_contains($c['cycle'], '-')) {
                $name = trim(str_replace(["'__CODENAME__'", '__CODENAME__'], '', (string) ($c['releaseLabel'] ?? $c['cycle'])));
                $out[] = $name . (!empty($c['latest']) ? ' (' . preg_replace('/\s.*/', '', (string) $c['latest']) . ')' : '') . ($l['lts'] ? ' LTS' : '');
            }
        }
        return array_slice($out, 0, 4);
    }

    /**
     * Avalia a versão. Nunca lança exceção: sem base ou sem versão, devolve status explicando o motivo.
     * @return array{metrics: array, findings: array, log: array}
     */
    public static function evaluate(string $engine, array $connect, ?callable $ai = null): array
    {
        $log = [];
        $findings = [];
        $versionStr = (string) ($connect['version'] ?? '');
        $db = self::db();
        $key = self::engineKey($engine, $versionStr, $connect['flavor'] ?? null);
        $m = ['engine_key' => $key, 'version_string' => $versionStr];

        if (!$db) {
            $log[] = '⚠ Base de vulnerabilidades ausente (data/vulndb.json). Rode: php bin/console vulndb:update';
            return ['metrics' => $m + ['status' => 'no_db'], 'findings' => [], 'log' => $log];
        }
        $m['db'] = ['generated_at' => $db['generated_at'], 'nvd_feed_at' => $db['nvd_feed_at'] ?? null, 'sources' => $db['sources'] ?? []];
        $age = (int) floor((time() - strtotime((string) ($db['nvd_feed_at'] ?: $db['generated_at']))) / 86400);
        $m['db']['age_days'] = $age;
        $log[] = '• Base de CVEs offline de ' . substr((string) ($db['nvd_feed_at'] ?: $db['generated_at']), 0, 10) . " ($age dias)";
        if ($age > self::STALE_DAYS) {
            $log[] = "⚠ Base com mais de " . self::STALE_DAYS . ' dias — CVEs recentes podem faltar. Atualize com: php bin/console vulndb:update';
        }
        $edb = $key ? ($db['engines'][$key] ?? null) : null;
        if (!$edb) {
            $log[] = "⚠ Motor '$engine' sem dados de vulnerabilidade na base";
            return ['metrics' => $m + ['status' => 'unsupported_engine'], 'findings' => [], 'log' => $log];
        }
        $v = self::parseVersion($key, $versionStr, $connect);
        if (!$v) {
            $log[] = '⚠ Não foi possível extrair a versão de: ' . mb_substr($versionStr, 0, 120);
            return ['metrics' => $m + ['status' => 'unknown_version'], 'findings' => [], 'log' => $log];
        }
        $label = ['postgresql' => 'PostgreSQL', 'mysql' => 'MySQL', 'mariadb' => 'MariaDB', 'sqlserver' => 'SQL Server', 'oracle' => 'Oracle Database'][$key];
        $m['version'] = $v;
        $m['product'] = $label;
        $log[] = "• Versão identificada: $label $v";

        // Oracle sem RU (19.0.0.0.0): só a release base é conhecida
        $oracleNoRu = $key === 'oracle' && preg_match('/^\d+\.0\.0\.0/', $v) && (int) $v >= 18;
        if ($oracleNoRu) {
            $log[] = '⚠ Oracle reportou apenas a release base; o Release Update (RU) aplicado é desconhecido. Conceda SELECT em v$instance (version_full) para checar CVEs.';
        }

        $cycle = self::cycle($edb['cycles'], $key, $v);
        $life = self::lifecycle($cycle);
        $latest = $cycle ? self::latestOf($cycle, $key, $v) : null;
        $behind = null;
        if ($latest && self::cmp($latest, $v) > 0 && !empty($edb['versions']) && $cycle) {
            $prefix = preg_replace('/[^\d.].*$/', '', $cycle['cycle']) . '.';
            $behind = count(array_filter($edb['versions'], fn($x) => str_starts_with($x, $prefix) && self::cmp($x, $v) > 0 && self::cmp($x, $latest) <= 0));
        }
        $all = $oracleNoRu ? [] : self::match($edb['cves'], $v);
        $cves = self::localize(array_slice($all, 0, 200), $ai, $log) + $all; // traduz só os que aparecem no laudo

        // Versão-alvo: a última do ciclo; sem ela (Oracle), a maior correção conhecida dentro do mesmo major
        $target = $latest && self::cmp($latest, $v) > 0 ? $latest : null;
        if (!$target && $cves) {
            $major = explode('.', $v)[0] . '.';
            foreach ($cves as $c) {
                if ($c['fixed_in'] && str_starts_with($c['fixed_in'], $major) && self::cmp($c['fixed_in'], $v) > 0 && (!$target || self::cmp($c['fixed_in'], $target) > 0)) {
                    $target = $c['fixed_in'];
                }
            }
        }
        $sevCount = array_count_values(array_column($cves, 'sev'));
        $kev = array_values(array_filter($cves, fn($c) => !empty($c['kev'])));
        $unfixedInCycle = $target ? count(array_filter($cves, fn($c) => !$c['fixed_in'] || self::cmp($c['fixed_in'], $target) > 0)) : count($cves);

        $cycleName = trim(str_replace(["'__CODENAME__'", '__CODENAME__'], '', (string) ($life['label'] ?? $cycle['cycle'] ?? '')));
        $m += [
            'status' => 'ok',
            'cycle' => $cycle['cycle'] ?? null,
            'cycle_name' => $cycleName,
            'lifecycle' => $life,
            'latest' => $latest,
            'target' => $target,
            'behind' => $behind,
            'supported_cycles' => self::supportedCycles($edb['cycles']),
            'cves' => array_slice($cves, 0, 200),
            'cve_total' => count($cves),
            'cve_by_sev' => $sevCount,
            'kev' => array_column($kev, 'id'),
            'not_fixed_by_target' => $unfixedInCycle,
            'oracle_ru_unknown' => $oracleNoRu,
        ];

        $log[] = '• Ciclo ' . ($cycleName ?: '?') . ': ' . match ($life['status']) {
            'supported' => 'com suporte' . ($life['eol'] ? ' até ' . $life['eol'] : ''),
            'security' => 'só correções de segurança até ' . ($life['eol'] ?? '?'),
            'extended' => 'FORA do suporte padrão desde ' . $life['eol'] . ' (suporte estendido pago até ' . $life['eoes'] . ')',
            'eol' => 'SEM SUPORTE desde ' . ($life['eol'] ?? '?'),
            default => 'ciclo de vida desconhecido',
        };
        if ($latest) {
            $log[] = $target ? "• Última versão do ciclo: $latest" . ($behind ? ' (' . self::behindTxt($behind) . ')' : '') : "✔ Versão mais recente do ciclo ($latest)";
        }
        $log[] = $oracleNoRu ? '⚠ CVEs não verificados: RU desconhecido' : (count($cves) ? sprintf('✘ %d CVEs conhecidos afetam %s (%d críticos, %d altos, %d médios)%s', count($cves), $v,
            $sevCount['critical'] ?? 0, $sevCount['high'] ?? 0, $sevCount['medium'] ?? 0, $kev ? ' — ' . count($kev) . ' com exploração ativa (CISA KEV)' : '')
            : '✔ Nenhum CVE conhecido para ' . $v);

        // ---- Achados ----
        $upgradeHint = $life['status'] === 'eol' || $life['status'] === 'extended'
            ? 'Planeje o upgrade para um ciclo suportado: ' . implode(', ', $m['supported_cycles']) . '.'
            : ($target ? "Atualize para $label $target (atualização de correção, mesmo major: sem migração de dados)." : '');

        if (in_array($life['status'], ['eol', 'extended'], true)) {
            $days = $life['eol'] ? (int) floor((time() - strtotime($life['eol'])) / 86400) : 0;
            $sev = $life['status'] === 'extended' ? 'medium' : ($days > 365 ? 'critical' : 'high');
            $findings[] = self::f($sev, "$label $cycleName sem suporte do fabricante" . ($life['eol'] ? " desde {$life['eol']}" : ''),
                ($life['status'] === 'extended'
                    ? "O suporte padrão terminou em {$life['eol']}; correções só com contrato de suporte estendido até {$life['eoes']}. "
                    : 'Versões sem suporte não recebem correções de segurança: novas vulnerabilidades ficarão abertas para sempre. ')
                . $upgradeHint, $label . ' ' . $v);
        }

        if ($cves) {
            $top = array_slice($cves, 0, 8);
            $lines = array_map(fn($c) => "• {$c['id']}" . ($c['cvss'] !== null ? " (CVSS {$c['cvss']})" : '') . (!empty($c['kev']) ? ' [EXPLORADO ATIVAMENTE]' : '')
                . ($c['fixed_in'] ? " — corrigido em {$c['fixed_in']}" : '') . ": {$c['summary']}", $top);
            $worst = $kev ? 'critical' : (isset($sevCount['critical']) ? 'critical' : (isset($sevCount['high']) ? 'high' : (isset($sevCount['medium']) ? 'medium' : 'low')));
            $findings[] = self::f($worst,
                sprintf('%d vulnerabilidades conhecidas (CVE) em %s %s', count($cves), $label, $v),
                implode("\n", $lines) . (count($cves) > 8 ? "\n… e mais " . (count($cves) - 8) . ' (lista completa na aba Segurança).' : '')
                . ($upgradeHint ? "\n\n$upgradeHint" : '')
                . ($target && $unfixedInCycle ? "\n$unfixedInCycle CVE(s) não têm correção dentro deste ciclo: exigem upgrade de major." : ''),
                $label . ' ' . $v);
        } elseif ($target && $behind !== 0 && $life['status'] !== 'eol') {
            $n = $behind ?? 0;
            $findings[] = self::f($n >= 4 ? 'medium' : 'low', "$label $v desatualizado" . ($n ? ' (' . self::behindTxt($n) . ')' : ''),
                "A última versão do ciclo $cycleName é $target. Versões de correção trazem apenas bugfixes e segurança. $upgradeHint", $label . ' ' . $v);
        }

        // ---- Extensões (PostgreSQL) ----
        $extOut = [];
        if ($key === 'postgresql') {
            foreach (($connect['extensions'] ?? []) as $name => $ver) {
                $x = $db['pg_extensions'][$name] ?? null;
                $ev = preg_match('/^(\d+(?:\.\d+)*)/', (string) $ver, $mm) ? $mm[1] : null;
                if (!$x || !$ev) {
                    continue;
                }
                $hits = self::localize(self::match($x['cves'], $ev), $ai, $log);
                $extOut[$name] = ['version' => $ev, 'cves' => $hits];
                if ($hits) {
                    $fix = array_filter(array_column($hits, 'fixed_in'));
                    usort($fix, [self::class, 'cmp']);
                    $log[] = "✘ Extensão $name $ev: " . count($hits) . ' CVE(s)';
                    $es = array_count_values(array_column($hits, 'sev'));
                    $findings[] = self::f(isset($es['critical']) ? 'high' : (isset($es['high']) ? 'medium' : 'low'),
                        "Extensão $name $ev com " . count($hits) . ' CVE(s) conhecido(s)',
                        implode("\n", array_map(fn($c) => "• {$c['id']}" . ($c['cvss'] !== null ? " (CVSS {$c['cvss']})" : '') . ($c['fixed_in'] ? " — corrigido em {$c['fixed_in']}" : '') . ": {$c['summary']}", array_slice($hits, 0, 6)))
                        . ($fix ? "\n\nAtualize o pacote da extensão para " . end($fix) . "+ e rode ALTER EXTENSION $name UPDATE;" : ''),
                        "extension $name");
                }
            }
        }
        $m['extensions'] = $extOut;

        return ['metrics' => $m, 'findings' => $findings, 'log' => $log];
    }

    /**
     * Descrições em português: regras da base > cache local > IA (se $ai for passado) > inglês.
     * @param callable|null $ai fn(array<string,string> $idToEnglish): array<string,string> $idToPortuguese
     */
    public static function localize(array $list, ?callable $ai = null, ?array &$log = null): array
    {
        $missing = [];
        foreach ($list as $c) {
            if (($c['lang'] ?? 'en') !== 'pt') {
                $missing[$c['id']] = $c['summary_en'] ?? $c['summary'];
            }
        }
        if (!$missing) {
            return $list;
        }
        $pt = CveTranslator::cached($missing);
        $rest = array_diff_key($missing, $pt);
        if ($rest && $ai) {
            try {
                $pt += $ai($rest);
            } catch (\Throwable $e) {
                $log[] = '⚠ Tradução dos CVEs pela IA indisponível: ' . mb_substr($e->getMessage(), 0, 120);
            }
        }
        foreach ($list as &$c) {
            if (isset($pt[$c['id']])) {
                $c['summary_en'] ??= $c['summary'];
                $c['summary'] = $pt[$c['id']];
                $c['lang'] = 'pt';
            }
        }
        unset($c);
        return $list;
    }

    /** Para laudos já gravados: aplica traduções disponíveis offline (base + cache), sem chamar a IA. */
    public static function localizeStored(array $v): array
    {
        if (empty($v['cves']) && empty($v['extensions'])) {
            return $v;
        }
        $db = self::db();
        $idx = [];
        foreach ([$db['engines'][$v['engine_key'] ?? ''] ?? [], ...array_values($db['pg_extensions'] ?? [])] as $e) {
            foreach ($e['cves'] ?? [] as $c) {
                if (isset($c['pt'])) {
                    $idx[$c['id']] = $c['pt'];
                }
            }
        }
        $fix = function (array $list) use ($idx): array {
            foreach ($list as &$c) {
                if (($c['lang'] ?? 'en') !== 'pt' && isset($idx[$c['id']])) {
                    $c['summary_en'] ??= $c['summary'];
                    $c['summary'] = $idx[$c['id']];
                    $c['lang'] = 'pt';
                }
            }
            unset($c);
            return self::localize($list);
        };
        $v['cves'] = $fix($v['cves'] ?? []);
        foreach ($v['extensions'] ?? [] as $k => $x) {
            $v['extensions'][$k]['cves'] = $fix($x['cves'] ?? []);
        }
        return $v;
    }

    /** Resumo compacto para o prompt da IA e para exportações. */
    public static function summary(array $v): ?array
    {
        if (($v['status'] ?? '') !== 'ok') {
            return null;
        }
        return [
            'versao' => ($v['product'] ?? '') . ' ' . $v['version'],
            'ciclo' => $v['cycle_name'] ?: $v['cycle'],
            'suporte' => ($v['lifecycle']['status'] ?? 'unknown') . (!empty($v['lifecycle']['eol']) ? ' (fim do suporte ' . $v['lifecycle']['eol'] . ')' : ''),
            'ultima_versao_do_ciclo' => $v['latest'],
            'versoes_de_correcao_atras' => $v['behind'],
            'atualizar_para' => $v['target'],
            'ciclos_suportados' => $v['supported_cycles'],
            'cves_total' => $v['oracle_ru_unknown'] ? 'não verificado (RU desconhecido)' : $v['cve_total'],
            'cves_por_severidade' => $v['cve_by_sev'],
            'exploracao_ativa_kev' => $v['kev'],
            'cves_principais' => array_map(fn($c) => "{$c['id']} CVSS " . ($c['cvss'] ?? '?') . ($c['fixed_in'] ? " corrigido em {$c['fixed_in']}" : '') . ': ' . mb_substr($c['summary'], 0, 140), array_slice($v['cves'], 0, 10)),
            'extensoes_com_cve' => array_map(fn($x) => $x['version'] . ': ' . implode(', ', array_column($x['cves'], 'id')), array_filter($v['extensions'] ?? [], fn($x) => $x['cves'])),
            'base_de_dados_cve' => substr((string) ($v['db']['nvd_feed_at'] ?? $v['db']['generated_at'] ?? ''), 0, 10),
        ];
    }

    /** Seção Markdown do laudo exportado. */
    public static function markdown(array $v): string
    {
        $v = self::localizeStored($v);
        $s = self::summary($v);
        if (!$s) {
            return '';
        }
        $life = $v['lifecycle'] ?? [];
        $st = ['supported' => 'com suporte', 'security' => 'só correções de segurança', 'extended' => 'suporte estendido (pago)', 'eol' => '**SEM SUPORTE (EOL)**'][$life['status'] ?? ''] ?? 'desconhecido';
        $md = "## Segurança e versão\n\n| Item | Valor |\n|---|---|\n";
        $md .= "| Versão em uso | {$s['versao']} |\n| Ciclo | {$s['ciclo']} — $st" . (!empty($life['eol']) ? " (fim do suporte {$life['eol']})" : '') . " |\n";
        $md .= '| Última versão do ciclo | ' . ($v['latest'] ?? 'n/d') . ($v['behind'] ? ' (' . self::behindTxt((int) $v['behind']) . ')' : '') . " |\n";
        $md .= '| Atualizar para | ' . ($v['target'] ?: 'já está na última versão conhecida') . " |\n";
        $sevPt = ['critical' => 'críticos', 'high' => 'altos', 'medium' => 'médios', 'low' => 'baixos', 'unknown' => 'sem nota'];
        $md .= '| CVEs conhecidos | ' . (is_int($s['cves_total']) ? $s['cves_total'] . ($v['cve_by_sev'] ? ' (' . implode(', ', array_map(fn($k, $n) => "$n " . ($sevPt[$k] ?? $k), array_keys($v['cve_by_sev']), $v['cve_by_sev'])) . ')' : '') : $s['cves_total'])
            . ($v['kev'] ? ' · exploração ativa: ' . implode(', ', $v['kev']) : '') . " |\n\n";
        if ($v['cves']) {
            $md .= "| CVE | CVSS | Corrigido em | Descrição |\n|---|---:|---|---|\n";
            foreach (array_slice($v['cves'], 0, 40) as $c) {
                $md .= "| [{$c['id']}](https://nvd.nist.gov/vuln/detail/{$c['id']}) | " . ($c['cvss'] ?? '—') . ' | ' . ($c['fixed_in'] ?? '—') . ' | ' . str_replace(['|', "\n"], ['/', ' '], mb_substr($c['summary'], 0, 180)) . " |\n";
            }
            if ($v['cve_total'] > 40) {
                $md .= "\n_… e mais " . ($v['cve_total'] - 40) . " CVEs (lista completa no laudo online)._\n";
            }
            $md .= "\n";
        }
        $md .= "_Base offline de {$s['base_de_dados_cve']} (NVD + avisos dos fabricantes; ciclo de vida: endoflife.date). Compara a versão informada pelo servidor; pacotes com correções retroportadas podem aparecer como vulneráveis._\n\n";
        return $md;
    }

    public static function behindTxt(int $n): string
    {
        return $n === 1 ? '1 versão de correção atrás' : "$n versões de correção atrás";
    }

    private static function f(string $sev, string $title, string $detail, string $object): array
    {
        return ['severity' => $sev, 'category' => 'security', 'title' => $title, 'detail' => $detail, 'object' => $object, 'fix_sql' => null];
    }

    /** Baixa a base publicada no repositório. Devolve [ok, mensagem]. */
    public static function update(?string $url = null): array
    {
        $url = $url ?: (string) Config::get('vulndb_url', self::DEFAULT_URL);
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT => 120,
            CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_USERAGENT => 'db-oraculo-analyzer']);
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($body === false || $code !== 200) {
            return [false, "Falha ao baixar $url: " . ($err ?: "HTTP $code") . ' — o laudo segue usando a base local.'];
        }
        $d = json_decode((string) $body, true);
        if (!self::valid($d)) {
            return [false, 'Conteúdo baixado não é uma base válida; nada foi alterado.'];
        }
        $cur = self::db();
        if ($cur && strcmp((string) $d['generated_at'], (string) $cur['generated_at']) <= 0) {
            return [true, 'Base já está atualizada (' . $cur['generated_at'] . ').'];
        }
        $dest = self::localPath();
        $tmp = $dest . '.tmp';
        if (file_put_contents($tmp, $body) === false || !rename($tmp, $dest)) {
            return [false, "Não foi possível gravar $dest"];
        }
        self::$db = null;
        $n = array_sum(array_map(fn($e) => count($e['cves'] ?? []), $d['engines']));
        return [true, "Base atualizada: {$d['generated_at']} ($n CVEs)."];
    }
}
