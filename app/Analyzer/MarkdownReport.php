<?php
declare(strict_types=1);

namespace App\Analyzer;

/** Exporta um laudo completo em Markdown. */
final class MarkdownReport
{
    public static function build(array $a): string
    {
        $m = json_decode((string) $a['metrics_json'], true) ?: [];
        $f = json_decode((string) $a['findings_json'], true) ?: [];
        $t = json_decode((string) $a['tuning_json'], true) ?: [];
        $hw = json_decode((string) $a['hardware_json'], true) ?: [];
        $brand = brand('name', 'DB Oráculo Analyzer');

        $md = "# Laudo Técnico — {$a['database_name']}\n\n";
        $md .= "> $brand · análise #{$a['id']} · {$a['started_at']}\n\n";
        $md .= "| Item | Valor |\n|---|---|\n";
        $md .= "| Motor | {$a['engine']} |\n| Servidor | {$a['host']}:{$a['port']} |\n| Versão | " . str_replace('|', '/', (string) $a['server_version']) . " |\n";
        $md .= '| Score | **' . (int) $a['score'] . "/100** |\n| Veredito | " . strtoupper($t['verdict'] ?? 'n/d') . " |\n";
        if ($hw) {
            $md .= '| Hardware | ' . ($hw['vcpu'] ?? '?') . ' vCPU @ ' . ($hw['clock_ghz'] ?? '?') . ' GHz, ' . ($hw['ram_gb'] ?? '?') . ' GB RAM, ' . strtoupper($hw['disk'] ?? '?') . " |\n";
        }
        $md .= "\n";
        if (!empty($a['ai_report_md'])) {
            $md .= "## Análise da IA ({$a['ai_provider']} / {$a['ai_model']})\n\n" . trim($a['ai_report_md']) . "\n\n";
        }
        $md .= "## Achados (" . count($f) . ")\n\n";
        foreach ($f as $x) {
            $md .= '- **[' . strtoupper($x['severity']) . "] {$x['title']}** — {$x['detail']}\n";
        }
        $md .= "\n## Configuração de referência\n\n```ini\n" . ($t['config'] ?? '') . "```\n\n";
        $sql = array_filter(array_column($f, 'fix_sql'));
        if ($sql) {
            $md .= "## Scripts SQL de correção\n\n```sql\n" . implode("\n\n", $sql) . "\n```\n\n";
        }
        $md .= "## Tabelas\n\n| Tabela | Linhas | Dados | Índices | PK |\n|---|---:|---:|---:|:-:|\n";
        foreach (array_slice($m['schemas']['tables'] ?? [], 0, 100) as $tb) {
            $md .= "| {$tb['schema']}.{$tb['name']} | " . number_format($tb['rows'], 0, ',', '.') . ' | ' . human_bytes($tb['data_bytes']) . ' | ' . human_bytes($tb['index_bytes']) . ' | ' . ($tb['has_pk'] ? '✔' : '✘') . " |\n";
        }
        $md .= "\n---\n_" . brand('footer') . "_\n";
        return $md;
    }
}
