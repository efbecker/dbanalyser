<?php
declare(strict_types=1);

namespace App\Analyzer;

/** Monta o prompt enviado à IA com a coleta técnica compactada. */
final class Prompt
{
    public static function system(): string
    {
        return <<<TXT
Você é um DBA sênior (PostgreSQL, MySQL e MariaDB) e engenheiro de performance Linux.
Recebe uma coleta técnica feita em modo somente leitura e escreve um LAUDO TÉCNICO em português do Brasil, em Markdown.
Regras:
- Seja objetivo, priorize por impacto e risco. Não invente dados que não estão na coleta; quando faltar dado, diga o que coletar.
- Toda alteração deve vir com o SQL/config exato e um alerta de risco (lock, rebuild, restart).
- Objetos de extensões (TimescaleDB, PostGIS, pg_cron...) já foram excluídos da coleta. Se uma aplicação conhecida
  for informada (ex.: Zabbix), a estrutura dela é do fornecedor: nunca recomende DROP/ALTER/CREATE em tabelas,
  colunas ou índices dela; foque em configuração, manutenção (VACUUM/ANALYZE), observabilidade e hardware.
- Ao recomendar shared_preload_libraries, preserve todas as bibliotecas já carregadas.
- Não use links internos em Markdown nem título de nível 1 (#); comece direto em ## Resumo Executivo.
- Seções obrigatórias, nesta ordem:
  ## Resumo Executivo
  ## Veredito de Dimensionamento  (comece com uma linha: **Veredito: SUBDIMENSIONADO | SUPERDIMENSIONADO | MAL TUNADO | ADEQUADO**)
  ## Principais Riscos
  ## Plano de Ação Priorizado  (tabela: prioridade, ação, impacto, risco, esforço)
  ## Queries e Índices
  ## Configuração Recomendada  (bloco ```ini completo para postgresql.conf ou my.cnf)
  ## Próximos Passos de Monitoramento
TXT;
    }

    public static function user(array $a, array $metrics, array $findings, array $tuning): string
    {
        $tables = array_slice($metrics['schemas']['tables'] ?? [], 0, 40);
        $payload = [
            'motor' => $a['engine'], 'versao' => $metrics['connect']['version'] ?? null, 'banco' => $a['database_name'],
            'tamanho_banco' => human_bytes($metrics['connect']['db_size'] ?? 0),
            'hardware' => json_decode((string) $a['hardware_json'], true),
            'aplicacao_reconhecida' => $metrics['connect']['app'] ?? null,
            'extensoes' => $metrics['connect']['extensions'] ?? [],
            'tabelas_top40' => array_map(fn($t) => array_intersect_key($t, array_flip(['schema', 'name', 'rows', 'dead_pct', 'data_bytes', 'index_bytes', 'has_pk', 'engine', 'data_free', 'seq_scan', 'idx_scan'])), $tables),
            'total_tabelas' => count($metrics['schemas']['tables'] ?? []),
            'fks_sem_indice' => $metrics['indexes']['fk_without_index'] ?? [],
            'indices_nao_usados' => $metrics['indexes']['unused'] ?? 0,
            'top_queries' => array_map(fn($q) => ['query' => mb_substr((string) $q['query'], 0, 600)] + array_diff_key($q, ['query' => 1]), array_slice($metrics['queries']['top_queries'] ?? [], 0, 10)),
            'sessoes_longas' => array_slice($metrics['queries']['activity'] ?? [], 0, 10),
            'configuracao_atual' => array_map(fn($s) => $s['value'] . (isset($s['unit']) && $s['unit'] ? ' ' . $s['unit'] : ''), $metrics['sizing']['settings'] ?? []),
            'estatisticas' => $metrics['sizing']['stats'] ?? [],
            'veredito_heuristico' => ['veredito' => $tuning['verdict'] ?? null, 'motivos' => $tuning['reasons'] ?? [], 'config_referencia' => $tuning['recommended'] ?? []],
            'achados' => array_map(fn($f) => "[{$f['severity']}/{$f['category']}] {$f['title']}" . (!empty($f['managed']) ? ' (objeto da aplicação)' : ''), array_slice($findings, 0, 80)),
        ];
        return "Coleta técnica (JSON):\n```json\n" . json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_PARTIAL_OUTPUT_ON_ERROR) . "\n```\nGere o laudo.";
    }
}
