<?php
declare(strict_types=1);

namespace App\Analyzer;

use PDO;

/**
 * Contrato de coleta por etapa. Cada etapa devolve:
 *   ['metrics' => [...], 'findings' => [Finding...], 'log' => ['linha', ...], 'counters' => [...]]
 * Para suportar um novo motor, implemente esta classe e registre em Connector::collector().
 */
abstract class Collector
{
    protected array $log = [];
    protected array $findings = [];

    public function __construct(protected PDO $pdo, protected string $database)
    {
    }

    abstract public function connect(): array;
    abstract public function schemas(): array;
    abstract public function indexes(): array;
    abstract public function queries(): array;
    abstract public function sizing(): array;

    protected function q(string $sql, array $params = []): array
    {
        $st = $this->pdo->prepare($sql);
        $st->execute($params);
        return $st->fetchAll();
    }

    /** Executa ignorando falhas (permissão, extensão ausente) e registra no terminal. */
    protected function tryQ(string $label, string $sql, array $params = []): ?array
    {
        try {
            return $this->q($sql, $params);
        } catch (\Throwable $e) {
            $this->log("⚠ $label indisponível: " . mb_substr($e->getMessage(), 0, 160));
            return null;
        }
    }

    protected function log(string $line): void
    {
        $this->log[] = $line;
    }

    protected function finding(string $severity, string $category, string $title, string $detail, ?string $fixSql = null, ?string $object = null): void
    {
        $this->findings[] = compact('severity', 'category', 'title', 'detail', 'object') + ['fix_sql' => $fixSql];
    }

    protected function result(array $metrics, array $counters = []): array
    {
        $out = ['metrics' => $metrics, 'findings' => $this->findings, 'log' => $this->log, 'counters' => $counters];
        $this->findings = [];
        $this->log = [];
        return $out;
    }

    protected static function qi(string $ident, string $quote = '"'): string
    {
        return $quote . str_replace($quote, $quote . $quote, $ident) . $quote;
    }
}
