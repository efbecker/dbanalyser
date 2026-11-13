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

    /** Aplicações de terceiros reconhecidas pelas tabelas que criam (schema mantido pelo fornecedor). */
    public const KNOWN_APPS = [
        'Zabbix'    => ['dbversion', 'hosts', 'items', 'triggers'],
        'GLPI'      => ['glpi_configs'],
        'Moodle'    => ['mdl_config'],
        'WordPress' => ['wp_options', 'wp_posts'],
        'Nextcloud' => ['oc_appconfig'],
        'Odoo'      => ['ir_module_module', 'res_users'],
        'Keycloak'  => ['realm', 'client', 'user_entity'],
        'Grafana'   => ['dashboard', 'data_source', 'alert_rule'],
    ];

    /** @var array{app:?string, schemas:string[], extensions:array<string,string>}|null */
    private ?array $ctx = null;

    /** Lista [schema, tabela] das tabelas do banco (sem catálogos) para detectar aplicações. */
    abstract protected function tableNames(): array;

    /** Extensões instaladas (nome => versão). */
    protected function extensions(): array
    {
        return [];
    }

    /** Contexto detectado: aplicação conhecida, schemas que ela gerencia e extensões. */
    public function context(): array
    {
        if ($this->ctx === null) {
            $bySchema = [];
            foreach ($this->tableNames() as [$schema, $table]) {
                $bySchema[$schema][strtolower($table)] = true;
            }
            $app = null;
            $schemas = [];
            foreach (self::KNOWN_APPS as $name => $markers) {
                foreach ($bySchema as $schema => $tables) {
                    if (count(array_filter($markers, fn($m) => isset($tables[$m]))) === count($markers)) {
                        $app ??= $name;
                        $schemas[] = $schema;
                    }
                }
                if ($app) {
                    break;
                }
            }
            $this->ctx = ['app' => $app, 'schemas' => $schemas, 'extensions' => $this->extensions()];
        }
        return $this->ctx;
    }

    private function isManaged(?string $object): bool
    {
        $ctx = $this->context();
        if (!$ctx['app'] || $object === null) {
            return false;
        }
        $schema = str_contains($object, '.') ? explode('.', $object, 2)[0] : $this->database;
        return in_array($schema, $ctx['schemas'], true) || (!str_contains($object, '.') && in_array($this->database, $ctx['schemas'], true));
    }

    public function __construct(protected PDO|OracleConnection $pdo, protected string $database)
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

    /** Categorias que mexem na estrutura (DDL). Em schema de aplicação de terceiros viram informativas e sem script. */
    private const STRUCTURAL = ['schema', 'types', 'indexes', 'relationships'];

    protected function finding(string $severity, string $category, string $title, string $detail, ?string $fixSql = null, ?string $object = null): void
    {
        $managed = in_array($category, self::STRUCTURAL, true) && $this->isManaged($object);
        if ($managed) {
            $app = $this->context()['app'];
            $severity = 'info';
            $fixSql = null;
            $detail .= " Objeto do schema oficial do $app: não altere a estrutura por conta própria (quebra upgrades da aplicação); trate com o fornecedor.";
        }
        $this->findings[] = compact('severity', 'category', 'title', 'detail', 'object', 'managed') + ['fix_sql' => $fixSql];
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
