<?php
declare(strict_types=1);

namespace App\Analyzer;

use App\Ai\AiClient;
use App\Core\Config;

/**
 * Tradução para português das descrições de CVE.
 *
 * Ordem: (1) tradução por regras que já vem na base (texto padrão de Oracle/Microsoft, campo "pt");
 * (2) cache local DATA_DIR/cve-pt.json; (3) a IA configurada traduz o que faltar e grava no cache;
 * (4) sem IA, fica o texto original em inglês. O cache fica fora do código e sobrevive às atualizações da base.
 */
final class CveTranslator
{
    private const BATCH = 20;          // descrições por chamada (cabe no max_tokens padrão mesmo com raciocínio)
    private const MAX_PER_RUN = 80;    // teto por análise; o restante é traduzido nas próximas
    private static ?array $cache = null;

    public static function path(): string
    {
        return Config::dataDir() . '/cve-pt.json';
    }

    private static function key(string $en): string
    {
        return hash('crc32b', $en);
    }

    private static function load(): array
    {
        if (self::$cache === null) {
            $d = is_file(self::path()) ? json_decode((string) file_get_contents(self::path()), true) : null;
            self::$cache = is_array($d) ? $d : [];
        }
        return self::$cache;
    }

    /** Traduções em cache válidas para o texto atual. @param array<string,string> $map id => inglês */
    public static function cached(array $map): array
    {
        $c = self::load();
        $out = [];
        foreach ($map as $id => $en) {
            if (isset($c[$id]['pt']) && ($c[$id]['h'] ?? '') === self::key($en)) {
                $out[$id] = $c[$id]['pt'];
            }
        }
        return $out;
    }

    private static function save(array $new): void
    {
        if (!$new) {
            return;
        }
        $fp = @fopen(self::path() . '.lock', 'c');
        $fp && flock($fp, LOCK_EX);
        self::$cache = null;
        $c = self::load();
        $c = array_replace($c, $new);
        $tmp = self::path() . '.tmp';
        if (file_put_contents($tmp, json_encode($c, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) !== false) {
            @rename($tmp, self::path());
        }
        self::$cache = $c;
        if ($fp) {
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    /**
     * Traduz com a IA o que não está em cache. Nunca lança exceção: em falha devolve o que conseguiu.
     * @param array<string,string> $map id => inglês, já em ordem de prioridade
     * @return array{0: array<string,string>, 1: array{calls:int, tokens_in:int, tokens_out:int, error:?string}}
     */
    public static function translate(array $map, AiClient $client): array
    {
        $map = array_slice($map, 0, self::MAX_PER_RUN, true);
        $out = [];
        $stats = ['calls' => 0, 'tokens_in' => 0, 'tokens_out' => 0, 'error' => null];
        foreach (array_chunk($map, self::BATCH, true) as $chunk) {
            try {
                $r = $client->chat(self::system(), json_encode($chunk, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
                $stats['calls']++;
                $stats['tokens_in'] += $r['tokens_in'];
                $stats['tokens_out'] += $r['tokens_out'];
                $got = self::parse((string) $r['text'], $chunk);
                $new = [];
                foreach ($got as $id => $pt) {
                    $out[$id] = $pt;
                    $new[$id] = ['h' => self::key($chunk[$id]), 'pt' => $pt];
                }
                self::save($new);
            } catch (\Throwable $e) {
                $stats['error'] = mb_substr($e->getMessage(), 0, 200);
                break; // provedor fora do ar ou cota estourada: não insiste nos outros lotes
            }
        }
        return [$out, $stats];
    }

    public static function system(): string
    {
        return <<<TXT
Você traduz descrições técnicas de vulnerabilidades (CVE) do inglês para o português do Brasil.
Regras:
- Tradução fiel e técnica, sem acrescentar nem omitir informação. Tom de laudo de segurança.
- Mantenha como estão: IDs, versões, nomes de produtos, componentes, funções, parâmetros, comandos SQL e trechos de código.
- Termos consagrados podem ficar em inglês entre parênteses na primeira menção, ex.: "uso após liberação (use after free)".
- Se o texto terminar em "…", a tradução também termina em "…".
- Responda SOMENTE com um objeto JSON no formato {"CVE-AAAA-NNNN": "tradução", ...}, com as mesmas chaves recebidas.
TXT;
    }

    /** Extrai o JSON da resposta e aceita só chaves pedidas com texto plausível. */
    public static function parse(string $text, array $asked): array
    {
        $text = preg_replace('/^```(?:json)?\s*|\s*```$/m', '', trim($text));
        $a = strpos((string) $text, '{');
        $b = strrpos((string) $text, '}');
        if ($a === false || $b === false) {
            return [];
        }
        $j = json_decode(substr((string) $text, $a, $b - $a + 1), true);
        if (!is_array($j)) {
            return [];
        }
        $out = [];
        foreach ($j as $id => $pt) {
            if (!isset($asked[$id]) || !is_string($pt)) {
                continue;
            }
            $pt = trim(preg_replace('/\s+/', ' ', $pt));
            $len = mb_strlen($pt);
            if ($pt !== '' && $len >= mb_strlen($asked[$id]) * 0.4 && $len <= mb_strlen($asked[$id]) * 2.5 + 40) {
                $out[$id] = mb_substr($pt, 0, 600);
            }
        }
        return $out;
    }
}
