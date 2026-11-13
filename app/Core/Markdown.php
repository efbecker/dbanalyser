<?php
declare(strict_types=1);

namespace App\Core;

/**
 * Renderizador Markdown mínimo e seguro (escapa todo HTML de entrada).
 * Suporta: títulos, parágrafos, listas, tabelas GFM, blocos de código, citações, hr, negrito, itálico, código inline e links http(s).
 */
final class Markdown
{
    public static function render(string $md): string
    {
        $lines = preg_split('/\R/', str_replace("\t", '    ', $md));
        $out = [];
        $n = count($lines);
        for ($i = 0; $i < $n; $i++) {
            $line = $lines[$i];
            if (preg_match('/^```\s*([\w+-]*)/', $line, $m)) {
                $code = [];
                while (++$i < $n && !preg_match('/^```/', $lines[$i])) {
                    $code[] = $lines[$i];
                }
                $out[] = '<div class="code-block"><button type="button" class="copy-btn" data-copy>Copiar</button><pre class="code lang-' . e($m[1]) . '"><code>' . e(implode("\n", $code)) . '</code></pre></div>';
                continue;
            }
            if (trim($line) === '') {
                continue;
            }
            if (preg_match('/^(#{1,6})\s+(.*)$/', $line, $m)) {
                $lvl = min(6, strlen($m[1]) + 1);
                $out[] = "<h$lvl>" . self::inline($m[2]) . "</h$lvl>";
                continue;
            }
            if (preg_match('/^\s*([-*_])\s*\1\s*\1[\s\1]*$/', $line)) {
                $out[] = '<hr>';
                continue;
            }
            if (str_starts_with(ltrim($line), '|') && isset($lines[$i + 1]) && preg_match('/^\s*\|?\s*:?-{2,}/', $lines[$i + 1])) {
                $head = self::cells($line);
                $i++;
                $rows = [];
                while ($i + 1 < $n && str_starts_with(ltrim($lines[$i + 1]), '|')) {
                    $rows[] = self::cells($lines[++$i]);
                }
                $h = '<div class="table-wrap"><table class="table md-table"><thead><tr>' . implode('', array_map(fn($c) => '<th>' . self::inline($c) . '</th>', $head)) . '</tr></thead><tbody>';
                foreach ($rows as $r) {
                    $h .= '<tr>' . implode('', array_map(fn($c) => '<td>' . self::inline($c) . '</td>', $r)) . '</tr>';
                }
                $out[] = $h . '</tbody></table></div>';
                continue;
            }
            if (preg_match('/^\s*>\s?(.*)$/', $line)) {
                $q = [];
                while ($i < $n && preg_match('/^\s*>\s?(.*)$/', $lines[$i], $m)) {
                    $q[] = self::inline($m[1]);
                    $i++;
                }
                $i--;
                $out[] = '<blockquote>' . implode('<br>', $q) . '</blockquote>';
                continue;
            }
            if (preg_match('/^\s*([-*+]|\d+[.)])\s+/', $line, $m)) {
                $ordered = ctype_digit($m[1][0]);
                $items = [];
                while ($i < $n && preg_match('/^\s*([-*+]|\d+[.)])\s+(.*)$/', $lines[$i], $mm)) {
                    $items[] = '<li>' . self::inline($mm[2]) . '</li>';
                    $i++;
                }
                $i--;
                $tag = $ordered ? 'ol' : 'ul';
                $out[] = "<$tag>" . implode('', $items) . "</$tag>";
                continue;
            }
            $para = [$line];
            while ($i + 1 < $n && trim($lines[$i + 1]) !== '' && !preg_match('/^(#{1,6}\s|```|\s*[-*+]\s|\s*\d+[.)]\s|\s*>|\s*\|)/', $lines[$i + 1])) {
                $para[] = $lines[++$i];
            }
            $out[] = '<p>' . self::inline(implode(' ', $para)) . '</p>';
        }
        return implode("\n", $out);
    }

    private static function cells(string $row): array
    {
        return array_map('trim', explode('|', trim(trim($row), '|')));
    }

    private static function inline(string $s): string
    {
        $s = e($s);
        $codes = [];
        $s = preg_replace_callback('/`([^`]+)`/', function ($m) use (&$codes) {
            $codes[] = '<code>' . $m[1] . '</code>';
            return "\x00" . (count($codes) - 1) . "\x00";
        }, $s);
        $s = preg_replace('/\*\*(.+?)\*\*/', '<strong>$1</strong>', $s);
        $s = preg_replace('/(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])/', '<em>$1</em>', $s);
        $s = preg_replace('/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/', '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>', $s);
        return preg_replace_callback("/\x00(\d+)\x00/", fn($m) => $codes[(int) $m[1]], $s);
    }
}
