<?php
declare(strict_types=1);

namespace App\Analyzer;

final class Scorer
{
    private const WEIGHT = ['critical' => 15, 'high' => 7, 'medium' => 3, 'low' => 1];
    private const CAP = 25; // perda máxima por categoria, evita que uma única categoria zere o score

    public static function score(array $findings, array $tuning): int
    {
        $byCat = [];
        foreach ($findings as $f) {
            $byCat[$f['category']] = ($byCat[$f['category']] ?? 0) + (self::WEIGHT[$f['severity']] ?? 1);
        }
        $loss = array_sum(array_map(fn($v) => min(self::CAP, $v), $byCat));
        $loss += match ($tuning['verdict'] ?? '') {
            'mal tunado' => 10, 'subdimensionado' => 12, 'superdimensionado' => 3, default => 0,
        };
        return max(0, min(100, 100 - $loss));
    }

    public static function sort(array $findings): array
    {
        $order = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
        usort($findings, fn($a, $b) => ($order[$a['severity']] ?? 9) <=> ($order[$b['severity']] ?? 9));
        return $findings;
    }
}
