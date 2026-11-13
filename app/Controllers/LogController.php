<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Core\{Database, View};

final class LogController
{
    public function index(): void
    {
        $f = [
            'from' => (string) ($_GET['from'] ?? date('Y-m-d', strtotime('-7 days'))),
            'to' => (string) ($_GET['to'] ?? date('Y-m-d')),
            'user' => trim((string) ($_GET['user'] ?? '')),
            'severity' => (string) ($_GET['severity'] ?? ''),
            'q' => trim((string) ($_GET['q'] ?? '')),
        ];
        $where = ["date(created_at, 'localtime') BETWEEN :from AND :to"];
        $p = ['from' => $f['from'], 'to' => $f['to']];
        if ($f['user'] !== '') {
            $where[] = 'username LIKE :user';
            $p['user'] = '%' . $f['user'] . '%';
        }
        if (in_array($f['severity'], ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], true)) {
            $where[] = 'severity = :sev';
            $p['sev'] = $f['severity'];
        }
        if ($f['q'] !== '') {
            $where[] = '(event LIKE :q OR message LIKE :q)';
            $p['q'] = '%' . $f['q'] . '%';
        }
        $w = implode(' AND ', $where);
        $page = max(1, (int) ($_GET['page'] ?? 1));
        $per = 50;
        $total = (int) Database::value("SELECT COUNT(*) FROM audit_logs WHERE $w", $p);
        $rows = Database::all("SELECT *, datetime(created_at, 'localtime') AS local_time FROM audit_logs WHERE $w ORDER BY id DESC LIMIT $per OFFSET " . (($page - 1) * $per), $p);
        $usage = Database::all("SELECT provider, model, COUNT(*) AS calls, SUM(tokens_in) AS tin, SUM(tokens_out) AS tout, ROUND(AVG(latency_ms)) AS lat
                                  FROM ai_usage WHERE date(created_at, 'localtime') BETWEEN :from AND :to GROUP BY provider, model ORDER BY tin + tout DESC",
            ['from' => $f['from'], 'to' => $f['to']]);
        View::render('admin/logs', ['title' => 'Logs de Auditoria', 'rows' => $rows, 'f' => $f, 'total' => $total, 'page' => $page, 'pages' => max(1, (int) ceil($total / $per)), 'usage' => $usage]);
    }
}
