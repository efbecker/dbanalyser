<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Analyzer\MarkdownReport;
use App\Core\{Audit, Auth, Database, Http, Session, View};

final class ReportController
{
    private function find(int $id): array
    {
        $a = Database::one('SELECT a.*, u.username FROM analyses a JOIN users u ON u.id = a.user_id WHERE a.id = ?', [$id]);
        if (!$a || (!Auth::isAdmin() && (int) $a['user_id'] !== (int) Auth::user()['id'])) {
            View::render('errors/404', [], 404);
            exit;
        }
        return $a;
    }

    public function index(): void
    {
        $where = Auth::isAdmin() ? '1=1' : 'a.user_id = ' . (int) Auth::user()['id'];
        $q = trim((string) ($_GET['q'] ?? ''));
        $p = [];
        if ($q !== '') {
            $where .= ' AND (a.host LIKE :q OR a.database_name LIKE :q OR a.engine LIKE :q)';
            $p['q'] = "%$q%";
        }
        $rows = Database::all("SELECT a.id, a.engine, a.host, a.port, a.database_name, a.score, a.status, a.ai_model, a.error, u.username,
                                      datetime(a.started_at, 'localtime') AS started
                                 FROM analyses a JOIN users u ON u.id = a.user_id WHERE $where ORDER BY a.id DESC LIMIT 300", $p);
        View::render('reports/index', ['title' => 'Relatórios', 'rows' => $rows, 'q' => $q]);
    }

    public function show(string $id): void
    {
        $a = $this->find((int) $id);
        $prev = Database::one("SELECT id, score, datetime(started_at,'localtime') AS started FROM analyses WHERE host = ? AND port = ? AND database_name = ? AND id < ? AND status = 'done' ORDER BY id DESC LIMIT 1",
            [$a['host'], $a['port'], $a['database_name'], $a['id']]);
        View::render('reports/show', ['title' => 'Laudo #' . $a['id'], 'a' => $a, 'prev' => $prev] + self::decode($a));
    }

    public static function decode(array $a): array
    {
        return [
            'm' => json_decode((string) $a['metrics_json'], true) ?: [],
            'findings' => json_decode((string) $a['findings_json'], true) ?: [],
            'tuning' => json_decode((string) $a['tuning_json'], true) ?: [],
            'hw' => json_decode((string) $a['hardware_json'], true) ?: [],
        ];
    }

    public function export(string $id, string $format): void
    {
        $a = $this->find((int) $id);
        $slug = preg_replace('/[^A-Za-z0-9_-]+/', '-', $a['database_name']) . '-' . $a['id'];
        Audit::log('report.export', "Laudo #{$a['id']} exportado em $format");
        switch ($format) {
            case 'md':
                header('Content-Type: text/markdown; charset=utf-8');
                header("Content-Disposition: attachment; filename=\"laudo-$slug.md\"");
                echo MarkdownReport::build($a);
                return;
            case 'html':
            case 'pdf':
                // HTML autocontido; "pdf" abre a mesma página e dispara a impressão (Salvar como PDF)
                if ($format === 'html') {
                    header("Content-Disposition: attachment; filename=\"laudo-$slug.html\"");
                }
                View::render('reports/print', ['a' => $a, 'autoPrint' => $format === 'pdf', 'md' => MarkdownReport::build($a)] + self::decode($a), 200, '');
                return;
        }
        View::render('errors/404', [], 404);
    }

    public function compare(): void
    {
        $a = $this->find((int) ($_GET['a'] ?? 0));
        $b = $this->find((int) ($_GET['b'] ?? 0));
        if ($a['id'] > $b['id']) {
            [$a, $b] = [$b, $a];
        }
        View::render('reports/compare', ['title' => 'Comparar laudos', 'a' => $a, 'b' => $b, 'da' => self::decode($a), 'db' => self::decode($b)]);
    }

    public function delete(string $id): void
    {
        $a = $this->find((int) $id);
        Database::exec('DELETE FROM analyses WHERE id = ?', [$a['id']]);
        Audit::log('report.deleted', "Laudo #{$a['id']} excluído", 'WARNING');
        Session::flash('success', "Laudo #{$a['id']} excluído.");
        Http::redirect('/reports');
    }
}
