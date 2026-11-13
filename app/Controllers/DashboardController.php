<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Core\{Auth, Database, View};

final class DashboardController
{
    public function index(): void
    {
        $u = Auth::user();
        $scope = Auth::isAdmin() ? '1=1' : 'user_id = ' . (int) $u['id'];
        $stats = Database::one("SELECT COUNT(*) AS total, ROUND(AVG(score)) AS avg_score,
                                       SUM(CASE WHEN started_at >= datetime('now','-30 days') THEN 1 ELSE 0 END) AS last30
                                  FROM analyses WHERE status = 'done' AND $scope");
        $recent = Database::all("SELECT id, engine, host, database_name, score, status, started_at FROM analyses WHERE $scope ORDER BY id DESC LIMIT 8");
        $tokens = Database::one("SELECT COALESCE(SUM(tokens_in),0) AS tin, COALESCE(SUM(tokens_out),0) AS tout FROM ai_usage
                                  WHERE created_at >= datetime('now','-30 days')" . (Auth::isAdmin() ? '' : ' AND user_id = ' . (int) $u['id']));
        $aiReady = (bool) Database::value('SELECT 1 FROM ai_profiles WHERE is_global = 1') || !empty($u['ai_profile_id']);
        View::render('dashboard', ['title' => 'Painel', 'stats' => $stats, 'recent' => $recent, 'tokens' => $tokens, 'aiReady' => $aiReady]);
    }
}
