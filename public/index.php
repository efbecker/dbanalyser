<?php
declare(strict_types=1);

/**
 * Front controller — único ponto de entrada PHP exposto pelo Apache.
 */
require dirname(__DIR__) . '/app/bootstrap.php';

use App\Controllers\{AiController, AnalyzerController, AuthController, BrandingController,
    DashboardController, LogController, ReportController, UserController};
use App\Core\{Audit, Http, Router, Session, View};

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

Session::start();

$r = new Router();
$admin = ['role' => 'ADMIN'];

// Autenticação
$r->get('/login', [AuthController::class, 'showLogin'], ['auth' => false]);
$r->post('/login', [AuthController::class, 'login'], ['auth' => false]);
$r->post('/logout', [AuthController::class, 'logout'], ['allow_pw_change' => true]);
$r->get('/account/password', [AuthController::class, 'showPassword'], ['allow_pw_change' => true]);
$r->post('/account/password', [AuthController::class, 'changePassword'], ['allow_pw_change' => true]);
$r->get('/branding/logo', [BrandingController::class, 'logo'], ['auth' => false]);

// Painel
$r->get('/', [DashboardController::class, 'index']);

// Analisador
$r->get('/analyzer', [AnalyzerController::class, 'index']);
$r->post('/api/analyzer/databases', [AnalyzerController::class, 'listDatabases']);
$r->post('/api/analyzer/start', [AnalyzerController::class, 'start']);
$r->post('/api/analyzer/step', [AnalyzerController::class, 'step']);
$r->post('/api/analyzer/ssh', [AnalyzerController::class, 'testSsh']);

// Relatórios
$r->get('/reports', [ReportController::class, 'index']);
$r->get('/reports/compare', [ReportController::class, 'compare']);
$r->get('/reports/{id}', [ReportController::class, 'show']);
$r->get('/reports/{id}/export/{format}', [ReportController::class, 'export']);
$r->post('/reports/{id}/delete', [ReportController::class, 'delete']);

// Administração
$r->get('/admin/ai', [AiController::class, 'index'], $admin);
$r->post('/admin/ai/global', [AiController::class, 'saveGlobal'], $admin);
$r->post('/admin/ai/profiles', [AiController::class, 'saveProfile'], $admin);
$r->post('/admin/ai/profiles/{id}/delete', [AiController::class, 'deleteProfile'], $admin);
$r->post('/api/ai/test', [AiController::class, 'test'], $admin);

$r->get('/admin/users', [UserController::class, 'index'], $admin);
$r->get('/api/users', [UserController::class, 'search'], $admin);
$r->post('/admin/users', [UserController::class, 'save'], $admin);
$r->post('/admin/users/{id}/delete', [UserController::class, 'delete'], $admin);

$r->get('/admin/branding', [BrandingController::class, 'index'], $admin);
$r->post('/admin/branding', [BrandingController::class, 'save'], $admin);

$r->get('/admin/logs', [LogController::class, 'index'], $admin);

try {
    $r->dispatch($_SERVER['REQUEST_METHOD'] ?? 'GET', $_SERVER['REQUEST_URI'] ?? '/');
} catch (Throwable $e) {
    error_log('[db-analyzer] ' . $e);
    Audit::log('app.error', $e->getMessage(), 'ERROR', ['file' => $e->getFile(), 'line' => $e->getLine()]);
    if (str_starts_with(parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '', '/api/')) {
        Http::json(['error' => 'Erro interno: ' . $e->getMessage()], 500);
    } else {
        View::render('errors/500', ['message' => App\Core\Config::get('debug') ? (string) $e : null], 500);
    }
}
