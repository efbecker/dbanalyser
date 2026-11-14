<?php
/** @var string $content */
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$active = fn(string $p) => ($p === '/' ? $path === url('/') : str_starts_with((string) $path, url($p))) ? 'active' : '';
$isAdmin = ($user['role'] ?? '') === 'ADMIN';
$liveRuns = [];
if ($user) {
    try {
        $liveRuns = App\Core\Database::all("SELECT * FROM analyses WHERE status = 'running'" . ($isAdmin ? '' : ' AND user_id = ' . (int) $user['id']) . ' ORDER BY id DESC LIMIT 20');
    } catch (\Throwable) {
    }
}
$live0 = $liveRuns ? App\Analyzer\Runner::summary($liveRuns[0]) : null;
?><!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="<?= e(App\Core\Csrf::token()) ?>">
<meta name="base-path" content="<?= e(url('')) ?>">
<title><?= e(($title ?? 'Painel') . ' · ' . brand('name', 'DB Oráculo Analyzer')) ?></title>
<link rel="icon" href="<?= e(url('/branding/logo')) ?>">
<link rel="stylesheet" href="<?= e(asset('css/app.css')) ?>">
<style>:root{--accent:<?= e(brand('accent', '#00e5ff')) ?>}</style>
</head>
<body>
<div class="shell">
  <?php if ($user): ?>
  <aside class="sidebar" id="sidebar">
    <div class="brand">
      <img src="<?= e(url('/branding/logo')) ?>" alt="" class="brand-logo">
      <div>
        <div class="brand-name"><?= e(brand('name', 'DB Oráculo Analyzer')) ?></div>
        <?php if ($isAdmin): ?><span class="badge badge-accent">ADMIN</span><?php else: ?><span class="badge">CLIENTE</span><?php endif; ?>
      </div>
    </div>
    <nav class="nav">
      <a href="<?= e(url('/')) ?>" class="<?= $active('/') ?>"><span>📈</span> Painel</a>
      <a href="<?= e(url('/analyzer')) ?>" class="<?= $active('/analyzer') ?>"><span>🗄️</span> Analisador</a>
      <a href="<?= e(url('/reports')) ?>" class="<?= $active('/reports') ?>"><span>📊</span> Relatórios</a>
      <?php if ($isAdmin): ?>
      <div class="nav-section">Administração</div>
      <a href="<?= e(url('/admin/ai')) ?>" class="<?= $active('/admin/ai') ?>"><span>🧠</span> Inteligência Artificial</a>
      <a href="<?= e(url('/admin/users')) ?>" class="<?= $active('/admin/users') ?>"><span>👤</span> Usuários</a>
      <a href="<?= e(url('/admin/branding')) ?>" class="<?= $active('/admin/branding') ?>"><span>🎨</span> Branding</a>
      <a href="<?= e(url('/admin/logs')) ?>" class="<?= $active('/admin/logs') ?>"><span>📜</span> Logs</a>
      <?php endif; ?>
    </nav>
    <a class="nav-live" id="nav-live" href="<?= e(url($live0 && count($liveRuns) === 1 ? '/analyzer?watch=' . $live0['id'] : '/reports')) ?>" data-base="<?= e(url('')) ?>"<?= $live0 ? '' : ' hidden' ?>>
      <span class="nav-live-top"><span class="nav-live-dot"></span><span id="nav-live-count"><?= count($liveRuns) === 1 ? '1 análise em andamento' : count($liveRuns) . ' análises em andamento' ?></span><b id="nav-live-pct"><?= (int) ($live0['percent'] ?? 0) ?>%</b></span>
      <span class="nav-live-sub" id="nav-live-sub"><?= $live0 ? e('#' . $live0['id'] . ' · ' . $live0['database'] . ' · ' . $live0['stage_label']) : '' ?></span>
      <span class="live-track"><i id="nav-live-fill" style="width:<?= (int) ($live0['percent'] ?? 0) ?>%"></i></span>
    </a>
    <div class="sidebar-foot">
      <div class="who"><?= e($user['display_name'] ?: $user['username']) ?></div>
      <a href="<?= e(url('/account/password')) ?>" class="muted small">Alterar senha</a>
      <form method="post" action="<?= e(url('/logout')) ?>"><?= csrf_field() ?><button class="btn btn-ghost btn-sm">Sair</button></form>
      <div class="muted tiny">v<?= e(APP_VERSION) ?></div>
    </div>
  </aside>
  <?php endif; ?>
  <main class="main">
    <header class="topbar">
      <button class="btn btn-ghost btn-sm menu-toggle" data-toggle-sidebar aria-label="Menu">☰</button>
      <h1><?= e($title ?? '') ?></h1>
    </header>
    <?php foreach ($flash as $f): ?>
      <div class="alert alert-<?= e($f['type']) ?>"><?= e($f['msg']) ?></div>
    <?php endforeach; ?>
    <?= $content ?>
  </main>
</div>
<script src="<?= e(asset('js/app.js')) ?>"></script>
<?php foreach (($scripts ?? ($GLOBALS["__scripts"] ?? [])) as $s): ?><script src="<?= e(asset('js/' . $s)) ?>"></script><?php endforeach; ?>
</body>
</html>
