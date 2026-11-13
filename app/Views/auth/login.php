<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entrar · <?= e(brand('name', 'DB Oráculo Analyzer')) ?></title>
<link rel="icon" href="<?= e(url('/branding/logo')) ?>">
<link rel="stylesheet" href="<?= e(asset('css/app.css')) ?>">
<style>:root{--accent:<?= e(brand('accent', '#00e5ff')) ?>}</style>
</head>
<body class="login-page">
<canvas id="login-bg" aria-hidden="true"></canvas>
<form class="login-card" method="post" action="<?= e(url('/login')) ?>" autocomplete="on">
  <?= csrf_field() ?>
  <img src="<?= e(url('/branding/logo')) ?>" alt="" class="login-logo">
  <h1><?= e(brand('name', 'DB Oráculo Analyzer')) ?></h1>
  <p class="muted">Diagnóstico, auditoria e tuning de bancos de dados com IA</p>
  <?php if ($error): ?><div class="alert alert-error"><?= e($error) ?></div><?php endif; ?>
  <label>Usuário<input name="username" value="<?= e($username) ?>" required autofocus autocomplete="username"></label>
  <label>Senha<input type="password" name="password" required autocomplete="current-password"></label>
  <button class="btn btn-primary btn-block">Entrar</button>
  <p class="tiny muted">Acesso monitorado. Tentativas falhas são registradas e bloqueadas temporariamente.</p>
</form>
<script src="<?= e(asset('js/login.js')) ?>"></script>
</body>
</html>
