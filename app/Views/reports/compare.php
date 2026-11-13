<?php
$fa = $da['findings']; $fb = $db['findings'];
$titlesA = array_column($fa, 'title'); $titlesB = array_column($fb, 'title');
$fixed = array_diff($titlesA, $titlesB); $new = array_diff($titlesB, $titlesA);
$delta = (int) $b['score'] - (int) $a['score'];
$sa = $da['m']['sizing']['stats'] ?? []; $sb = $db['m']['sizing']['stats'] ?? [];
?>
<section class="card">
  <div class="compare-head">
    <div><div class="muted small">Antes · #<?= (int) $a['id'] ?> · <?= e($a['started_at']) ?></div><div class="big"><?= (int) $a['score'] ?></div></div>
    <div class="delta <?= $delta >= 0 ? 'ok' : 'bad' ?>"><?= $delta >= 0 ? '▲ +' : '▼ ' ?><?= $delta ?></div>
    <div><div class="muted small">Depois · #<?= (int) $b['id'] ?> · <?= e($b['started_at']) ?></div><div class="big"><?= (int) $b['score'] ?></div></div>
  </div>
  <p class="center muted"><?= e($a['database_name']) ?> @ <?= e($a['host']) ?><?= $a['database_name'] !== $b['database_name'] ? ' vs ' . e($b['database_name']) . ' @ ' . e($b['host']) : '' ?></p>
</section>
<div class="grid two">
  <section class="card"><h3 class="ok">✔ Resolvidos (<?= count($fixed) ?>)</h3><ul class="small"><?php foreach ($fixed as $t): ?><li><?= e($t) ?></li><?php endforeach; ?></ul></section>
  <section class="card"><h3 class="bad">✘ Novos (<?= count($new) ?>)</h3><ul class="small"><?php foreach ($new as $t): ?><li><?= e($t) ?></li><?php endforeach; ?></ul></section>
</div>
<section class="card">
  <h3>Métricas</h3>
  <table class="table"><thead><tr><th>Métrica</th><th class="right">Antes</th><th class="right">Depois</th></tr></thead><tbody>
  <?php foreach (array_unique(array_merge(array_keys($sa), array_keys($sb))) as $k): if (!is_scalar($sa[$k] ?? '') || !is_scalar($sb[$k] ?? '')) continue; ?>
    <tr><td><code><?= e($k) ?></code></td><td class="right"><?= e($sa[$k] ?? '—') ?></td><td class="right"><?= e($sb[$k] ?? '—') ?></td></tr>
  <?php endforeach; ?>
    <tr><td><code>findings</code></td><td class="right"><?= count($fa) ?></td><td class="right"><?= count($fb) ?></td></tr>
    <tr><td><code>verdict</code></td><td class="right"><?= e($da['tuning']['verdict'] ?? '—') ?></td><td class="right"><?= e($db['tuning']['verdict'] ?? '—') ?></td></tr>
  </tbody></table>
</section>
