<?php if (!$aiReady && ($user['role'] ?? '') === 'ADMIN'): ?>
<div class="alert alert-warning">Nenhuma IA configurada. As análises funcionam só com regras determinísticas até você <a href="<?= e(url('/admin/ai')) ?>">configurar um provedor</a>.</div>
<?php endif; ?>
<div class="grid kpis">
  <div class="card kpi"><div class="kpi-label">Análises concluídas</div><div class="kpi-value" data-count="<?= (int) $stats['total'] ?>">0</div></div>
  <div class="card kpi"><div class="kpi-label">Score médio</div><div class="kpi-value" data-count="<?= (int) $stats['avg_score'] ?>">0</div></div>
  <div class="card kpi"><div class="kpi-label">Análises (30 dias)</div><div class="kpi-value" data-count="<?= (int) $stats['last30'] ?>">0</div></div>
  <div class="card kpi"><div class="kpi-label">Tokens de IA (30 dias)</div><div class="kpi-value" data-count="<?= (int) ($tokens['tin'] + $tokens['tout']) ?>">0</div></div>
</div>
<section class="card">
  <div class="card-head"><h2>Últimas análises</h2><a class="btn btn-primary btn-sm" href="<?= e(url('/analyzer')) ?>">＋ Nova análise</a></div>
  <?php if (!$recent): ?>
    <p class="muted">Nenhuma análise ainda. Abra o <a href="<?= e(url('/analyzer')) ?>">Analisador</a> para começar.</p>
  <?php else: ?>
  <table class="table">
    <thead><tr><th>#</th><th>Alvo</th><th>Banco</th><th>Score</th><th>Status</th><th>Data</th></tr></thead>
    <tbody>
    <?php foreach ($recent as $r): ?>
      <tr<?= $r['status'] === 'running' ? ' class="row-live"' : '' ?>>
        <td><a href="<?= e(url('/reports/' . $r['id'])) ?>">#<?= (int) $r['id'] ?></a></td>
        <td><span class="engine engine-<?= e($r['engine']) ?>"><?= e($r['engine']) ?></span> <?= e($r['host']) ?></td>
        <td><?= e($r['database_name']) ?></td>
        <td><?php if ($r['score'] !== null): ?><span class="score score-<?= $r['score'] >= 80 ? 'good' : ($r['score'] >= 50 ? 'warn' : 'bad') ?>"><?= (int) $r['score'] ?></span><?php endif; ?></td>
        <td><?php if ($r['status'] === 'running'): ?><?= live_progress($r) ?><?php else: ?><span class="status status-<?= e($r['status']) ?>"><?= e($r['status']) ?></span><?php endif; ?></td>
        <td class="muted"><?= e($r['started_at']) ?> UTC</td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <?php endif; ?>
</section>
