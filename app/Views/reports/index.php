<section class="card">
  <div class="card-head">
    <form method="get" class="inline"><input type="search" name="q" class="search" value="<?= e($q) ?>" placeholder="Filtrar por host, banco ou motor…"></form>
    <button class="btn btn-ghost btn-sm" id="btn-compare" disabled data-base="<?= e(url('/reports/compare')) ?>">⇄ Comparar selecionados</button>
  </div>
  <table class="table">
    <thead><tr><th></th><th>#</th><th>Data</th><th>Motor</th><th>Servidor</th><th>Banco</th><th>Score</th><th>Status</th><th>IA</th><?php if (($user['role'] ?? '') === 'ADMIN'): ?><th>Usuário</th><?php endif; ?><th class="right">Exportar</th></tr></thead>
    <tbody>
    <?php if (!$rows): ?><tr><td colspan="11" class="muted center">Nenhuma análise encontrada.</td></tr><?php endif; ?>
    <?php foreach ($rows as $r): ?>
      <tr>
        <td><?php if ($r['status'] === 'done'): ?><input type="checkbox" class="cmp" value="<?= (int) $r['id'] ?>"><?php endif; ?></td>
        <td><a href="<?= e(url('/reports/' . $r['id'])) ?>">#<?= (int) $r['id'] ?></a></td>
        <td class="small nowrap"><?= e($r['started']) ?></td>
        <td><span class="engine engine-<?= e($r['engine']) ?>"><?= e($r['engine']) ?></span></td>
        <td class="small"><?= e($r['host'] . ':' . $r['port']) ?></td>
        <td><?= e($r['database_name']) ?></td>
        <td><?php if ($r['score'] !== null): ?><span class="score score-<?= $r['score'] >= 80 ? 'good' : ($r['score'] >= 50 ? 'warn' : 'bad') ?>"><?= (int) $r['score'] ?></span><?php endif; ?></td>
        <td><span class="status status-<?= e($r['status']) ?>" title="<?= e($r['error'] ?? '') ?>"><?= e($r['status']) ?></span></td>
        <td class="small muted"><?= e($r['ai_model'] ?? '—') ?></td>
        <?php if (($user['role'] ?? '') === 'ADMIN'): ?><td class="small"><?= e($r['username']) ?></td><?php endif; ?>
        <td class="right nowrap">
          <?php if ($r['status'] === 'done'): foreach (['pdf' => 'PDF', 'html' => 'HTML', 'md' => 'MD'] as $fmt => $lbl): ?>
            <a class="btn btn-ghost btn-xs" href="<?= e(url("/reports/{$r['id']}/export/$fmt")) ?>" <?= $fmt === 'pdf' ? 'target="_blank"' : '' ?>><?= $lbl ?></a>
          <?php endforeach; endif; ?>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</section>
