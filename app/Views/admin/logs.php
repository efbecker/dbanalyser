<section class="card">
  <form method="get" class="filters">
    <label>De<input type="date" name="from" value="<?= e($f['from']) ?>"></label>
    <label>Até<input type="date" name="to" value="<?= e($f['to']) ?>"></label>
    <label>Usuário<input name="user" value="<?= e($f['user']) ?>"></label>
    <label>Severidade<select name="severity"><option value="">Todas</option>
      <?php foreach (['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'] as $s): ?><option <?= $f['severity'] === $s ? 'selected' : '' ?>><?= $s ?></option><?php endforeach; ?>
    </select></label>
    <label>Evento/texto<input name="q" value="<?= e($f['q']) ?>" placeholder="auth.failed, ai.usage…"></label>
    <button class="btn btn-primary">Filtrar</button>
  </form>
</section>
<?php if ($usage): ?>
<section class="card">
  <h2>Consumo de tokens de IA no período</h2>
  <table class="table"><thead><tr><th>Provedor</th><th>Modelo</th><th class="right">Chamadas</th><th class="right">Tokens entrada</th><th class="right">Tokens saída</th><th class="right">Latência média</th></tr></thead><tbody>
  <?php foreach ($usage as $u): ?>
    <tr><td><?= e($u['provider']) ?></td><td><code><?= e($u['model']) ?></code></td><td class="right"><?= (int) $u['calls'] ?></td>
    <td class="right"><?= number_format((int) $u['tin'], 0, ',', '.') ?></td><td class="right"><?= number_format((int) $u['tout'], 0, ',', '.') ?></td><td class="right"><?= (int) $u['lat'] ?> ms</td></tr>
  <?php endforeach; ?>
  </tbody></table>
</section>
<?php endif; ?>
<section class="card">
  <div class="card-head"><h2>Eventos <span class="muted small"><?= $total ?> registros</span></h2></div>
  <table class="table logs">
    <thead><tr><th>Data/hora</th><th>Severidade</th><th>Evento</th><th>Usuário</th><th>IP</th><th>Mensagem</th></tr></thead>
    <tbody>
    <?php if (!$rows): ?><tr><td colspan="6" class="muted center">Nenhum evento no período.</td></tr><?php endif; ?>
    <?php foreach ($rows as $r): ?>
      <tr>
        <td class="nowrap small"><?= e($r['local_time']) ?></td>
        <td><span class="sev sev-<?= e(strtolower($r['severity'])) ?>"><?= e($r['severity']) ?></span></td>
        <td><code><?= e($r['event']) ?></code></td>
        <td><?= e($r['username'] ?? '—') ?></td>
        <td class="small muted"><?= e($r['ip']) ?></td>
        <td class="small"><?= e($r['message']) ?><?php if ($r['context_json']): ?> <details><summary class="muted tiny">contexto</summary><pre class="code tiny"><?= e($r['context_json']) ?></pre></details><?php endif; ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
  <?php if ($pages > 1): ?>
  <div class="pager">
    <?php for ($i = max(1, $page - 5); $i <= min($pages, $page + 5); $i++): ?>
      <a class="btn btn-sm <?= $i === $page ? 'btn-primary' : 'btn-ghost' ?>" href="?<?= e(http_build_query(array_merge($f, ['page' => $i]))) ?>"><?= $i ?></a>
    <?php endfor; ?>
  </div>
  <?php endif; ?>
</section>
