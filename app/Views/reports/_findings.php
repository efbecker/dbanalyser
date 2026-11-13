<?php
/** @var array $list */
$sevLabel = ['critical' => 'CRÍTICO', 'high' => 'ALTO', 'medium' => 'MÉDIO', 'low' => 'BAIXO'];
if (!$list): ?>
  <p class="muted">✔ Nenhum problema encontrado nesta categoria.</p>
<?php else: ?>
<div class="findings">
<?php foreach ($list as $f): ?>
  <details class="finding sev-border-<?= e($f['severity']) ?>">
    <summary><span class="sev sev-<?= e($f['severity']) ?>"><?= e($sevLabel[$f['severity']] ?? $f['severity']) ?></span> <?= e($f['title']) ?></summary>
    <p><?= nl2br(e($f['detail'])) ?></p>
    <?php if (!empty($f['fix_sql'])): ?>
      <div class="code-block"><button type="button" class="copy-btn" data-copy>Copiar</button><pre class="code"><code><?= e($f['fix_sql']) ?></code></pre></div>
    <?php endif; ?>
  </details>
<?php endforeach; ?>
</div>
<?php endif;
