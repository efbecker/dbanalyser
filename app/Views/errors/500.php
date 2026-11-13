<?php $title = 'Erro interno'; ?>
<section class="card narrow center">
  <div class="error-code">500</div>
  <h2>Erro interno</h2>
  <p class="muted">O erro foi registrado nos logs de auditoria.<?php if (!empty($message)): ?><pre class="code"><?= e($message) ?></pre><?php endif; ?></p>
  <a class="btn btn-primary" href="<?= e(url('/')) ?>">Voltar ao painel</a>
</section>
