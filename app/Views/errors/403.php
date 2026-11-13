<?php $title = 'Acesso negado'; ?>
<section class="card narrow center">
  <div class="error-code">403</div>
  <h2>Acesso negado</h2>
  <p class="muted"><?= e($message ?? "Você não tem permissão para acessar este recurso.") ?></p>
  <a class="btn btn-primary" href="<?= e(url('/')) ?>">Voltar ao painel</a>
</section>
