<?php if ((int) $user['must_change_password'] === 1): ?>
<div class="alert alert-warning">Por segurança, defina uma nova senha antes de continuar (a senha inicial foi gerada pelo instalador).</div>
<?php endif; ?>
<section class="card narrow">
  <form method="post" action="<?= e(url('/account/password')) ?>" class="form">
    <?= csrf_field() ?>
    <label>Senha atual<input type="password" name="current" required autocomplete="current-password"></label>
    <label>Nova senha (mín. 10 caracteres)<input type="password" name="password" required minlength="10" autocomplete="new-password"></label>
    <label>Confirmar nova senha<input type="password" name="confirm" required minlength="10" autocomplete="new-password"></label>
    <button class="btn btn-primary">Salvar nova senha</button>
  </form>
</section>
