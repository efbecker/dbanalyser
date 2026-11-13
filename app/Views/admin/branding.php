<section class="card narrow-lg">
  <form method="post" action="<?= e(url('/admin/branding')) ?>" enctype="multipart/form-data" class="form grid-form">
    <?= csrf_field() ?>
    <label>Nome do sistema<input name="name" maxlength="60" value="<?= e(brand('name')) ?>"></label>
    <label>Nome curto<input name="short" maxlength="16" value="<?= e(brand('short')) ?>"></label>
    <label>Cor de destaque (interface)<input type="color" name="accent" value="<?= e(brand('accent', '#00e5ff')) ?>"></label>
    <label>Cor de destaque (relatórios)<input type="color" name="report_color" value="<?= e(brand('report_color', '#00e5ff')) ?>"></label>
    <label class="span-2">Rodapé dos laudos<input name="footer" maxlength="300" value="<?= e(brand('footer')) ?>"></label>
    <div class="span-2 logo-row">
      <img src="<?= e(url('/branding/logo')) ?>?t=<?= time() ?>" alt="Logo atual" class="logo-preview">
      <label>Logotipo / ícone <small class="muted">PNG, JPG, WEBP ou SVG até 512 KB</small><input type="file" name="logo" accept="image/png,image/jpeg,image/webp,image/svg+xml"></label>
      <?php if (brand('logo')): ?><label class="check"><input type="checkbox" name="remove_logo" value="1"> Remover logo personalizado</label><?php endif; ?>
    </div>
    <div class="form-actions span-2"><button class="btn btn-primary">💾 Salvar branding</button></div>
  </form>
</section>
