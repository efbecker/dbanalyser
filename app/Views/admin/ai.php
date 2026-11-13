<?php
$opt = function (?string $sel) use ($providers) {
    $h = '';
    foreach ($providers as $k => $p) {
        $h .= '<option value="' . e($k) . '" data-model="' . e($p['model']) . '" data-base="' . e($p['base']) . '"' . ($sel === $k ? ' selected' : '') . '>' . e($p['label']) . '</option>';
    }
    return $h;
};
?>
<section class="card">
  <div class="card-head"><h2>Seção 1 · IA Padrão Global</h2><span class="muted small">Usada por todos os usuários sem perfil específico</span></div>
  <form method="post" action="<?= e(url('/admin/ai/global')) ?>" class="form grid-form" data-ai-form data-global="1">
    <?= csrf_field() ?>
    <label>Provedor<select name="provider" required><?= $opt($global['provider'] ?? 'openai') ?></select></label>
    <label>Modelo <small class="muted">(em branco = padrão do provedor)</small><input name="model" value="<?= e($global['model'] ?? '') ?>" data-model-input></label>
    <label>API Key <small class="muted"><?= $global ? 'atual: ' . e($globalMasked) . ' — vazio mantém' : '' ?></small><input type="password" name="api_key" autocomplete="off" placeholder="<?= $global ? 'Manter chave atual' : 'sk-...' ?>"></label>
    <label>Base URL <small class="muted">(opcional)</small><input name="base_url" value="<?= e($global['base_url'] ?? '') ?>" data-base-input placeholder="padrão do provedor"></label>
    <label>Temperatura <small class="muted">(ignorada pela Anthropic e por modelos de raciocínio)</small><input type="number" step="0.1" min="0" max="1.5" name="temperature" value="<?= e($global['temperature'] ?? '0.2') ?>"></label>
    <label>Máx. tokens de saída<input type="number" min="256" max="64000" name="max_tokens" value="<?= e($global['max_tokens'] ?? '16000') ?>"></label>
    <div class="form-actions span-2">
      <button type="button" class="btn btn-ghost" data-ai-test>🔌 Testar Conexão</button>
      <button class="btn btn-primary">💾 Salvar e Aplicar</button>
      <span class="test-result" data-ai-result></span>
    </div>
  </form>
</section>

<section class="card">
  <div class="card-head"><h2>Seção 2 · Perfis de IA por Cliente</h2><?php if ($edit): ?><a class="btn btn-ghost btn-sm" href="<?= e(url('/admin/ai')) ?>">Cancelar edição</a><?php endif; ?></div>
  <form method="post" action="<?= e(url('/admin/ai/profiles')) ?>" class="form grid-form" data-ai-form>
    <?= csrf_field() ?>
    <input type="hidden" name="id" value="<?= e($edit['id'] ?? '') ?>">
    <label>Nome do Perfil<input name="name" required maxlength="80" value="<?= e($edit['name'] ?? '') ?>" placeholder="Ex: Cliente ACME — Claude"></label>
    <label>Provedor<select name="provider" required><?= $opt($edit['provider'] ?? 'anthropic') ?></select></label>
    <label>Modelo<input name="model" value="<?= e($edit['model'] ?? '') ?>" data-model-input></label>
    <label>API Key <?= $edit ? '<small class="muted">vazio mantém a atual</small>' : '' ?><input type="password" name="api_key" autocomplete="off"></label>
    <label>Base URL <small class="muted">(endpoints customizados/locais)</small><input name="base_url" value="<?= e($edit['base_url'] ?? '') ?>" data-base-input></label>
    <label>Temperatura <small class="muted">(ignorada pela Anthropic e por modelos de raciocínio)</small><input type="number" step="0.1" min="0" max="1.5" name="temperature" value="<?= e($edit['temperature'] ?? '0.2') ?>"></label>
    <input type="hidden" name="max_tokens" value="<?= e($edit['max_tokens'] ?? '16000') ?>">
    <div class="form-actions span-2">
      <button type="button" class="btn btn-ghost" data-ai-test>🔌 Testar Conexão</button>
      <button class="btn btn-primary"><?= $edit ? '💾 Atualizar Perfil' : '＋ Criar Perfil' ?></button>
      <span class="test-result" data-ai-result></span>
    </div>
  </form>

  <table class="table mt">
    <thead><tr><th>PERFIL</th><th>PROVEDOR</th><th>MODELO</th><th>API KEY</th><th>BASE URL</th><th>USUÁRIOS</th><th class="right">AÇÕES</th></tr></thead>
    <tbody>
    <?php if (!$profiles): ?><tr><td colspan="7" class="muted center">Nenhum perfil cadastrado.</td></tr><?php endif; ?>
    <?php foreach ($profiles as $p): ?>
      <tr>
        <td><strong><?= e($p['name']) ?></strong></td>
        <td><?= e($providers[$p['provider']]['label'] ?? $p['provider']) ?></td>
        <td><code><?= e($p['model'] ?: $providers[$p['provider']]['model'] . ' (padrão)') ?></code></td>
        <td><code><?= e($p['api_key_masked']) ?></code></td>
        <td class="muted small"><?= e($p['base_url'] ?: '—') ?></td>
        <td><?= (int) $p['users'] ?></td>
        <td class="right nowrap">
          <a class="btn btn-edit btn-sm" href="<?= e(url('/admin/ai?edit=' . $p['id'])) ?>">Editar</a>
          <form method="post" action="<?= e(url('/admin/ai/profiles/' . $p['id'] . '/delete')) ?>" class="inline" data-confirm="Excluir o perfil '<?= e($p['name']) ?>'?">
            <?= csrf_field() ?><button class="btn btn-danger btn-sm">Excluir</button>
          </form>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</section>
