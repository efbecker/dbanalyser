<?php $infra = json_decode((string) ($edit['infra_json'] ?? ''), true) ?: []; ?>
<section class="card">
  <div class="card-head"><h2><?= $edit ? 'Atualizar conta: ' . e($edit['username']) : 'Cadastrar conta' ?></h2><?php if ($edit): ?><a class="btn btn-ghost btn-sm" href="<?= e(url('/admin/users')) ?>">Nova conta</a><?php endif; ?></div>
  <form method="post" action="<?= e(url('/admin/users')) ?>" class="form grid-form" autocomplete="off">
    <?= csrf_field() ?>
    <input type="hidden" name="id" value="<?= e($edit['id'] ?? '') ?>">
    <label>Usuário (login)<input name="username" required pattern="[A-Za-z0-9._@\-]{3,64}" value="<?= e($edit['username'] ?? '') ?>"></label>
    <label>Senha <small class="muted"><?= $edit ? '(vazio p/ manter)' : '(mín. 10 caracteres)' ?></small><input type="password" name="password" <?= $edit ? '' : 'required' ?> minlength="10" autocomplete="new-password"></label>
    <label>Nome de exibição<input name="display_name" value="<?= e($edit['display_name'] ?? '') ?>"></label>
    <label>E-mail<input type="email" name="email" value="<?= e($edit['email'] ?? '') ?>"></label>
    <label>Perfil de Acesso
      <select name="role">
        <option value="CLIENT" <?= ($edit['role'] ?? 'CLIENT') === 'CLIENT' ? 'selected' : '' ?>>CLIENTE</option>
        <option value="ADMIN" <?= ($edit['role'] ?? '') === 'ADMIN' ? 'selected' : '' ?>>ADMINISTRADOR</option>
      </select>
    </label>
    <label>Perfil de IA
      <select name="ai_profile_id">
        <option value="">IA padrão do sistema</option>
        <?php foreach ($profiles as $p): ?>
          <option value="<?= (int) $p['id'] ?>" <?= (int) ($edit['ai_profile_id'] ?? 0) === (int) $p['id'] ? 'selected' : '' ?>><?= e($p['name']) ?> (<?= e($p['provider']) ?>)</option>
        <?php endforeach; ?>
      </select>
    </label>
    <fieldset class="span-2">
      <legend>Infraestrutura do cliente <small class="muted">(apoia o cálculo de dimensionamento)</small></legend>
      <div class="grid-form">
        <label>Monitoramento<select name="monitoring_type">
          <?php foreach (['' => 'Nenhum', 'zabbix' => 'Zabbix', 'prometheus' => 'Prometheus', 'netdata' => 'Netdata', 'other' => 'Outro'] as $k => $v): ?>
            <option value="<?= e($k) ?>" <?= ($infra['monitoring_type'] ?? '') === $k ? 'selected' : '' ?>><?= e($v) ?></option>
          <?php endforeach; ?></select></label>
        <label>Endpoint de monitoramento<input type="url" name="monitoring_url" value="<?= e($infra['monitoring_url'] ?? '') ?>" placeholder="https://zabbix.exemplo.com/api_jsonrpc.php"></label>
        <label>Clock por vCPU (GHz)<input name="vcpu_clock_ghz" inputmode="decimal" value="<?= e($infra['vcpu_clock_ghz'] ?? '') ?>" placeholder="2.6"></label>
        <label>vCPUs padrão do cluster<input type="number" min="1" name="default_vcpu" value="<?= e($infra['default_vcpu'] ?? '') ?>"></label>
        <label>RAM padrão (GB)<input name="default_ram_gb" inputmode="decimal" value="<?= e($infra['default_ram_gb'] ?? '') ?>"></label>
        <label>Observações<input name="notes" value="<?= e($infra['notes'] ?? '') ?>"></label>
      </div>
    </fieldset>
    <input type="hidden" name="is_active" value="0">
    <label class="check"><input type="checkbox" name="is_active" value="1" <?= ($edit['is_active'] ?? 1) ? 'checked' : '' ?>> Conta ativa</label>
    <label class="check"><input type="checkbox" name="force_change" value="1" <?= $edit ? '' : 'checked' ?>> Exigir troca de senha no próximo login</label>
    <div class="form-actions span-2"><button class="btn btn-primary">💾 Salvar conta</button></div>
  </form>
</section>

<section class="card" data-users-table data-endpoint="<?= e(url('/api/users')) ?>">
  <div class="card-head">
    <h2>Contas cadastradas <span class="muted small" data-total></span></h2>
    <input type="search" class="search" placeholder="Buscar por login, nome, e-mail ou perfil…" data-search>
  </div>
  <table class="table">
    <thead><tr><th>LOGIN</th><th>NOME</th><th>PERFIL</th><th>IA</th><th>STATUS</th><th>ÚLTIMO ACESSO</th><th class="right">AÇÕES</th></tr></thead>
    <tbody data-rows><tr><td colspan="7" class="muted center">Carregando…</td></tr></tbody>
  </table>
  <div class="pager" data-pager></div>
  <template data-row-template>
    <tr>
      <td><strong data-f="username"></strong></td><td data-f="display_name"></td><td data-f="role"></td><td data-f="ai_profile" class="small"></td>
      <td data-f="status"></td><td data-f="last_login_at" class="muted small"></td>
      <td class="right nowrap">
        <a class="btn btn-edit btn-sm" data-edit>Editar</a>
        <form method="post" class="inline" data-delete><?= csrf_field() ?><button class="btn btn-danger btn-sm">Excluir</button></form>
      </td>
    </tr>
  </template>
</section>
