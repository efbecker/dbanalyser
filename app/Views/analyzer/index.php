<?php $GLOBALS['__scripts'] = ['analyzer.js']; ?>
<?php if (!$ai): ?>
<div class="alert alert-warning">Nenhuma IA vinculada à sua conta: o laudo será gerado apenas com regras determinísticas.</div>
<?php else: ?>
<div class="alert alert-info small">IA ativa: <strong><?= e($ai->provider) ?></strong> / <code><?= e($ai->model) ?></code>. Toda coleta é feita em <strong>modo somente leitura</strong>.</div>
<?php endif; ?>
<div class="analyzer">
  <section class="card analyzer-form">
    <form id="conn-form" class="form" autocomplete="off">
      <h2>1 · Conexão</h2>
      <div class="engine-pick">
        <?php foreach ($engines as $k => $eng): ?>
          <label class="engine-opt"><input type="radio" name="engine" value="<?= e($k) ?>" data-port="<?= (int) $eng['port'] ?>" <?= $k === 'postgresql' ? 'checked' : '' ?>><span><?= e($eng['label']) ?></span></label>
        <?php endforeach; ?>
      </div>
      <div class="row">
        <label class="grow">Host / IP<input name="host" required placeholder="10.0.0.15 ou db.exemplo.com"></label>
        <label class="w-port">Porta<input name="port" type="number" min="1" max="65535" value="5432"></label>
      </div>
      <div class="row">
        <label class="grow">Usuário<input name="username" required autocomplete="off"></label>
        <label class="grow">Senha<input name="password" type="password" autocomplete="new-password"></label>
      </div>
      <label>Banco inicial <small class="muted" id="initial-db-help">(opcional; use se o pg_hba.conf só libera um banco, ex.: zabbix)</small><input name="initial_db" placeholder="automático: postgres → nome do usuário"></label>
      <label>SSL/TLS
        <select name="ssl">
          <option value="prefer">Preferir (prefer)</option><option value="require">Exigir (require)</option>
          <option value="verify-full">Exigir e validar certificado (verify-full)</option><option value="disable">Desativado</option>
        </select>
      </label>
      <button type="button" class="btn btn-primary btn-block" id="btn-list">🔌 Conectar e Listar Bancos</button>
      <div class="test-result" id="conn-status"></div>

      <h2 class="mt">2 · Servidor do banco via SSH <small class="muted">(opcional)</small></h2>
      <label class="check"><input type="checkbox" name="ssh_enabled" value="1" id="ssh-enabled"> Coletar memória, swap, CPU, disco e OOM do sistema operacional</label>
      <div id="ssh-fields" hidden>
        <p class="small muted">Somente leitura: o analisador roda apenas uma lista fixa de comandos de consulta (free, vmstat, /proc/meminfo, sysctl vm.*, dmesg, df…), sem sudo.
          Use um usuário comum; para ver eventos de OOM ele precisa estar no grupo <code>adm</code> ou usar a opção de sudo abaixo. As credenciais ficam cifradas apenas enquanto a análise roda no servidor e são apagadas ao terminar.</p>
        <div class="row">
          <label class="grow">Host SSH<input name="ssh_host" placeholder="mesmo host do banco"></label>
          <label class="w-port">Porta<input name="ssh_port" type="number" min="1" max="65535" value="22"></label>
        </div>
        <div class="row">
          <label class="grow">Usuário SSH<input name="ssh_user" autocomplete="off"></label>
          <label class="grow">Autenticação<select name="ssh_auth" id="ssh-auth"><option value="password">Senha</option><option value="key">Chave privada</option></select></label>
        </div>
        <label data-ssh="password">Senha SSH<input name="ssh_password" type="password" autocomplete="new-password"></label>
        <label data-ssh="key" hidden>Chave privada <small class="muted">(OpenSSH/PEM)</small><textarea name="ssh_key" rows="4" spellcheck="false" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></label>
        <label data-ssh="key" hidden>Passphrase da chave <small class="muted">(se houver)</small><input name="ssh_passphrase" type="password" autocomplete="new-password"></label>
        <label class="check"><input type="checkbox" name="ssh_sudo" value="1" id="ssh-sudo"> Usar sudo para ler o log do kernel (OOM) quando o usuário não tiver acesso</label>
        <label id="ssh-sudo-pw" hidden>Senha do sudo <small class="muted">(vazio: usa a senha SSH, ou NOPASSWD no sudoers)</small><input name="ssh_sudo_password" type="password" autocomplete="new-password"></label>
        <p class="small muted" id="ssh-sudo-help" hidden>O sudo é usado só em <code>journalctl -k</code> e <code>dmesg -T</code>, comandos de leitura da lista fixa. Regra mínima de sudoers:
          <code>USUARIO ALL=(root) NOPASSWD: /usr/bin/journalctl -k -q --no-pager -n 1, /usr/bin/journalctl -k -q --no-pager --since=-30d, /usr/bin/dmesg -T</code></p>
        <button type="button" class="btn btn-ghost btn-block" id="btn-ssh">🔐 Testar SSH e detectar hardware</button>
        <div class="test-result" id="ssh-status"></div>
      </div>

      <h2 class="mt">3 · Banco e hardware</h2>
      <label>Database<select name="database" id="db-select" disabled><option value="">— conecte primeiro —</option></select></label>
      <div class="row">
        <label>vCPUs<input name="vcpu" type="number" min="1" value="<?= e($infra['default_vcpu'] ?? '') ?>"></label>
        <label>Clock (GHz)<input name="clock_ghz" inputmode="decimal" value="<?= e($infra['vcpu_clock_ghz'] ?? '') ?>"></label>
        <label>RAM (GB)<input name="ram_gb" inputmode="decimal" value="<?= e($infra['default_ram_gb'] ?? '') ?>"></label>
      </div>
      <div class="row">
        <label class="grow">Disco<select name="disk"><option value="ssd">SSD</option><option value="nvme">NVMe</option><option value="san">SAN/Storage</option><option value="hdd">HDD</option></select></label>
        <label class="check grow"><input type="checkbox" name="dedicated" value="1" checked> Servidor dedicado ao banco</label>
      </div>
      <button type="button" class="btn btn-primary btn-block btn-glow" id="btn-start" disabled>⚡ Iniciar Análise Profunda</button>
    </form>
  </section>

  <section class="card scan-stage">
    <div class="scan-canvas-wrap">
      <canvas id="scan-canvas"<?php if ($watch): ?> data-watch="<?= (int) $watch['id'] ?>" data-engine="<?= e($watch['engine']) ?>"<?php endif; ?>></canvas>
      <div class="scan-overlay" id="scan-overlay">Aguardando conexão…</div>
    </div>
    <div class="run-bar" id="run-bar" hidden data-state="queued">
      <span class="run-orb" aria-hidden="true"></span>
      <div class="run-main">
        <div class="run-top"><strong id="run-title">Análise</strong><span class="run-stage" id="run-stage">Na fila do servidor…</span><span class="run-pct" id="run-pct">0%</span></div>
        <div class="run-track"><i id="run-fill"></i></div>
        <div class="run-hint tiny muted" id="run-hint">Roda no servidor: pode fechar esta página e acompanhar depois aqui ou em Relatórios.</div>
      </div>
      <button type="button" class="btn btn-ghost btn-sm" id="btn-cancel">■ Cancelar</button>
    </div>
    <div class="telemetry">
      <div class="odo"><span class="odo-v" data-odo="tables">0</span><span class="odo-l">tabelas</span></div>
      <div class="odo"><span class="odo-v" data-odo="indexes">0</span><span class="odo-l">índices</span></div>
      <div class="odo"><span class="odo-v" data-odo="fks">0</span><span class="odo-l">FKs</span></div>
      <div class="odo"><span class="odo-v" data-odo="findings">0</span><span class="odo-l">achados</span></div>
      <div class="odo"><span class="odo-v" data-odo="latency">0</span><span class="odo-l">ms latência</span></div>
      <div class="odo"><span class="odo-v" data-odo="score">—</span><span class="odo-l">score</span></div>
    </div>
    <ol class="stages" id="stages">
      <?php foreach ($stages as $k => $label): ?>
        <li data-stage="<?= e($k) ?>"><span class="st-label"><?= e($label) ?></span><span class="st-bar"><i></i></span><span class="st-time"></span></li>
      <?php endforeach; ?>
    </ol>
    <div class="terminal" id="terminal" aria-live="polite"><div class="t-line t-dim">oraculo@analyzer:~$ pronto.</div></div>
  </section>
</div>
