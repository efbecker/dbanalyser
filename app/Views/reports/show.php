<?php
use App\Core\{Markdown, View};
$byCat = fn(array $cats) => array_values(array_filter($findings, fn($f) => in_array($f['category'], $cats, true)));
$sev = array_count_values(array_column($findings, 'severity'));
$score = (int) $a['score'];
$scoreClass = $score >= 80 ? 'good' : ($score >= 50 ? 'warn' : 'bad');
$tables = $m['schemas']['tables'] ?? [];
$verdictClass = ['adequado' => 'good', 'superdimensionado' => 'warn', 'mal tunado' => 'warn', 'subdimensionado' => 'bad'][$tuning['verdict'] ?? ''] ?? 'muted';
$sqlAll = implode("\n\n", array_filter(array_column(array_filter($findings, fn($f) => $f['category'] !== 'os'), 'fix_sql')));
$os = $m['os'] ?? null;
$osp = $os['parsed'] ?? [];
$ctxApp = $m['connect']['app'] ?? null;
$ctxExt = array_diff_key($m['connect']['extensions'] ?? [], ['plpgsql' => 1]);
?>
<?php if ($a['status'] === 'failed'): ?><div class="alert alert-error">Análise falhou: <?= e($a['error']) ?></div><?php endif; ?>
<div class="report-head card">
  <div class="gauge gauge-<?= $scoreClass ?>" style="--score:<?= $score ?>"><svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="52" class="g-bg"/><circle cx="60" cy="60" r="52" class="g-fg" pathLength="100" style="stroke-dasharray:<?= $score ?> 100"/></svg><div class="g-val"><?= $score ?><small>/100</small></div></div>
  <div class="report-meta">
    <h2><span class="engine engine-<?= e($a['engine']) ?>"><?= e($a['engine']) ?></span> <?= e($a['database_name']) ?> <span class="muted">@ <?= e($a['host'] . ':' . $a['port']) ?></span></h2>
    <p class="muted small"><?= e($a['server_version']) ?></p>
    <p class="small">Analisado por <strong><?= e($a['username']) ?></strong> em <?= e($a['started_at']) ?> UTC
      <?php if ($a['ai_model']): ?> · IA: <code><?= e($a['ai_provider'] . ' / ' . $a['ai_model']) ?></code><?php endif; ?></p>
    <div class="sev-row">
      <?php foreach (['critical' => 'Críticos', 'high' => 'Altos', 'medium' => 'Médios', 'low' => 'Baixos', 'info' => 'Informativos'] as $k => $l): ?>
        <span class="sev sev-<?= $k ?>"><?= (int) ($sev[$k] ?? 0) ?> <?= $l ?></span>
      <?php endforeach; ?>
      <span class="verdict verdict-<?= $verdictClass ?>">Dimensionamento: <?= e(mb_strtoupper($tuning['verdict'] ?? 'n/d')) ?></span>
    </div>
    <?php if ($ctxApp || $ctxExt): ?><p class="small muted">
      <?php if ($ctxApp): ?>Aplicação reconhecida: <strong><?= e($ctxApp) ?></strong> (estrutura do fornecedor: achados de schema são informativos e sem script). <?php endif; ?>
      <?php if ($ctxExt): ?>Extensões: <?= e(implode(', ', array_map(fn($k, $v) => "$k $v", array_keys($ctxExt), $ctxExt))) ?>.<?php endif; ?>
    </p><?php endif; ?>
  </div>
  <div class="report-actions">
    <a class="btn btn-ghost btn-sm" href="<?= e(url("/reports/{$a['id']}/export/pdf")) ?>" target="_blank">PDF</a>
    <a class="btn btn-ghost btn-sm" href="<?= e(url("/reports/{$a['id']}/export/html")) ?>">HTML</a>
    <a class="btn btn-ghost btn-sm" href="<?= e(url("/reports/{$a['id']}/export/md")) ?>">Markdown</a>
    <?php if ($prev): ?><a class="btn btn-edit btn-sm" href="<?= e(url("/reports/compare?a={$prev['id']}&b={$a['id']}")) ?>">⇄ Comparar com #<?= (int) $prev['id'] ?></a><?php endif; ?>
    <form method="post" action="<?= e(url("/reports/{$a['id']}/delete")) ?>" class="inline" data-confirm="Excluir este laudo?"><?= csrf_field() ?><button class="btn btn-danger btn-sm">Excluir</button></form>
  </div>
</div>

<div class="tabs" data-tabs>
  <nav class="tab-nav">
    <button data-tab="sum" class="active">Resumo Executivo</button>
    <button data-tab="tables">Tabelas &amp; Relacionamentos</button>
    <button data-tab="idx">Índices</button>
    <button data-tab="q">Queries &amp; Performance</button>
    <button data-tab="tune">Dimensionamento &amp; Tuning</button>
    <button data-tab="os">Sistema Operacional</button>
    <button data-tab="sec">Segurança &amp; Versão<?php $nSec = (int) ($m['vulns']['cve_total'] ?? 0); if ($nSec): ?> <span class="badge"><?= $nSec ?></span><?php endif; ?></button>
    <button data-tab="sql">Scripts SQL</button>
  </nav>

  <section class="card tab-pane active" data-pane="sum">
    <?php if ($a['ai_report_md']): ?>
      <div class="md"><?= Markdown::render(ltrim((string) preg_replace('/\A\s*#\s+[^\n]*\n/', '', $a['ai_report_md']))) ?></div>
    <?php else: ?>
      <p class="muted">Sem laudo de IA (nenhum provedor configurado ou falha na chamada). Achados determinísticos mais relevantes:</p>
      <?= View::partial('reports/_findings', ['list' => array_slice($findings, 0, 15)]) ?>
    <?php endif; ?>
  </section>

  <section class="card tab-pane" data-pane="tables">
    <h3>Achados</h3>
    <?= View::partial('reports/_findings', ['list' => $byCat(['schema', 'bloat', 'types', 'relationships', 'statistics'])]) ?>
    <h3 class="mt">Tabelas (<?= count($tables) ?>)</h3>
    <div class="table-wrap"><table class="table">
      <thead><tr><th>Tabela</th><th class="right">Linhas</th><th class="right">Dados</th><th class="right">Índices</th><th class="right">Dead %</th><th>PK</th><th>Relacionamentos</th></tr></thead>
      <tbody><?php foreach (array_slice($tables, 0, 300) as $t): ?>
        <tr><td><?= e($t['schema'] . '.' . $t['name']) ?></td><td class="right"><?= number_format($t['rows'], 0, ',', '.') ?></td>
        <td class="right"><?= human_bytes($t['data_bytes']) ?></td><td class="right"><?= human_bytes($t['index_bytes']) ?></td>
        <td class="right"><?= isset($t['dead_pct']) ? e($t['dead_pct']) . '%' : '—' ?></td>
        <td><?= $t['has_pk'] ? '<span class="ok">✔</span>' : '<span class="bad">✘</span>' ?></td>
        <td class="small"><?= $t['isolated'] ? '<span class="muted">isolada</span>' : 'conectada' ?></td></tr>
      <?php endforeach; ?></tbody>
    </table></div>
    <h3 class="mt">Chaves estrangeiras (<?= count($m['schemas']['foreign_keys'] ?? []) ?>)</h3>
    <div class="table-wrap"><table class="table"><thead><tr><th>Constraint</th><th>Tabela</th><th>Colunas</th><th>Referencia</th></tr></thead><tbody>
      <?php foreach (array_slice($m['schemas']['foreign_keys'] ?? [], 0, 300) as $fk): ?>
        <tr><td><code><?= e($fk['name']) ?></code></td><td><?= e($fk['table_name']) ?></td><td><?= e($fk['columns']) ?></td><td><?= e($fk['ref_table']) ?></td></tr>
      <?php endforeach; ?></tbody></table></div>
  </section>

  <section class="card tab-pane" data-pane="idx">
    <?= View::partial('reports/_findings', ['list' => $byCat(['indexes'])]) ?>
    <h3 class="mt">Inventário de índices</h3>
    <div class="table-wrap"><table class="table"><thead><tr><th>Tabela</th><th>Índice</th><th class="right">Tamanho</th><th class="right">Scans</th><th>Definição</th></tr></thead><tbody>
      <?php foreach (array_slice($m['indexes']['indexes'] ?? [], 0, 300) as $i): ?>
        <tr><td><?= e($i['table']) ?></td><td><?= e($i['name']) ?><?= $i['primary'] ? ' <span class="badge">PK</span>' : ($i['unique'] ? ' <span class="badge">UQ</span>' : '') ?></td>
        <td class="right"><?= isset($i['bytes']) ? human_bytes($i['bytes']) : '—' ?></td><td class="right"><?= isset($i['scans']) ? number_format($i['scans'], 0, ',', '.') : '—' ?></td>
        <td class="small"><code><?= e(mb_substr($i['def'], 0, 160)) ?></code></td></tr>
      <?php endforeach; ?></tbody></table></div>
  </section>

  <section class="card tab-pane" data-pane="q">
    <?= View::partial('reports/_findings', ['list' => $byCat(['queries', 'locks', 'observability'])]) ?>
    <h3 class="mt">Queries mais custosas</h3>
    <?php if (empty($m['queries']['top_queries'])): ?><p class="muted">Sem dados de pg_stat_statements / performance_schema.</p><?php else: ?>
    <div class="table-wrap"><table class="table"><thead><tr><th>Query</th><th class="right">Chamadas</th><th class="right">Total (ms)</th><th class="right">Média (ms)</th></tr></thead><tbody>
      <?php foreach ($m['queries']['top_queries'] as $q): ?>
        <tr><td><code class="small"><?= e(mb_substr(preg_replace('/\s+/', ' ', (string) $q['query']), 0, 300)) ?></code></td><td class="right"><?= number_format((int) $q['calls'], 0, ',', '.') ?></td>
        <td class="right"><?= e($q['total_ms']) ?></td><td class="right"><?= e($q['mean_ms']) ?></td></tr>
      <?php endforeach; ?></tbody></table></div>
    <?php endif; ?>
    <h3 class="mt">Sessões/transações longas no momento da coleta</h3>
    <?php if (empty($m['queries']['activity'])): ?><p class="muted">Nenhuma.</p><?php else: ?>
      <pre class="code small"><?= e(json_encode($m['queries']['activity'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) ?></pre>
    <?php endif; ?>
  </section>

  <section class="card tab-pane" data-pane="tune">
    <h3>Veredito: <span class="verdict verdict-<?= $verdictClass ?>"><?= e(mb_strtoupper($tuning['verdict'] ?? 'n/d')) ?></span></h3>
    <?php if ($hw): ?><p class="small muted">Hardware <?= ($hw['source'] ?? '') === 'ssh' ? 'detectado via SSH' : 'informado' ?>: <?= e(($hw['vcpu'] ?? '?') . ' vCPU @ ' . ($hw['clock_ghz'] ?? '?') . ' GHz · ' . ($hw['ram_gb'] ?? '?') . ' GB RAM · disco ' . strtoupper($hw['disk'] ?? '?')) ?></p><?php endif; ?>
    <?php if (!empty($hw['disk_note'])): ?><p class="small muted">O tipo de disco acima foi informado no formulário, não detectado: <?= e($hw['disk_note']) ?>.</p><?php endif; ?>
    <?php if (!empty($tuning['reasons'])): ?><ul><?php foreach ($tuning['reasons'] as $r): ?><li><?= e($r) ?></li><?php endforeach; ?></ul><?php endif; ?>
    <?= View::partial('reports/_findings', ['list' => $byCat(['sizing'])]) ?>
    <div class="grid two mt">
      <div>
        <h3>Configuração atual</h3>
        <table class="table"><tbody>
          <?php foreach ($m['sizing']['settings'] ?? [] as $k => $s): ?>
            <tr><td><code><?= e($k) ?></code></td><td class="right"><?= e($s['value'] . (!empty($s['unit']) ? ' ' . $s['unit'] : '')) ?><?= isset($s['bytes']) && $s['bytes'] > 1048576 ? ' <span class="muted small">(' . human_bytes($s['bytes']) . ')</span>' : '' ?></td>
            <td class="small ok"><?= e($tuning['recommended'][$k] ?? '') ?></td></tr>
          <?php endforeach; ?>
        </tbody></table>
        <h3 class="mt">Métricas</h3>
        <table class="table"><tbody>
          <?php foreach ($m['sizing']['stats'] ?? [] as $k => $v): ?><tr><td><code><?= e($k) ?></code></td><td class="right"><?= e(is_scalar($v) ? (string) $v : json_encode($v)) ?></td></tr><?php endforeach; ?>
        </tbody></table>
      </div>
      <div>
        <h3>Configuração recomendada para o hardware</h3>
        <?php if (!empty($tuning['config'])): ?>
          <div class="code-block"><button type="button" class="copy-btn" data-copy>Copiar</button><pre class="code"><code><?= e($tuning['config']) ?></code></pre></div>
        <?php else: ?><p class="muted">Informe vCPU e RAM na próxima análise para gerar o bloco de configuração.</p><?php endif; ?>
      </div>
    </div>
  </section>

  <section class="card tab-pane" data-pane="os">
    <?php if (!$os): ?>
      <p class="muted">Coleta do sistema operacional não habilitada nesta análise. Marque "Coletar via SSH" no analisador para incluir memória, swap, vmstat, OOM, sysctl e disco no laudo.</p>
    <?php elseif (!empty($os['error'])): ?>
      <div class="alert alert-warning">A coleta via SSH em <code><?= e($os['target'] ?? '') ?></code> falhou: <?= e($os['error']) ?></div>
    <?php else: $mem = $osp['mem'] ?? []; $vs = $osp['vmstat'] ?? null; ?>
      <p class="small muted">Coletado via SSH em <code><?= e($os['target']) ?></code> (somente leitura)<?= $os['fingerprint'] ? ' · host key <code>' . e($os['fingerprint']) . '</code>' : '' ?></p>
      <?= View::partial('reports/_findings', ['list' => $byCat(['os'])]) ?>
      <div class="grid two mt">
        <div>
          <h3>Servidor</h3>
          <table class="table"><tbody>
            <?php foreach (array_filter([
              'Sistema' => $osp['distro'] ?? null, 'Kernel' => $osp['kernel'] ?? null, 'Virtualização' => $osp['virtualization'] ?? null,
              'Uptime' => isset($osp['uptime_days']) ? $osp['uptime_days'] . ' dias' : null,
              'CPU' => trim(($osp['vcpu'] ?? '?') . ' vCPU · ' . ($osp['cpu_model'] ?? '')),
              'Load (1/5/15 min)' => isset($osp['load']) ? "{$osp['load']['1m']} / {$osp['load']['5m']} / {$osp['load']['15m']}" : null,
              'vmstat (média)' => $vs ? "us {$vs['us']}% · sy {$vs['sy']}% · wa {$vs['wa']}% · id {$vs['id']}%" . ($vs['st'] !== null ? " · st {$vs['st']}%" : '') . " · si/so {$vs['si']}/{$vs['so']}" : null,
              'Transparent Huge Pages' => isset($osp['thp']['enabled']) ? $osp['thp']['enabled'] . ' (defrag ' . ($osp['thp']['defrag'] ?? '?') . ')' : null,
              'OOM no kernel' => ($osp['oom_access'] ?? true) ? count($osp['oom_events'] ?? []) . ' evento(s)' . (!empty($osp['oom_via_sudo']) ? ' (lido via sudo)' : '') : 'sem permissão para ler' . (($osp['sudo'] ?? null) === 'negado' ? ' (sudo recusado)' : ''),
            ]) as $k => $v): ?><tr><td><?= e($k) ?></td><td class="right"><?= e($v) ?></td></tr><?php endforeach; ?>
          </tbody></table>
          <h3 class="mt">Memória</h3>
          <table class="table"><tbody>
            <?php foreach (['total' => 'Total', 'available' => 'Disponível', 'cached' => 'Cache de páginas', 'shmem' => 'Shared memory', 'dirty' => 'Dirty',
              'swap_total' => 'Swap total', 'swap_used' => 'Swap usada', 'committed_as' => 'Committed_AS', 'commit_limit' => 'CommitLimit', 'anon_hugepages' => 'AnonHugePages'] as $k => $l):
              if (!isset($mem[$k])) continue; ?>
              <tr><td><?= e($l) ?></td><td class="right"><?= human_bytes($mem[$k]) ?><?= $k === 'available' && isset($mem['available_pct']) ? ' <span class="muted small">(' . $mem['available_pct'] . '%)</span>' : '' ?></td></tr>
            <?php endforeach; ?>
            <?php if (isset($mem['hugepages_total'])): ?><tr><td>HugePages (total/livres)</td><td class="right"><?= (int) $mem['hugepages_total'] ?> / <?= (int) $mem['hugepages_free'] ?></td></tr><?php endif; ?>
          </tbody></table>
          <h3 class="mt">sysctl vm.*</h3>
          <table class="table"><tbody>
            <?php foreach ($osp['vm'] ?? [] as $k => $v): ?><tr><td><code>vm.<?= e($k) ?></code></td><td class="right"><?= e((string) $v) ?></td></tr><?php endforeach; ?>
          </tbody></table>
        </div>
        <div>
          <h3>Disco</h3>
          <?php if (!empty($osp['data_dir']['size'])): $dd = $osp['data_dir']; ?>
            <p class="small">Diretório de dados <code><?= e($dd['path']) ?></code> em <code><?= e($dd['mount']) ?></code> (<?= e(($dd['fstype'] ?? '?') . ($dd['mount_options'] ? ', ' . $dd['mount_options'] : '')) ?>):
              <strong><?= (int) $dd['used_pct'] ?>%</strong> usado, <?= human_bytes($dd['avail']) ?> livres de <?= human_bytes($dd['size']) ?>.</p>
          <?php endif; ?>
          <div class="table-wrap"><table class="table"><thead><tr><th>Montagem</th><th class="right">Tamanho</th><th class="right">Uso</th><th class="right">Inodes</th></tr></thead><tbody>
            <?php foreach ($osp['filesystems'] ?? [] as $fs): ?>
              <tr><td><code><?= e($fs['mount']) ?></code> <span class="muted small"><?= e($fs['filesystem']) ?></span></td><td class="right"><?= human_bytes($fs['size']) ?></td>
              <td class="right <?= $fs['used_pct'] >= 90 ? 'bad' : ($fs['used_pct'] >= 80 ? 'warn' : '') ?>"><?= (int) $fs['used_pct'] ?>%</td><td class="right"><?= $fs['inodes_pct'] !== null ? (int) $fs['inodes_pct'] . '%' : '—' ?></td></tr>
            <?php endforeach; ?>
          </tbody></table></div>
          <?php if (!empty($osp['disks'])): ?>
            <table class="table"><thead><tr><th>Dispositivo</th><th>Tipo</th><th class="right">Tamanho</th></tr></thead><tbody>
              <?php foreach ($osp['disks'] as $d): ?><tr><td><?= e($d['name']) ?> <span class="muted small"><?= e((string) $d['model']) ?></span></td><td><?= !empty($d['virtual']) ? 'virtual' . (!empty($d['discard']) ? ' · TRIM' : '') : (str_starts_with($d['name'], 'nvme') ? 'NVMe' : ($d['rotational'] ? 'rotacional' : 'SSD')) ?></td><td class="right"><?= $d['size'] ? human_bytes($d['size']) : '—' ?></td></tr><?php endforeach; ?>
            </tbody></table>
          <?php endif; ?>
          <h3 class="mt">Processos por memória</h3>
          <table class="table"><thead><tr><th>Processo</th><th class="right">RSS</th><th class="right">CPU</th></tr></thead><tbody>
            <?php foreach ($osp['top_processes'] ?? [] as $pr): ?><tr><td><code><?= e($pr['command']) ?></code></td><td class="right"><?= human_bytes($pr['rss']) ?></td><td class="right"><?= e((string) $pr['cpu_pct']) ?>%</td></tr><?php endforeach; ?>
          </tbody></table>
          <?php if (!empty($osp['oom_events'])): ?>
            <h3 class="mt">Eventos de OOM</h3>
            <pre class="code small"><?= e(implode("\n", $osp['oom_events'])) ?></pre>
          <?php endif; ?>
        </div>
      </div>
      <details class="mt"><summary>Saída bruta dos comandos</summary>
        <?php foreach ($os['raw'] ?? [] as $k => $x): ?>
          <h4><?= e(\App\Analyzer\OsCollector::COMMANDS[$k][0] ?? $k) ?> <span class="muted small">rc=<?= (int) $x['rc'] ?></span></h4>
          <pre class="code small"><?= e($x['out']) ?></pre>
        <?php endforeach; ?>
      </details>
    <?php endif; ?>
  </section>

  <section class="card tab-pane" data-pane="sec">
    <?= View::partial('reports/_security', ['v' => $m['vulns'] ?? [], 'list' => $byCat(['security'])]) ?>
  </section>

  <section class="card tab-pane" data-pane="sql">
    <p class="muted small">Scripts gerados automaticamente. Revise, teste em homologação e aplique em janela de manutenção. Nada foi executado no banco analisado.</p>
    <?php if ($sqlAll): ?>
      <div class="code-block"><button type="button" class="copy-btn" data-copy>Copiar tudo</button><pre class="code"><code><?= e("-- Laudo #{$a['id']} · {$a['database_name']}\n\n" . $sqlAll) ?></code></pre></div>
    <?php else: ?><p class="muted">Nenhum script de correção necessário.</p><?php endif; ?>
  </section>
</div>
