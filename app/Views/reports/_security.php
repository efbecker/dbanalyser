<?php
/** Aba "Segurança & Versão": CVEs conhecidos e ciclo de vida da versão do SGBD. @var array $v @var array $list */
use App\Core\View;

$v = $v ? \App\Analyzer\VulnCheck::localizeStored($v) : $v;
$sevLabel = ['critical' => 'CRÍTICO', 'high' => 'ALTO', 'medium' => 'MÉDIO', 'low' => 'BAIXO', 'unknown' => 'N/D'];
$life = $v['lifecycle'] ?? [];
$statusTxt = [
    'supported' => ['good', 'Com suporte'], 'security' => ['warn', 'Só correções de segurança'],
    'extended' => ['warn', 'Suporte estendido (pago)'], 'eol' => ['bad', 'Sem suporte (EOL)'], 'unknown' => ['muted', 'Desconhecido'],
][$life['status'] ?? 'unknown'] ?? ['muted', '—'];
?>
<?php if (!$v): ?>
  <p class="muted">Este laudo foi gerado antes da checagem de vulnerabilidades. Rode uma nova análise para ver CVEs e ciclo de vida da versão.</p>
<?php elseif (($v['status'] ?? '') !== 'ok'): ?>
  <p class="muted"><?= e(match ($v['status'] ?? '') {
      'no_db' => 'Base de vulnerabilidades ausente no servidor do analisador. Rode: php bin/console vulndb:update',
      'unsupported_engine' => 'Ainda não há dados de vulnerabilidade para este motor.',
      'unknown_version' => 'Não foi possível identificar a versão do servidor: ' . ($v['version_string'] ?? ''),
      default => 'Checagem indisponível: ' . ($v['error'] ?? ''),
  }) ?></p>
<?php else: ?>
  <div class="table-wrap"><table class="table"><tbody>
    <tr><td>Versão em uso</td><td><strong><?= e(($v['product'] ?? '') . ' ' . $v['version']) ?></strong></td></tr>
    <tr><td>Ciclo</td><td><?= e($v['cycle_name'] ?: ($v['cycle'] ?? '?')) ?><?= !empty($life['lts']) ? ' <span class="badge">LTS</span>' : '' ?>
      · <span class="verdict verdict-<?= $statusTxt[0] ?>"><?= e($statusTxt[1]) ?></span>
      <?php if (!empty($life['eol'])): ?><span class="small muted"> · fim do suporte: <?= e($life['eol']) ?><?= !empty($life['eoes']) ? ' (estendido até ' . e($life['eoes']) . ')' : '' ?></span><?php endif; ?></td></tr>
    <tr><td>Última versão do ciclo</td><td><?= e($v['latest'] ?? 'n/d') ?><?php if ($v['behind']): ?> <span class="small muted">(<?= e(\App\Analyzer\VulnCheck::behindTxt((int) $v['behind'])) ?>)</span><?php endif; ?></td></tr>
    <tr><td>Atualizar para</td><td><?= $v['target'] ? '<strong class="ok">' . e($v['target']) . '</strong> <span class="small muted">mesmo major: troca de binário, sem dump/restore</span>' : '<span class="ok">✔ já está na última versão conhecida do ciclo</span>' ?></td></tr>
    <?php if (in_array($life['status'] ?? '', ['eol', 'extended'], true) && $v['supported_cycles']): ?>
      <tr><td>Ciclos suportados</td><td><?= e(implode(' · ', $v['supported_cycles'])) ?></td></tr>
    <?php endif; ?>
    <tr><td>CVEs conhecidos</td><td><?php if ($v['oracle_ru_unknown']): ?><span class="muted">não verificados: o servidor informou só a release base (sem RU)</span><?php else: ?>
      <strong><?= (int) $v['cve_total'] ?></strong>
      <?php foreach (['critical' => 'críticos', 'high' => 'altos', 'medium' => 'médios', 'low' => 'baixos'] as $k => $l): if (!empty($v['cve_by_sev'][$k])): ?>
        <span class="sev sev-<?= $k ?>"><?= (int) $v['cve_by_sev'][$k] ?> <?= $l ?></span>
      <?php endif; endforeach; ?>
      <?php if (!empty($v['kev'])): ?><span class="sev sev-critical"><?= count($v['kev']) ?> com exploração ativa (CISA KEV)</span><?php endif; ?>
    <?php endif; ?></td></tr>
  </tbody></table></div>

  <?= View::partial('reports/_findings', ['list' => $list]) ?>

  <?php if (!empty($v['cves'])): ?>
    <h3 class="mt">Vulnerabilidades que afetam <?= e($v['version']) ?></h3>
    <div class="table-wrap"><table class="table">
      <thead><tr><th>CVE</th><th>Severidade</th><th class="right">CVSS</th><th>Corrigido em</th><th>Descrição</th></tr></thead>
      <tbody><?php foreach ($v['cves'] as $c): ?>
        <tr><td class="nowrap"><a href="https://nvd.nist.gov/vuln/detail/<?= e($c['id']) ?>" target="_blank" rel="noopener noreferrer"><?= e($c['id']) ?></a><?= !empty($c['kev']) ? ' <span class="badge">KEV</span>' : '' ?><div class="small muted"><?= e($c['pub']) ?></div></td>
        <td><span class="sev sev-<?= e($c['sev']) ?>"><?= e($sevLabel[$c['sev']] ?? $c['sev']) ?></span></td>
        <td class="right"><?= $c['cvss'] !== null ? e((string) $c['cvss']) : '—' ?></td>
        <td><?= e($c['fixed_in'] ?? '—') ?></td>
        <td class="small"><?= e($c['summary']) ?></td></tr>
      <?php endforeach; ?></tbody>
    </table></div>
    <?php if ($v['cve_total'] > count($v['cves'])): ?><p class="small muted">Exibindo <?= count($v['cves']) ?> de <?= (int) $v['cve_total'] ?>.</p><?php endif; ?>
  <?php endif; ?>

  <?php if (!empty($v['extensions'])): ?>
    <h3 class="mt">Extensões verificadas</h3>
    <table class="table"><thead><tr><th>Extensão</th><th>Versão</th><th>CVEs</th></tr></thead><tbody>
      <?php foreach ($v['extensions'] as $name => $x): ?>
        <tr><td><code><?= e($name) ?></code></td><td><?= e($x['version']) ?></td>
        <td><?= $x['cves'] ? implode(', ', array_map(fn($c) => '<a href="https://nvd.nist.gov/vuln/detail/' . e($c['id']) . '" target="_blank" rel="noopener noreferrer">' . e($c['id']) . '</a>', $x['cves'])) : '<span class="ok">✔ nenhum</span>' ?></td></tr>
      <?php endforeach; ?>
    </tbody></table>
  <?php endif; ?>

  <p class="small muted mt">Base offline de <?= e(substr((string) ($v['db']['nvd_feed_at'] ?? $v['db']['generated_at'] ?? ''), 0, 10)) ?>
    (NVD + avisos dos fabricantes; ciclo de vida: endoflife.date). Compara a versão informada pelo servidor: pacotes de distribuição com
    correções retroportadas (ex.: RHEL) podem aparecer como vulneráveis sem estar. Atualize a base com <code>php bin/console vulndb:update</code>.</p>
<?php endif; ?>
