<?php
use App\Core\Markdown;
$accent = brand('report_color', '#00e5ff');
?><!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Laudo #<?= (int) $a['id'] ?> — <?= e($a['database_name']) ?></title>
<style>
body{font:14px/1.55 -apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;color:#1d2330;max-width:960px;margin:32px auto;padding:0 24px}
h1{border-bottom:3px solid <?= e($accent) ?>;padding-bottom:8px}h2{color:#0b0e14;border-left:4px solid <?= e($accent) ?>;padding-left:10px;margin-top:28px}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:12.5px}th,td{border:1px solid #d6dbe4;padding:5px 8px;text-align:left;vertical-align:top}th{background:#f1f4f8}
pre{background:#0b0e14;color:#d7e3f4;padding:12px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap}code{font-family:ui-monospace,Menlo,Consolas,monospace}
blockquote{border-left:3px solid #ccd;margin:0;padding:4px 12px;color:#556}.copy-btn{display:none}.muted{color:#6b7385}
@media print{body{margin:0;max-width:none}h2{break-after:avoid}pre,table{break-inside:avoid}}
</style></head><body>
<?= Markdown::render($md) ?>
<?php if ($autoPrint): ?><script src="<?= e(asset('js/print.js')) ?>"></script><?php endif; ?>
</body></html>
