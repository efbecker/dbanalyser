<?php
declare(strict_types=1);

use App\Core\Csrf;
use App\Core\Settings;

function e(mixed $v): string
{
    return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function url(string $path = '/'): string
{
    return rtrim(App\Core\Config::get('base_path', ''), '/') . $path;
}

function asset(string $path): string
{
    $file = APP_ROOT . '/public/assets/' . ltrim($path, '/');
    $v = is_file($file) ? substr((string) filemtime($file), -6) : APP_VERSION;
    return url('/assets/' . ltrim($path, '/')) . '?v=' . $v;
}

function csrf_field(): string
{
    return '<input type="hidden" name="_csrf" value="' . e(Csrf::token()) . '">';
}

function brand(string $key, string $default = ''): string
{
    return (string) (Settings::get('brand.' . $key) ?? $default);
}

function mask_secret(?string $secret): string
{
    if ($secret === null || $secret === '') {
        return '—';
    }
    $len = mb_strlen($secret);
    if ($len <= 8) {
        return str_repeat('•', $len);
    }
    return mb_substr($secret, 0, 4) . str_repeat('•', 8) . mb_substr($secret, -4);
}

function human_bytes(int|float|null $bytes): string
{
    if ($bytes === null) {
        return '—';
    }
    $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    $i = 0;
    $b = (float) $bytes;
    while ($b >= 1024 && $i < count($units) - 1) {
        $b /= 1024;
        $i++;
    }
    return ($i === 0 ? (string) (int) $b : number_format($b, 1, ',', '.')) . ' ' . $units[$i];
}

function client_ip(): string
{
    // Atrás de proxy reverso, configure trusted_proxy em /etc/db-analyzer/config.php
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $trusted = App\Core\Config::get('trusted_proxy');
    if ($trusted && $ip === $trusted && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
    }
    return $ip;
}

/** Célula "em andamento" de uma análise (anel + etapa + %), atualizada ao vivo pelo app.js. */
function live_progress(array $a): string
{
    $s = App\Analyzer\Runner::summary($a);
    $state = $s['cancelling'] ? 'cancelling' : ($s['queued'] ? 'queued' : 'running');
    $label = $s['cancelling'] ? 'Cancelando' : ($s['queued'] ? 'Na fila' : $s['stage_label']);
    return sprintf(
        '<a class="live" href="%s" data-live-id="%d" data-state="%s" style="--p:%d" title="Acompanhar a análise ao vivo"><span class="live-ring"></span>'
        . '<span class="live-txt"><span>%s</span><b>%d%%</b></span><span class="live-track"><i style="width:%d%%"></i></span></a>',
        e(url('/analyzer?watch=' . $s['id'])), $s['id'], $state, $s['percent'], e($label), $s['percent'], $s['percent']
    );
}
