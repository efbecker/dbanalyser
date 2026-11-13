<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Core\{Audit, Config, Http, Session, Settings, View};

final class BrandingController
{
    private const MIME = ['image/png' => 'png', 'image/jpeg' => 'jpg', 'image/webp' => 'webp', 'image/svg+xml' => 'svg'];

    public function index(): void
    {
        View::render('admin/branding', ['title' => 'Branding']);
    }

    public function save(): void
    {
        $hex = fn(string $v, string $d) => preg_match('/^#[0-9a-fA-F]{6}$/', $v) ? strtolower($v) : $d;
        Settings::set('brand.name', mb_substr(Http::str('name') ?: 'DB Oráculo Analyzer', 0, 60));
        Settings::set('brand.short', mb_substr(Http::str('short') ?: 'ORÁCULO', 0, 16));
        Settings::set('brand.accent', $hex(Http::str('accent'), '#00e5ff'));
        Settings::set('brand.report_color', $hex(Http::str('report_color'), '#00e5ff'));
        Settings::set('brand.footer', mb_substr(Http::str('footer'), 0, 300));

        if (!empty($_FILES['logo']['tmp_name']) && is_uploaded_file($_FILES['logo']['tmp_name'])) {
            $f = $_FILES['logo'];
            $mime = (new \finfo(FILEINFO_MIME_TYPE))->file($f['tmp_name']);
            if ($mime === 'text/xml' || $mime === 'text/plain') {
                $mime = str_contains((string) file_get_contents($f['tmp_name'], false, null, 0, 1024), '<svg') ? 'image/svg+xml' : $mime;
            }
            if (!isset(self::MIME[$mime]) || $f['size'] > 512 * 1024) {
                Session::flash('error', 'Logo deve ser PNG, JPG, WEBP ou SVG com até 512 KB.');
                Http::redirect('/admin/branding');
            }
            $dir = Config::dataDir() . '/uploads';
            @mkdir($dir, 0750, true);
            foreach (glob("$dir/logo.*") ?: [] as $old) {
                @unlink($old);
            }
            $name = 'logo.' . self::MIME[$mime];
            move_uploaded_file($f['tmp_name'], "$dir/$name");
            Settings::set('brand.logo', $name);
        } elseif (Http::str('remove_logo') === '1') {
            foreach (glob(Config::dataDir() . '/uploads/logo.*') ?: [] as $old) {
                @unlink($old);
            }
            Settings::set('brand.logo', '');
        }
        Audit::log('branding.updated', 'Branding atualizado');
        Session::flash('success', 'Branding atualizado.');
        Http::redirect('/admin/branding');
    }

    /** Serve o logo enviado (armazenado fora da raiz pública). */
    public function logo(): void
    {
        $name = Settings::get('brand.logo');
        $file = $name ? Config::dataDir() . '/uploads/' . basename($name) : null;
        if (!$file || !is_file($file)) {
            header('Location: ' . asset('img/logo.svg'));
            return;
        }
        $mime = array_search(pathinfo($file, PATHINFO_EXTENSION), self::MIME, true) ?: 'application/octet-stream';
        header('Content-Type: ' . $mime);
        header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox");
        header('Cache-Control: public, max-age=300');
        readfile($file);
    }
}
