<?php
declare(strict_types=1);

namespace App\Core;

final class View
{
    public static function render(string $view, array $data = [], int $status = 200, string $layout = 'layout'): void
    {
        http_response_code($status);
        if ($status >= 400) {
            $data['title'] ??= 'Erro ' . $status;
        }
        $content = self::partial($view, $data);
        if ($layout === '') {
            echo $content;
            return;
        }
        echo self::partial($layout, $data + ['content' => $content, 'flash' => Session::pullFlash()]);
    }

    public static function partial(string $view, array $data = []): string
    {
        $file = APP_ROOT . '/app/Views/' . $view . '.php';
        if (!is_file($file)) {
            throw new \RuntimeException("View não encontrada: $view");
        }
        extract($data, EXTR_SKIP);
        $user = Auth::user();
        ob_start();
        require $file;
        return (string) ob_get_clean();
    }
}
