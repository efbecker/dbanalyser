<?php
declare(strict_types=1);

namespace App\Core;

/**
 * Roteador mínimo. Opções por rota: auth (bool), role ('ADMIN'), csrf (bool, padrão true em POST),
 * session ('write' para APIs que gravam na sessão; as demais liberam o lock da sessão antes do handler).
 */
final class Router
{
    private array $routes = [];

    public function get(string $path, callable|array $handler, array $opts = []): void
    {
        $this->routes[] = ['GET', $path, $handler, $opts];
    }

    public function post(string $path, callable|array $handler, array $opts = []): void
    {
        $this->routes[] = ['POST', $path, $handler, $opts];
    }

    public function dispatch(string $method, string $uri): void
    {
        $path = parse_url($uri, PHP_URL_PATH) ?: '/';
        $base = rtrim((string) Config::get('base_path', ''), '/');
        if ($base !== '' && str_starts_with($path, $base)) {
            $path = substr($path, strlen($base)) ?: '/';
        }
        $path = rtrim($path, '/') ?: '/';

        foreach ($this->routes as [$m, $pattern, $handler, $opts]) {
            $regex = '#^' . preg_replace('#\{(\w+)\}#', '(?P<$1>[^/]+)', $pattern) . '$#';
            if ($m !== $method || !preg_match($regex, $path, $match)) {
                continue;
            }
            $params = array_filter($match, 'is_string', ARRAY_FILTER_USE_KEY);
            $isApi = str_starts_with($path, '/api/');

            if (($opts['auth'] ?? true) && !Auth::user()) {
                $isApi ? Http::json(['error' => 'Sessão expirada'], 401) : Http::redirect('/login');
                return;
            }
            $u = Auth::user();
            if ($u && (int) $u['must_change_password'] === 1 && !($opts['allow_pw_change'] ?? false)) {
                $isApi ? Http::json(['error' => 'Troque sua senha antes de continuar'], 403) : Http::redirect('/account/password');
                return;
            }
            if (isset($opts['role']) && ($u['role'] ?? null) !== $opts['role']) {
                Audit::log('auth.forbidden', "Acesso negado a $path", 'WARNING');
                $isApi ? Http::json(['error' => 'Acesso negado'], 403) : View::render('errors/403', [], 403);
                return;
            }
            if ($method === 'POST' && ($opts['csrf'] ?? true) && !Csrf::check()) {
                $isApi ? Http::json(['error' => 'Token CSRF inválido'], 419) : View::render('errors/403', ['message' => 'Formulário expirado. Recarregue a página.'], 419);
                return;
            }
            // APIs não precisam gravar sessão: libera o lock para que o acompanhamento (polling) não espere
            // outras requisições da mesma sessão. Rotas que gravam na sessão declaram 'session' => 'write'.
            if ($isApi && ($opts['session'] ?? 'read') !== 'write' && session_status() === PHP_SESSION_ACTIVE) {
                session_write_close();
            }
            if (is_array($handler)) {
                [$class, $fn] = $handler;
                (new $class())->$fn(...$params);
            } else {
                $handler(...$params);
            }
            return;
        }
        View::render('errors/404', [], 404);
    }
}
