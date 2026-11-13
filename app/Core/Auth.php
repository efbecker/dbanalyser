<?php
declare(strict_types=1);

namespace App\Core;

final class Auth
{
    private static ?array $user = null;
    private static bool $loaded = false;

    public static function hash(string $password): string
    {
        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        return password_hash($password, $algo);
    }

    public static function user(): ?array
    {
        if (!self::$loaded) {
            self::$loaded = true;
            $id = $_SESSION['uid'] ?? null;
            if ($id) {
                self::$user = Database::one('SELECT * FROM users WHERE id = ? AND is_active = 1', [$id]);
                if (!self::$user) {
                    unset($_SESSION['uid']);
                }
            }
        }
        return self::$user;
    }

    public static function isAdmin(): bool
    {
        return (self::user()['role'] ?? null) === 'ADMIN';
    }

    /** Retorna segundos de bloqueio restantes (0 = liberado). */
    public static function lockoutSeconds(string $username, string $ip): int
    {
        $max = (int) Config::get('login_max_attempts', 5);
        $win = (int) Config::get('login_window_min', 15);
        $since = gmdate('Y-m-d H:i:s', time() - $win * 60);
        // Falhas desde o último sucesso, por usuário+IP e (mais folgado) por IP
        $byUser = (int) Database::value(
            'SELECT COUNT(*) FROM login_attempts WHERE username = ? AND ip = ? AND success = 0 AND created_at >= ?
               AND created_at > COALESCE((SELECT MAX(created_at) FROM login_attempts WHERE username = ? AND ip = ? AND success = 1), \'\')',
            [mb_strtolower($username), $ip, $since, mb_strtolower($username), $ip]
        );
        $byIp = (int) Database::value(
            'SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND success = 0 AND created_at >= ?',
            [$ip, $since]
        );
        if ($byUser < $max && $byIp < $max * 4) {
            return 0;
        }
        $last = Database::value('SELECT MAX(created_at) FROM login_attempts WHERE ip = ? AND success = 0', [$ip]);
        $until = strtotime($last . ' UTC') + $win * 60;
        return max(0, $until - time());
    }

    public static function attempt(string $username, string $password): array
    {
        $ip = client_ip();
        $lock = self::lockoutSeconds($username, $ip);
        if ($lock > 0) {
            Audit::log('auth.locked', "Login bloqueado para '$username'", 'WARNING', ['username' => $username]);
            return ['ok' => false, 'error' => 'Muitas tentativas. Tente novamente em ' . ceil($lock / 60) . ' min.'];
        }
        $user = Database::one('SELECT * FROM users WHERE username = ?', [$username]);
        // Verifica hash mesmo sem usuário (tempo constante aproximado)
        $hash = $user['password_hash'] ?? '$2y$10$usesomesillystringforsaltuJ1x0D8rLwQ8n1dS2Yb9h5zq3QnFe';
        $valid = password_verify($password, $hash) && $user && (int) $user['is_active'] === 1;

        Database::insert('login_attempts', ['username' => mb_strtolower($username), 'ip' => $ip, 'success' => $valid ? 1 : 0]);

        if (!$valid) {
            Audit::log('auth.failed', "Falha de autenticação para '$username'", 'WARNING', ['username' => $username]);
            usleep(random_int(200000, 600000));
            return ['ok' => false, 'error' => 'Usuário ou senha inválidos.'];
        }

        if (password_needs_rehash($user['password_hash'], defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT)) {
            Database::exec('UPDATE users SET password_hash = ? WHERE id = ?', [self::hash($password), $user['id']]);
        }
        session_regenerate_id(true);
        $_SESSION = ['uid' => (int) $user['id'], '_last' => time()];
        Database::exec("UPDATE users SET last_login_at = datetime('now'), last_login_ip = ? WHERE id = ?", [$ip, $user['id']]);
        self::$loaded = false;
        Audit::log('auth.login', 'Login realizado', 'INFO', [], $user);
        // Limpeza oportunista
        Database::exec("DELETE FROM login_attempts WHERE created_at < datetime('now', '-30 days')");
        return ['ok' => true, 'user' => $user];
    }

    public static function logout(): void
    {
        Audit::log('auth.logout', 'Logout');
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
        }
        session_destroy();
        self::$user = null;
    }
}
