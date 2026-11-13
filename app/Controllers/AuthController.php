<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Core\{Audit, Auth, Database, Http, Session, View};

final class AuthController
{
    public function showLogin(): void
    {
        if (Auth::user()) {
            Http::redirect('/');
        }
        View::render('auth/login', ['error' => null, 'username' => ''], 200, '');
    }

    public function login(): void
    {
        $u = Http::str('username');
        $p = (string) (Http::input()['password'] ?? '');
        if ($u === '' || $p === '') {
            View::render('auth/login', ['error' => 'Informe usuário e senha.', 'username' => $u], 422, '');
            return;
        }
        $res = Auth::attempt($u, $p);
        if (!$res['ok']) {
            View::render('auth/login', ['error' => $res['error'], 'username' => $u], 401, '');
            return;
        }
        Http::redirect((int) $res['user']['must_change_password'] === 1 ? '/account/password' : '/');
    }

    public function logout(): void
    {
        Auth::logout();
        Http::redirect('/login');
    }

    public function showPassword(): void
    {
        View::render('auth/password', ['title' => 'Alterar senha']);
    }

    public function changePassword(): void
    {
        $user = Auth::user();
        $current = (string) (Http::input()['current'] ?? '');
        $new = (string) (Http::input()['password'] ?? '');
        $confirm = (string) (Http::input()['confirm'] ?? '');
        $error = match (true) {
            !password_verify($current, $user['password_hash']) => 'Senha atual incorreta.',
            mb_strlen($new) < 10 => 'A nova senha precisa de ao menos 10 caracteres.',
            $new !== $confirm => 'A confirmação não confere.',
            password_verify($new, $user['password_hash']) => 'A nova senha deve ser diferente da atual.',
            default => null,
        };
        if ($error) {
            Session::flash('error', $error);
            Http::redirect('/account/password');
        }
        Database::exec("UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = datetime('now') WHERE id = ?", [Auth::hash($new), $user['id']]);
        session_regenerate_id(true);
        Audit::log('auth.password_changed', 'Senha alterada pelo próprio usuário');
        Session::flash('success', 'Senha alterada com sucesso.');
        Http::redirect('/');
    }
}
