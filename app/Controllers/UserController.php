<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Core\{Audit, Auth, Database, Http, Session, View};

final class UserController
{
    public function index(): void
    {
        $edit = isset($_GET['edit']) ? Database::one('SELECT * FROM users WHERE id = ?', [(int) $_GET['edit']]) : null;
        $profiles = Database::all('SELECT id, name, provider FROM ai_profiles WHERE is_global = 0 ORDER BY name');
        View::render('admin/users', ['title' => 'Usuários', 'edit' => $edit, 'profiles' => $profiles]);
    }

    /** GET /api/users?q=&page= — busca em tempo real com paginação */
    public function search(): void
    {
        $q = trim((string) ($_GET['q'] ?? ''));
        $page = max(1, (int) ($_GET['page'] ?? 1));
        $per = 10;
        $where = '1=1';
        $params = [];
        if ($q !== '') {
            $where = '(u.username LIKE :q OR u.display_name LIKE :q OR u.email LIKE :q OR u.role LIKE :q)';
            $params['q'] = '%' . $q . '%';
        }
        $total = (int) Database::value("SELECT COUNT(*) FROM users u WHERE $where", $params);
        $rows = Database::all("SELECT u.id, u.username, u.display_name, u.email, u.role, u.is_active, u.last_login_at, u.created_at,
                                      COALESCE(p.name, 'IA padrão do sistema') AS ai_profile
                                 FROM users u LEFT JOIN ai_profiles p ON p.id = u.ai_profile_id
                                WHERE $where ORDER BY u.username LIMIT $per OFFSET " . (($page - 1) * $per), $params);
        Http::json(['rows' => $rows, 'total' => $total, 'page' => $page, 'pages' => max(1, (int) ceil($total / $per)), 'me' => (int) Auth::user()['id']]);
    }

    public function save(): void
    {
        $id = (int) Http::str('id');
        $username = Http::str('username');
        $password = (string) (Http::input()['password'] ?? '');
        $role = Http::str('role') === 'ADMIN' ? 'ADMIN' : 'CLIENT';
        $profileId = (int) Http::str('ai_profile_id') ?: null;
        $back = '/admin/users' . ($id ? "?edit=$id" : '');

        if (!preg_match('/^[A-Za-z0-9._@-]{3,64}$/', $username)) {
            Session::flash('error', 'Login deve ter 3 a 64 caracteres (letras, números, . _ @ -).');
            Http::redirect($back);
        }
        if ((!$id || $password !== '') && mb_strlen($password) < 10) {
            Session::flash('error', 'A senha precisa de ao menos 10 caracteres.');
            Http::redirect($back);
        }
        if ($profileId && !Database::value('SELECT 1 FROM ai_profiles WHERE id = ? AND is_global = 0', [$profileId])) {
            $profileId = null;
        }
        $infra = array_filter([
            'monitoring_url' => Http::str('monitoring_url'),
            'monitoring_type' => Http::str('monitoring_type'),
            'vcpu_clock_ghz' => Http::str('vcpu_clock_ghz') !== '' ? (float) str_replace(',', '.', Http::str('vcpu_clock_ghz')) : null,
            'default_vcpu' => Http::str('default_vcpu') !== '' ? (int) Http::str('default_vcpu') : null,
            'default_ram_gb' => Http::str('default_ram_gb') !== '' ? (float) str_replace(',', '.', Http::str('default_ram_gb')) : null,
            'notes' => Http::str('notes'),
        ], fn($v) => $v !== null && $v !== '');

        $data = [
            'username' => $username, 'role' => $role, 'ai_profile_id' => $profileId,
            'display_name' => Http::str('display_name') ?: null, 'email' => Http::str('email') ?: null,
            'infra_json' => $infra ? json_encode($infra, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null,
            'is_active' => Http::str('is_active', '1') === '1' ? 1 : 0,
        ];
        $me = Auth::user();
        if ($id === (int) $me['id'] && ($role !== 'ADMIN' || !$data['is_active'])) {
            Session::flash('error', 'Você não pode remover seu próprio acesso de administrador.');
            Http::redirect($back);
        }
        if ($password !== '') {
            $data['password_hash'] = Auth::hash($password);
            $data['must_change_password'] = Http::str('force_change') === '1' ? 1 : 0;
        }
        try {
            if ($id) {
                Database::update('users', $data + ['updated_at' => gmdate('Y-m-d H:i:s')], 'id = :id', ['id' => $id]);
                Audit::log('user.updated', "Conta '$username' atualizada" . ($password !== '' ? ' (senha redefinida)' : ''), 'INFO', ['role' => $role]);
            } else {
                Database::insert('users', $data);
                Audit::log('user.created', "Conta '$username' criada", 'INFO', ['role' => $role]);
            }
            Session::flash('success', "Conta '$username' salva.");
            Http::redirect('/admin/users');
        } catch (\PDOException) {
            Session::flash('error', "O login '$username' já está em uso.");
            Http::redirect($back);
        }
    }

    public function delete(string $id): void
    {
        $id = (int) $id;
        if ($id === (int) Auth::user()['id']) {
            Session::flash('error', 'Você não pode excluir a própria conta.');
            Http::redirect('/admin/users');
        }
        $u = Database::one('SELECT username, role FROM users WHERE id = ?', [$id]);
        if ($u && $u['role'] === 'ADMIN' && (int) Database::value("SELECT COUNT(*) FROM users WHERE role = 'ADMIN' AND is_active = 1") <= 1) {
            Session::flash('error', 'Não é possível excluir o último administrador.');
            Http::redirect('/admin/users');
        }
        if ($u) {
            Database::exec('DELETE FROM users WHERE id = ?', [$id]);
            Audit::log('user.deleted', "Conta '{$u['username']}' excluída", 'WARNING');
            Session::flash('success', "Conta '{$u['username']}' excluída.");
        }
        Http::redirect('/admin/users');
    }
}
