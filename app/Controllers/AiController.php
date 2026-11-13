<?php
declare(strict_types=1);

namespace App\Controllers;

use App\Ai\AiClient;
use App\Core\{Audit, Crypto, Database, Http, Session, View};

final class AiController
{
    public function index(): void
    {
        $global = Database::one('SELECT * FROM ai_profiles WHERE is_global = 1');
        $profiles = Database::all('SELECT p.*, (SELECT COUNT(*) FROM users u WHERE u.ai_profile_id = p.id) AS users FROM ai_profiles p WHERE is_global = 0 ORDER BY name');
        foreach ($profiles as &$p) {
            $p['api_key_masked'] = mask_secret(Crypto::decrypt($p['api_key_enc']));
        }
        unset($p);
        $edit = isset($_GET['edit']) ? Database::one('SELECT * FROM ai_profiles WHERE id = ? AND is_global = 0', [(int) $_GET['edit']]) : null;
        View::render('admin/ai', [
            'title' => 'Inteligência Artificial', 'providers' => AiClient::PROVIDERS, 'global' => $global,
            'globalMasked' => $global ? mask_secret(Crypto::decrypt($global['api_key_enc'])) : '', 'profiles' => $profiles, 'edit' => $edit,
        ]);
    }

    private function validated(): array
    {
        $provider = Http::str('provider');
        if (!isset(AiClient::PROVIDERS[$provider])) {
            throw new \InvalidArgumentException('Provedor inválido.');
        }
        $base = Http::str('base_url');
        if ($base !== '' && !preg_match('#^https?://#i', $base)) {
            throw new \InvalidArgumentException('Base URL deve começar com http:// ou https://');
        }
        return [
            'provider' => $provider, 'model' => Http::str('model') ?: null, 'base_url' => $base ?: null,
            'temperature' => max(0, min(1.5, (float) Http::str('temperature', '0.2'))),
            'max_tokens' => max(256, min(64000, (int) Http::str('max_tokens', '16000'))),
        ];
    }

    public function saveGlobal(): void
    {
        try {
            $data = $this->validated() + ['name' => '__GLOBAL__', 'is_global' => 1];
        } catch (\InvalidArgumentException $e) {
            Session::flash('error', $e->getMessage());
            Http::redirect('/admin/ai');
        }
        $key = Http::str('api_key');
        $existing = Database::one('SELECT id FROM ai_profiles WHERE is_global = 1');
        if ($key !== '') {
            $data['api_key_enc'] = Crypto::encrypt($key);
        }
        if ($existing) {
            Database::update('ai_profiles', $data + ['updated_at' => gmdate('Y-m-d H:i:s')], 'id = :id', ['id' => $existing['id']]);
        } else {
            Database::insert('ai_profiles', $data);
        }
        Audit::log('ai.global_updated', "IA padrão alterada para {$data['provider']}" . ($data['model'] ? " / {$data['model']}" : ''), 'INFO', ['key_changed' => $key !== '']);
        Session::flash('success', 'IA padrão global salva e aplicada.');
        Http::redirect('/admin/ai');
    }

    public function saveProfile(): void
    {
        $id = (int) Http::str('id');
        $name = Http::str('name');
        try {
            if ($name === '' || $name === '__GLOBAL__') {
                throw new \InvalidArgumentException('Informe um nome de perfil válido.');
            }
            $data = $this->validated() + ['name' => $name];
        } catch (\InvalidArgumentException $e) {
            Session::flash('error', $e->getMessage());
            Http::redirect('/admin/ai' . ($id ? "?edit=$id" : ''));
        }
        $key = Http::str('api_key');
        if ($key !== '') {
            $data['api_key_enc'] = Crypto::encrypt($key);
        }
        try {
            if ($id) {
                Database::update('ai_profiles', $data + ['updated_at' => gmdate('Y-m-d H:i:s')], 'id = :id AND is_global = 0', ['id' => $id]);
                Audit::log('ai.profile_updated', "Perfil de IA '$name' atualizado");
            } else {
                Database::insert('ai_profiles', $data);
                Audit::log('ai.profile_created', "Perfil de IA '$name' criado");
            }
            Session::flash('success', "Perfil '$name' salvo.");
        } catch (\PDOException) {
            Session::flash('error', "Já existe um perfil chamado '$name'.");
        }
        Http::redirect('/admin/ai');
    }

    public function deleteProfile(string $id): void
    {
        $p = Database::one('SELECT name FROM ai_profiles WHERE id = ? AND is_global = 0', [(int) $id]);
        if ($p) {
            Database::exec('DELETE FROM ai_profiles WHERE id = ?', [(int) $id]);
            Audit::log('ai.profile_deleted', "Perfil de IA '{$p['name']}' excluído", 'WARNING');
            Session::flash('success', "Perfil '{$p['name']}' excluído. Usuários vinculados voltaram para a IA padrão.");
        }
        Http::redirect('/admin/ai');
    }

    public function test(): void
    {
        $in = Http::input();
        $provider = (string) ($in['provider'] ?? '');
        if (!isset(AiClient::PROVIDERS[$provider])) {
            Http::json(['ok' => false, 'error' => 'Provedor inválido'], 422);
            return;
        }
        $key = trim((string) ($in['api_key'] ?? ''));
        if ($key === '') {
            // Reaproveita a chave já salva (perfil em edição ou global)
            $row = !empty($in['id'])
                ? Database::one('SELECT api_key_enc FROM ai_profiles WHERE id = ?', [(int) $in['id']])
                : (!empty($in['global']) ? Database::one('SELECT api_key_enc FROM ai_profiles WHERE is_global = 1') : null);
            $key = (string) Crypto::decrypt($row['api_key_enc'] ?? null);
        }
        try {
            $client = AiClient::fromProfile(['provider' => $provider, 'model' => $in['model'] ?? '', 'api_key' => $key, 'base_url' => $in['base_url'] ?? '', 'max_tokens' => 1024]);
            $r = $client->chat('Responda apenas com: OK', 'Teste de conectividade do DB Oráculo Analyzer.');
            Audit::log('ai.test', "Teste de IA OK ($provider / {$client->model})", 'INFO', ['latency_ms' => $r['latency_ms']]);
            Http::json(['ok' => true, 'model' => $client->model, 'latency_ms' => $r['latency_ms'], 'reply' => mb_substr(trim($r['text']), 0, 120)]);
        } catch (\Throwable $e) {
            Audit::log('ai.test_failed', "Teste de IA falhou ($provider): " . $e->getMessage(), 'WARNING');
            Http::json(['ok' => false, 'error' => $e->getMessage()]);
        }
    }
}
