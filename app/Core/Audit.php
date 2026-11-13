<?php
declare(strict_types=1);

namespace App\Core;

final class Audit
{
    public static function log(string $event, string $message = '', string $severity = 'INFO', array $context = [], ?array $user = null): void
    {
        $user ??= Auth::user();
        try {
            Database::insert('audit_logs', [
                'user_id'      => $user['id'] ?? null,
                'username'     => $user['username'] ?? ($context['username'] ?? null),
                'ip'           => PHP_SAPI === 'cli' ? 'cli' : client_ip(),
                'severity'     => $severity,
                'event'        => $event,
                'message'      => mb_substr($message, 0, 2000),
                'context_json' => $context ? json_encode($context, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null,
            ]);
        } catch (\Throwable $e) {
            error_log('[db-analyzer] audit failure: ' . $e->getMessage());
        }
    }
}
