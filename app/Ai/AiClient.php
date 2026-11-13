<?php
declare(strict_types=1);

namespace App\Ai;

use App\Core\{Config, Crypto, Database};

/**
 * Cliente de IA multi-provedor, só com ext-curl.
 * OpenAI, Groq, DeepSeek e Ollama usam a API compatível com /chat/completions.
 */
final class AiClient
{
    public const PROVIDERS = [
        'openai'    => ['label' => 'OpenAI',             'model' => 'gpt-4.1-mini',             'base' => 'https://api.openai.com/v1',                         'key' => true],
        'anthropic' => ['label' => 'Anthropic Claude',   'model' => 'claude-sonnet-5-5',         'base' => 'https://api.anthropic.com/v1',                      'key' => true],
        'gemini'    => ['label' => 'Google Gemini',      'model' => 'gemini-2.5-flash',          'base' => 'https://generativelanguage.googleapis.com/v1beta',  'key' => true],
        'ollama'    => ['label' => 'Ollama / Local',     'model' => 'llama3.1',                  'base' => 'http://127.0.0.1:11434/v1',                         'key' => false],
        'groq'      => ['label' => 'Groq',               'model' => 'llama-3.3-70b-versatile',   'base' => 'https://api.groq.com/openai/v1',                    'key' => true],
        'deepseek'  => ['label' => 'DeepSeek',           'model' => 'deepseek-chat',             'base' => 'https://api.deepseek.com/v1',                       'key' => true],
    ];

    public function __construct(
        public readonly string $provider,
        public readonly string $model,
        private readonly ?string $apiKey,
        private readonly string $baseUrl,
        private readonly float $temperature = 0.2,
        private readonly int $maxTokens = 4096,
    ) {
    }

    public static function fromProfile(array $p): self
    {
        $def = self::PROVIDERS[$p['provider']] ?? throw new \InvalidArgumentException('Provedor desconhecido');
        return new self(
            $p['provider'],
            trim((string) ($p['model'] ?? '')) ?: $def['model'],
            $p['api_key'] ?? Crypto::decrypt($p['api_key_enc'] ?? null),
            rtrim(trim((string) ($p['base_url'] ?? '')) ?: $def['base'], '/'),
            (float) ($p['temperature'] ?? 0.2),
            (int) ($p['max_tokens'] ?? 4096),
        );
    }

    /** Perfil efetivo do usuário: perfil vinculado ou IA padrão global. */
    public static function forUser(?array $user): ?self
    {
        $p = null;
        if (!empty($user['ai_profile_id'])) {
            $p = Database::one('SELECT * FROM ai_profiles WHERE id = ?', [$user['ai_profile_id']]);
        }
        $p ??= Database::one('SELECT * FROM ai_profiles WHERE is_global = 1');
        return $p ? self::fromProfile($p) : null;
    }

    /**
     * @return array{text:string, tokens_in:int, tokens_out:int, latency_ms:int}
     */
    public function chat(string $system, string $user): array
    {
        $t0 = microtime(true);
        $res = match ($this->provider) {
            'anthropic' => $this->anthropic($system, $user),
            'gemini'    => $this->gemini($system, $user),
            default     => $this->openaiCompatible($system, $user),
        };
        $res['latency_ms'] = (int) ((microtime(true) - $t0) * 1000);
        return $res;
    }

    private function openaiCompatible(string $system, string $user): array
    {
        $headers = ['Content-Type: application/json'];
        if ($this->apiKey) {
            $headers[] = 'Authorization: Bearer ' . $this->apiKey;
        }
        $body = [
            'model'       => $this->model,
            'messages'    => [['role' => 'system', 'content' => $system], ['role' => 'user', 'content' => $user]],
            'temperature' => $this->temperature,
            'max_tokens'  => $this->maxTokens,
        ];
        $j = $this->post($this->baseUrl . '/chat/completions', $body, $headers);
        return [
            'text'       => (string) ($j['choices'][0]['message']['content'] ?? ''),
            'tokens_in'  => (int) ($j['usage']['prompt_tokens'] ?? 0),
            'tokens_out' => (int) ($j['usage']['completion_tokens'] ?? 0),
        ];
    }

    private function anthropic(string $system, string $user): array
    {
        $j = $this->post($this->baseUrl . '/messages', [
            'model'       => $this->model,
            'system'      => $system,
            'max_tokens'  => $this->maxTokens,
            'temperature' => $this->temperature,
            'messages'    => [['role' => 'user', 'content' => $user]],
        ], [
            'Content-Type: application/json',
            'x-api-key: ' . $this->apiKey,
            'anthropic-version: 2023-06-01',
        ]);
        $text = '';
        foreach ($j['content'] ?? [] as $block) {
            if (($block['type'] ?? '') === 'text') {
                $text .= $block['text'];
            }
        }
        return ['text' => $text, 'tokens_in' => (int) ($j['usage']['input_tokens'] ?? 0), 'tokens_out' => (int) ($j['usage']['output_tokens'] ?? 0)];
    }

    private function gemini(string $system, string $user): array
    {
        $url = $this->baseUrl . '/models/' . rawurlencode($this->model) . ':generateContent';
        $j = $this->post($url, [
            'systemInstruction' => ['parts' => [['text' => $system]]],
            'contents'          => [['role' => 'user', 'parts' => [['text' => $user]]]],
            'generationConfig'  => ['temperature' => $this->temperature, 'maxOutputTokens' => $this->maxTokens],
        ], ['Content-Type: application/json', 'x-goog-api-key: ' . $this->apiKey]);
        $text = '';
        foreach ($j['candidates'][0]['content']['parts'] ?? [] as $part) {
            $text .= $part['text'] ?? '';
        }
        return [
            'text'       => $text,
            'tokens_in'  => (int) ($j['usageMetadata']['promptTokenCount'] ?? 0),
            'tokens_out' => (int) ($j['usageMetadata']['candidatesTokenCount'] ?? 0),
        ];
    }

    private function post(string $url, array $body, array $headers): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($body, JSON_UNESCAPED_UNICODE),
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => (int) Config::get('ai_timeout', 120),
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        ]);
        $raw = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($raw === false) {
            throw new \RuntimeException('Falha de rede ao contatar a IA: ' . $err);
        }
        $j = json_decode((string) $raw, true);
        if ($code >= 400 || !is_array($j)) {
            $msg = $j['error']['message'] ?? (is_string($j['error'] ?? null) ? $j['error'] : mb_substr((string) $raw, 0, 300));
            throw new \RuntimeException("IA respondeu HTTP $code: $msg");
        }
        return $j;
    }
}
