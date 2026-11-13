# DB Oráculo Analyzer

Plataforma web de diagnóstico, auditoria, tuning e análise inteligente de bancos **PostgreSQL, MySQL e MariaDB** com IA.
White-label, dark mode enterprise, coleta 100% somente leitura e laudo técnico com score de 0 a 100.

## Instalação (Debian 13+)

```bash
curl -sSL https://raw.githubusercontent.com/efbecker/dbanalyser/main/install.sh | sudo bash
```

Com domínio público e certificado Let's Encrypt:

```bash
curl -sSL https://raw.githubusercontent.com/efbecker/dbanalyser/main/install.sh | sudo DOMAIN=db.exemplo.com LE_EMAIL=ops@exemplo.com bash
```

O script é idempotente: rodar de novo atualiza o código (`git reset --hard origin/main`), aplica migrations e
reconfigura o Apache, preservando config, dados e usuários.

### Senha inicial do admin

Na primeira instalação o usuário `admin` é criado com uma **senha aleatória**, exibida no fim da instalação e salva em
`/root/db-analyzer-admin.txt` (chmod 600). A troca é obrigatória no primeiro login. Para definir a senha você mesmo,
passe `ADMIN_PASSWORD='...'` ao instalador. Para redefinir depois:

```bash
sudo -u www-data php /var/www/db-analyzer/bin/console user:password admin
```

## Stack e decisões

| Camada | Escolha | Por quê |
|---|---|---|
| Backend | PHP 8.4 (Debian 13) via **php-fpm** + `mpm_event` | Pacotes nativos do Debian, zero Composer, zero build; atualização via `apt` |
| Drivers | PDO `pdo_pgsql`, `pdo_mysql`, `pdo_sqlite`; `curl`; `sodium` | Tudo em `apt`, sem binários proprietários |
| Banco interno | SQLite 3 (WAL) em `/var/lib/db-analyzer` | Fora do DocumentRoot, portátil, backup com um arquivo |
| Frontend | HTML5 + CSS (variáveis, Grid/Flex) + JS ES2020 vanilla + Canvas 2D | Carregamento instantâneo, sem bundler |
| Segredos | API keys e senhas cifradas com libsodium (`app_key` em `/etc/db-analyzer/config.php`) | Vazamento do SQLite não expõe chaves |

## Estrutura

```
/var/www/db-analyzer/            (código, root:www-data, somente leitura para o PHP)
├── install.sh                   instalador/atualizador idempotente
├── public/                      ÚNICO diretório servido pelo Apache (DocumentRoot)
│   ├── index.php                front controller + rotas
│   └── assets/{css,js,img}      tema dark, analyzer.js (canvas animado), login.js
├── app/
│   ├── bootstrap.php            autoload PSR-4 simples, config, timezone
│   ├── Core/                    Router, Auth (argon2id + anti brute-force), Session, Csrf, Database, Crypto, Audit, Markdown
│   ├── Controllers/             Auth, Dashboard, Analyzer, Report, Ai, User, Branding, Log
│   ├── Analyzer/                Connector (read-only), Collector (contrato), PostgresCollector, MysqlCollector,
│   │                            Sizing (veredito + postgresql.conf/my.cnf), Scorer, Prompt, MarkdownReport
│   ├── Ai/AiClient.php          OpenAI, Anthropic, Gemini, Ollama, Groq, DeepSeek (só ext-curl)
│   └── Views/                   templates PHP
├── database/migrations/*.sql    esquema SQLite versionado
├── bin/console                  migrate, admin:init, user:create, user:password, key:generate, logs:prune
└── deploy/apache/               VirtualHost com HTTPS, HSTS, CSP e bloqueio de tudo fora de /public

/etc/db-analyzer/config.php      config + app_key (root:www-data 0640)
/var/lib/db-analyzer/            app.sqlite, sessions/, uploads/ (logo), backups/ (diário, 14 dias)
```

## Como a análise funciona

1. **Conectar e listar bancos**: valida credenciais com sessão `READ ONLY` + `statement_timeout`/`max_execution_time`.
2. A análise roda em 7 etapas (`/api/analyzer/step`), cada uma devolvendo log, contadores e grafo para a animação:
   Conectando → Mapeando Schemas → Analisando Índices → Avaliando Queries → Hardware/Buffers → Consultando IA → Laudo.
3. Regras determinísticas geram achados com severidade e **SQL de correção**; o `Sizing` calcula a configuração de
   referência para o hardware informado e um veredito (subdimensionado / superdimensionado / mal tunado / adequado).
4. A IA recebe a coleta compactada e devolve o laudo em Markdown. Sem IA configurada, o laudo é só heurístico.

Permissões mínimas recomendadas no banco alvo:

```sql
-- PostgreSQL
CREATE ROLE oraculo LOGIN PASSWORD '...'; GRANT pg_monitor TO oraculo; GRANT CONNECT ON DATABASE app TO oraculo;
-- MySQL / MariaDB
CREATE USER 'oraculo'@'%' IDENTIFIED BY '...'; GRANT SELECT, PROCESS, SHOW VIEW ON *.* TO 'oraculo'@'%';
```

Para adicionar um motor novo, implemente `App\Analyzer\Collector` e registre em `Connector::collector()`.

## Desenvolvimento local

```bash
php -r "echo \"<?php return ['debug'=>true,'app_key'=>'\".base64_encode(random_bytes(32)).\"'];\";" > storage/config.php
php bin/console migrate && php bin/console admin:init --password=troque-esta-senha
php -S 127.0.0.1:8080 -t public bin/dev-router.php
```

## Fluxo de versionamento

Todo o desenvolvimento vai **direto na branch `main`** (`git push origin main`), sem PRs nem branches de feature.
O deploy em produção é a mesma linha do `curl`.
