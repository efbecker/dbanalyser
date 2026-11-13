-- DB Oráculo Analyzer :: esquema interno (SQLite 3)
-- Aplicado por: php bin/console migrate
PRAGMA foreign_keys = ON;

-- Perfis de IA. A linha com is_global = 1 é a "IA Padrão Global".
CREATE TABLE IF NOT EXISTS ai_profiles (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL,
    provider     TEXT    NOT NULL CHECK (provider IN ('openai','anthropic','gemini','ollama','groq','deepseek')),
    model        TEXT,                       -- NULL/'' = modelo padrão do provedor
    api_key_enc  TEXT,                       -- cifrado com libsodium (chave em /etc/db-analyzer/config.php)
    base_url     TEXT,                       -- endpoint customizado/local (opcional)
    is_global    INTEGER NOT NULL DEFAULT 0 CHECK (is_global IN (0,1)),
    temperature  REAL    NOT NULL DEFAULT 0.2,
    max_tokens   INTEGER NOT NULL DEFAULT 4096,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ai_profiles_global ON ai_profiles(is_global) WHERE is_global = 1;
CREATE UNIQUE INDEX IF NOT EXISTS ux_ai_profiles_name   ON ai_profiles(name);

-- Usuários e controle de acesso (ADMIN / CLIENT)
CREATE TABLE IF NOT EXISTS users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    username             TEXT    NOT NULL COLLATE NOCASE UNIQUE,
    password_hash        TEXT    NOT NULL,
    role                 TEXT    NOT NULL DEFAULT 'CLIENT' CHECK (role IN ('ADMIN','CLIENT')),
    display_name         TEXT,
    email                TEXT,
    ai_profile_id        INTEGER REFERENCES ai_profiles(id) ON DELETE SET NULL, -- NULL = IA padrão do sistema
    infra_json           TEXT,               -- {"monitoring_url":..., "vcpu_clock_ghz":..., "notes":...}
    must_change_password INTEGER NOT NULL DEFAULT 0,
    is_active            INTEGER NOT NULL DEFAULT 1,
    last_login_at        TEXT,
    last_login_ip        TEXT,
    created_at           TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at           TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_users_ai_profile ON users(ai_profile_id);

-- Proteção contra brute-force
CREATE TABLE IF NOT EXISTS login_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT,
    ip          TEXT    NOT NULL,
    success     INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_login_attempts_ip   ON login_attempts(ip, created_at);
CREATE INDEX IF NOT EXISTS ix_login_attempts_user ON login_attempts(username, created_at);

-- Configurações chave/valor (branding, opções globais)
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Conexões salvas (senha cifrada) — opcional para reanálises
CREATE TABLE IF NOT EXISTS db_connections (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label         TEXT    NOT NULL,
    engine        TEXT    NOT NULL CHECK (engine IN ('postgresql','mysql','mariadb')),
    host          TEXT    NOT NULL,
    port          INTEGER NOT NULL,
    username      TEXT    NOT NULL,
    password_enc  TEXT,
    ssl_mode      TEXT    NOT NULL DEFAULT 'prefer',
    default_db    TEXT,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE (user_id, label)
);

-- Histórico de análises (laudos)
CREATE TABLE IF NOT EXISTS analyses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    engine          TEXT    NOT NULL,
    host            TEXT    NOT NULL,
    port            INTEGER NOT NULL,
    database_name   TEXT    NOT NULL,
    server_version  TEXT,
    status          TEXT    NOT NULL DEFAULT 'running' CHECK (status IN ('running','done','failed')),
    score           INTEGER,
    hardware_json   TEXT,                    -- vCPU, clock, RAM, disco informados
    metrics_json    TEXT,                    -- coleta técnica bruta por etapa
    findings_json   TEXT,                    -- achados (severidade, categoria, SQL de correção)
    tuning_json     TEXT,                    -- veredito + configuração recomendada
    ai_report_md    TEXT,                    -- laudo da IA em Markdown
    ai_provider     TEXT,
    ai_model        TEXT,
    error           TEXT,
    started_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    finished_at     TEXT
);
CREATE INDEX IF NOT EXISTS ix_analyses_user   ON analyses(user_id, started_at);
CREATE INDEX IF NOT EXISTS ix_analyses_target ON analyses(host, port, database_name, started_at);

-- Consumo de tokens de IA
CREATE TABLE IF NOT EXISTS ai_usage (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    analysis_id  INTEGER REFERENCES analyses(id) ON DELETE SET NULL,
    provider     TEXT    NOT NULL,
    model        TEXT,
    tokens_in    INTEGER NOT NULL DEFAULT 0,
    tokens_out   INTEGER NOT NULL DEFAULT 0,
    latency_ms   INTEGER,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS ix_ai_usage_created ON ai_usage(created_at);

-- Auditoria
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    user_id     INTEGER,
    username    TEXT,
    ip          TEXT,
    severity    TEXT    NOT NULL DEFAULT 'INFO' CHECK (severity IN ('DEBUG','INFO','WARNING','ERROR','CRITICAL')),
    event       TEXT    NOT NULL,            -- ex: auth.login, auth.failed, ai.update, db.connect, analysis.error
    message     TEXT,
    context_json TEXT
);
CREATE INDEX IF NOT EXISTS ix_audit_created  ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS ix_audit_user     ON audit_logs(user_id, created_at);
CREATE INDEX IF NOT EXISTS ix_audit_severity ON audit_logs(severity, created_at);

INSERT OR IGNORE INTO settings(key, value) VALUES
    ('brand.name',         'DB Oráculo Analyzer'),
    ('brand.short',        'ORÁCULO'),
    ('brand.accent',       '#00e5ff'),
    ('brand.report_color', '#00e5ff'),
    ('brand.logo',         ''),
    ('brand.footer',       'Laudo gerado automaticamente — revise antes de aplicar em produção.');
