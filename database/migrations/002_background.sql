-- Análise em segundo plano: o worker do servidor executa as etapas e grava o progresso aqui.
-- secrets_enc guarda as credenciais do alvo (e do SSH) cifradas com a app_key só enquanto a análise roda;
-- são apagadas ao concluir, falhar ou cancelar.
ALTER TABLE analyses ADD COLUMN secrets_enc      TEXT;
ALTER TABLE analyses ADD COLUMN progress_json    TEXT;
ALTER TABLE analyses ADD COLUMN current_stage    TEXT;
ALTER TABLE analyses ADD COLUMN worker_pid       INTEGER;
ALTER TABLE analyses ADD COLUMN heartbeat_at     TEXT;
ALTER TABLE analyses ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS ix_analyses_status ON analyses(status);
-- Análises que estavam "running" no modelo antigo (etapas dirigidas pelo navegador) não têm como continuar
UPDATE analyses SET status = 'failed', error = 'Interrompida pela atualização do sistema (refaça a análise).', finished_at = datetime('now')
 WHERE status = 'running';
