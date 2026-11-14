# DB Oráculo Analyzer

Plataforma web de diagnóstico, auditoria, tuning e análise inteligente de bancos **PostgreSQL, MySQL, MariaDB, Microsoft SQL Server e Oracle** com IA.
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
| Drivers | PDO `pdo_pgsql`, `pdo_mysql`, `pdo_dblib` (SQL Server via FreeTDS, pacote `php-sybase`), `pdo_sqlite`; `curl`; `sodium`. Oracle via `python-oracledb` em modo *thin* (ponte `bin/oracle-bridge.py`) | Sem binários proprietários: nada de Instant Client nem do driver ODBC da Microsoft. `python3-oracledb` vem do `apt` quando disponível; senão o instalador cria um venv em `/opt/db-analyzer/venv` |
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
│   │                            MssqlCollector, OracleCollector + OracleConnection (ponte python-oracledb),
│   │                            Sizing (veredito + postgresql.conf/my.cnf), Scorer, Prompt, MarkdownReport,
│   │                            Runner (execução em segundo plano, fila e progresso)
│   ├── Ai/AiClient.php          OpenAI, Anthropic, Gemini, Ollama, Groq, DeepSeek (só ext-curl)
│   └── Views/                   templates PHP
├── database/migrations/*.sql    esquema SQLite versionado
├── bin/console                  migrate, admin:init, user:*, key:generate, logs:prune, worker, analysis:run, analysis:list
└── deploy/apache/               VirtualHost com HTTPS, HSTS, CSP e bloqueio de tudo fora de /public

/etc/db-analyzer/config.php      config + app_key (root:www-data 0640)
/var/lib/db-analyzer/            app.sqlite, sessions/, uploads/ (logo), backups/ (diário, 14 dias)
```

## Como a análise funciona

1. **Conectar e listar bancos**: valida credenciais com sessão `READ ONLY` + `statement_timeout`/`max_execution_time`.
2. A análise roda **no servidor, em segundo plano**, em 9 etapas:
   Conectando → Mapeando Schemas → Analisando Índices → Avaliando Queries → Hardware/Buffers → SO via SSH (opcional) → Vulnerabilidades → Consultando IA → Laudo.
   O serviço `db-analyzer-worker` (systemd) lança um processo `bin/console analysis:run ID` por análise (até 3 simultâneas,
   `worker_concurrency` no config) e cada etapa grava log, contadores e grafo em `analyses.progress_json`. A tela do analisador
   só reproduz esses eventos (`/api/analyzer/progress`): dá para fechar a página e voltar depois, a animação retoma do ponto atual.
   Relatórios, Painel e a barra lateral mostram as análises em andamento com o percentual ao vivo; **Cancelar** interrompe
   inclusive a chamada à IA. Se o processo morrer (reboot, OOM), o worker retoma a análise da etapa em que parou.
   Sem o serviço, a própria requisição web dispara o processo. `bin/console analysis:list` mostra o que está rodando.
3. Regras determinísticas geram achados com severidade e **SQL de correção**; o `Sizing` calcula a configuração de
   referência para o hardware informado e um veredito (subdimensionado / superdimensionado / mal tunado / adequado).
4. A IA recebe a coleta compactada e devolve o laudo em Markdown. Sem IA configurada, o laudo é só heurístico.

Permissões mínimas recomendadas no banco alvo:

```sql
-- PostgreSQL
CREATE ROLE oraculo LOGIN PASSWORD '...'; GRANT pg_monitor TO oraculo; GRANT CONNECT ON DATABASE app TO oraculo;
-- MySQL / MariaDB
CREATE USER 'oraculo'@'%' IDENTIFIED BY '...'; GRANT SELECT, PROCESS, SHOW VIEW ON *.* TO 'oraculo'@'%';
-- SQL Server (2016+). No 2022 pode trocar VIEW SERVER STATE por VIEW SERVER PERFORMANCE STATE
CREATE LOGIN oraculo WITH PASSWORD = '...'; GRANT VIEW SERVER STATE, VIEW ANY DEFINITION TO oraculo;
USE app; CREATE USER oraculo FOR LOGIN oraculo; GRANT VIEW DATABASE STATE, VIEW DEFINITION TO oraculo;
USE msdb; CREATE USER oraculo FOR LOGIN oraculo; GRANT SELECT ON dbo.backupset TO oraculo;   -- checagem de backup (opcional)
-- Oracle (12.2+), no PDB. "Banco inicial" = service name; a lista de "bancos" são os schemas de usuário
CREATE USER oraculo IDENTIFIED BY "..."; GRANT CREATE SESSION, SELECT_CATALOG_ROLE TO oraculo;
```

### Coleta do servidor via SSH (opcional)

Na tela do analisador, marque **Coletar … do sistema operacional** e informe usuário e senha ou chave privada SSH.
O botão **Testar SSH e detectar hardware** preenche vCPUs, clock, RAM e tipo de disco. Na análise, a etapa
**Coletando SO via SSH** roda uma lista fixa de comandos de leitura (`App\Analyzer\OsCollector::COMMANDS`):
`/proc/meminfo`, `free`, `/proc/swaps`, `vm.*` (swappiness, overcommit, nr_hugepages, dirty_*), THP, `vmstat 2 5`,
OOM no `dmesg`/`journalctl -k`, `df` do diretório de dados e das montagens, `lsblk`, load e processos por memória.

- Nada digitado vira comando; o único valor dinâmico é o diretório de dados lido do próprio banco, validado e escapado.
- Use um usuário comum. Para ler o histórico de OOM (log do kernel) ele precisa estar no grupo `adm`
  (`usermod -aG adm oraculo`) **ou** marcar **Usar sudo**: o sudo só é usado em `journalctl -k` e `dmesg -T`, com a senha
  do sudo enviada pela entrada padrão da sessão (nunca na linha de comando). Regra mínima de sudoers:
  `oraculo ALL=(root) NOPASSWD: /usr/bin/journalctl -k -q --no-pager -n 1, /usr/bin/journalctl -k -q --no-pager --since=-30d, /usr/bin/dmesg -T`
- Em VMs (virtio `vd*`, discos QEMU/VMware/Hyper-V) o kernel não conhece a mídia física e costuma marcar o disco como
  rotacional. Nesses casos o analisador não afirma HDD/SSD: mantém o tipo escolhido no formulário e registra a ressalva no laudo.
- Credenciais SSH (e as do banco) ficam cifradas com libsodium em `analyses.secrets_enc` só enquanto a análise roda no
  worker, e são apagadas ao concluir, falhar ou cancelar.
  A chave privada vai para um arquivo temporário 0600 apagado logo após a conexão; a senha passa ao `sshpass` por variável de ambiente.
- A chave do host é fixada na primeira conexão (`<data_dir>/ssh/known_hosts`). Se mudar, a coleta é recusada; após uma
  reinstalação legítima rode `sudo -u www-data php bin/console ssh:forget <host>`.
- Os dados alimentam achados da categoria `os`, o veredito de dimensionamento (OOM, swap ativa, load e iowait) e o prompt da IA.
  Se o SSH falhar, a análise continua sem os dados do SO.

### Vulnerabilidades e ciclo de vida da versão

A etapa **Checando Vulnerabilidades** compara a versão exata do servidor (e, no PostgreSQL, as extensões com CVEs
próprios, como PostGIS, TimescaleDB e pgvector) com uma base local e mostra na aba **Segurança & Versão**: CVEs que
afetam a versão (com CVSS, versão que corrige e marcação de exploração ativa da CISA KEV), se o ciclo está sem suporte
(EOL), quantas versões de correção a instalação está atrasada e para qual versão atualizar.

- **Funciona sem internet.** Nenhuma consulta externa é feita durante a análise; a base `data/vulndb.json` vem no código.
- **Fontes:** NVD (configurações CPE) + dados dos próprios fabricantes no registro CVE (PostgreSQL, Oracle, Microsoft,
  MariaDB), via o espelho [fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds); ciclo de
  vida pelo [endoflife.date](https://endoflife.date). O dado do fabricante cobre CVEs recentes que o NVD ainda não analisou.
- **Atualização:** o workflow `.github/workflows/vulndb.yml` regera a base toda segunda e faz commit na `main`; cada
  servidor baixa o arquivo novo com `php bin/console vulndb:update` (cron semanal instalado pelo `install.sh`).
  Para regerar à mão: `pip install pyyaml && python3 tools/build_vulndb.py`.
- `php bin/console vulndb:status` mostra a data da base em uso; `vulndb:check postgresql 16.2` testa uma versão.
- Motores: PostgreSQL, MySQL, MariaDB, SQL Server (build `15.0.4xxx`, linha GDR ou CU) e Oracle (RU, ex.: `19.21`;
  se o servidor informar só `19.0.0.0.0`, os CVEs não são verificados e o laudo avisa).
- Limitação: vale a versão informada pelo servidor. Pacotes de distribuição com correções retroportadas (ex.: RHEL)
  podem aparecer como vulneráveis sem estar.

Como o analisador garante somente leitura nos motores novos: no SQL Server (que não tem sessão READ ONLY) o coletor
recusa qualquer instrução que não seja `SELECT`/`WITH`, lê em `READ UNCOMMITTED` com `LOCK_TIMEOUT 3000` e
`DEADLOCK_PRIORITY LOW`; no Oracle a ponte abre `SET TRANSACTION READ ONLY`, aceita só `SELECT`/`WITH`, nunca faz
COMMIT e usa `call_timeout`. Objetos de sistema (is_ms_shipped, schemas `sys`/`cdc`, replicação, diagramas; schemas
`ORACLE_MAINTAINED`, lixeira `BIN$`, `MLOG$`, `DR$`, tabelas externas e containers de MV) são excluídos na origem.

Para adicionar um motor novo, implemente `App\Analyzer\Collector` e registre em `Connector::collector()`.

## Desenvolvimento local

```bash
php -r "echo \"<?php return ['debug'=>true,'app_key'=>'\".base64_encode(random_bytes(32)).\"'];\";" > storage/config.php
php bin/console migrate && php bin/console admin:init --password=troque-esta-senha
php -S 127.0.0.1:8080 -t public bin/dev-router.php
php bin/console worker   # opcional: sem ele a requisição web dispara cada análise
```

## Fluxo de versionamento

Todo o desenvolvimento vai **direto na branch `main`** (`git push origin main`), sem PRs nem branches de feature.
O deploy em produção é a mesma linha do `curl`.
