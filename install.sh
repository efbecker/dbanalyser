#!/usr/bin/env bash
# =============================================================================
#  DB Oráculo Analyzer — instalador/atualizador idempotente para Debian 13+
#
#  Instalação ou atualização com uma linha:
#    curl -sSL https://raw.githubusercontent.com/efbecker/dbanalyser/main/install.sh | sudo bash
#
#  Variáveis opcionais (passe depois do sudo):
#    DOMAIN=analyzer.exemplo.com   nome do VirtualHost (padrão: hostname -f)
#    LE_EMAIL=voce@exemplo.com     com DOMAIN público, emite certificado Let's Encrypt
#    ADMIN_PASSWORD='...'          senha inicial do admin (padrão: gerada aleatoriamente)
#    BRANCH=main                   branch a implantar
#    FORCE=1                       ignora a checagem de versão do Debian
#  Ex.: curl -sSL .../install.sh | sudo DOMAIN=db.exemplo.com LE_EMAIL=ops@exemplo.com bash
# =============================================================================
set -Eeuo pipefail

REPO_URL="${REPO_URL:-https://github.com/efbecker/dbanalyser.git}"
BRANCH="${BRANCH:-main}"
APP_DIR="${APP_DIR:-/var/www/db-analyzer}"
DATA_DIR="${DATA_DIR:-/var/lib/db-analyzer}"
CONF_DIR="/etc/db-analyzer"
CRED_FILE="/root/db-analyzer-admin.txt"
DOMAIN="${DOMAIN:-$(hostname -f 2>/dev/null || hostname)}"
LE_EMAIL="${LE_EMAIL:-}"
export DEBIAN_FRONTEND=noninteractive

C='\033[0;36m'; G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'
step() { echo -e "\n${C}▶ $*${N}"; }
ok()   { echo -e "${G}✔ $*${N}"; }
warn() { echo -e "${Y}⚠ $*${N}"; }
die()  { echo -e "${R}✘ $*${N}" >&2; exit 1; }
trap 'die "Falha na linha $LINENO: $BASH_COMMAND"' ERR

# Todo o fluxo fica dentro de main() para que o bash leia o script inteiro antes de
# executar (seguro com `curl | bash`, mesmo que algum comando leia stdin).
main() {
# -----------------------------------------------------------------------------
step "Validando ambiente"
[[ $EUID -eq 0 ]] || die "Execute como root (use: curl ... | sudo bash)"
[[ -r /etc/os-release ]] || die "/etc/os-release não encontrado"
# shellcheck disable=SC1091
. /etc/os-release
if [[ "${FORCE:-0}" != "1" ]]; then
  [[ "${ID:-}" == "debian" ]] || die "Distribuição '${ID:-?}' não suportada (requer Debian 13+). Use FORCE=1 por sua conta e risco."
  major="${VERSION_ID%%.*}"
  if [[ -n "$major" ]]; then
    (( major >= 13 )) || die "Debian ${VERSION_ID} detectado; requer Debian 13 (Trixie) ou superior."
  else
    [[ "${VERSION_CODENAME:-}" =~ ^(trixie|forky|duke|sid)$ ]] || die "Versão do Debian não identificada (${VERSION_CODENAME:-?})."
  fi
fi
ok "${PRETTY_NAME:-Debian}"

# -----------------------------------------------------------------------------
step "Instalando pacotes (Apache2, PHP-FPM, drivers PDO, SQLite)"
apt-get update -qq
PKGS=(apache2 php-fpm php-cli php-pgsql php-mysql php-sqlite3 php-curl php-mbstring php-xml php-intl php-opcache
      sqlite3 git ca-certificates curl ssl-cert postgresql-client mariadb-client)
if [[ -n "$LE_EMAIL" ]]; then PKGS+=(certbot); fi
apt-get install -y -qq --no-install-recommends "${PKGS[@]}" >/dev/null
PHPV="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')"
php -r 'exit(version_compare(PHP_VERSION, "8.3.0", ">=") ? 0 : 1);' || die "PHP $PHPV encontrado; requer 8.3+"
for ext in pdo_pgsql pdo_mysql pdo_sqlite curl mbstring sodium; do
  php -m | grep -qi "^${ext}$" || die "Extensão PHP ausente: $ext"
done
ok "PHP $PHPV com pdo_pgsql, pdo_mysql, pdo_sqlite, curl, mbstring, sodium"

# -----------------------------------------------------------------------------
step "Obtendo código ($REPO_URL @ $BRANCH) em $APP_DIR"
if [[ -d "$APP_DIR/.git" ]]; then
  git -C "$APP_DIR" remote set-url origin "$REPO_URL"
  git -C "$APP_DIR" fetch --quiet --depth 1 origin "$BRANCH"
  git -C "$APP_DIR" reset --quiet --hard "origin/$BRANCH"
  git -C "$APP_DIR" clean -fdq -e storage/
  ok "Atualizado para $(git -C "$APP_DIR" rev-parse --short HEAD)"
else
  if [[ -e "$APP_DIR" ]] && [[ -n "$(ls -A "$APP_DIR" 2>/dev/null)" ]]; then
    bak="${APP_DIR}.bak-$(date +%Y%m%d%H%M%S)"
    warn "$APP_DIR existe e não é um clone git; movendo para $bak"
    mv "$APP_DIR" "$bak"
  fi
  git clone --quiet --depth 1 --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
  ok "Clonado $(git -C "$APP_DIR" rev-parse --short HEAD)"
fi

# -----------------------------------------------------------------------------
step "Configuração e diretório de dados (fora da raiz pública)"
install -d -m 0750 -o root -g www-data "$CONF_DIR"
if [[ ! -f "$CONF_DIR/config.php" ]]; then
  APP_KEY="$(php -r 'echo base64_encode(random_bytes(32));')"
  cat > "$CONF_DIR/config.php" <<PHP
<?php
// Gerado pelo install.sh em $(date -Is). NÃO versionar. Perder app_key = perder API keys cifradas.
return [
    'debug'     => false,
    'timezone'  => 'America/Sao_Paulo',
    'data_dir'  => '$DATA_DIR',
    'app_key'   => '$APP_KEY',
    'session_ttl' => 7200,
    'login_max_attempts' => 5,
    'login_window_min'   => 15,
    'analyzer_statement_timeout_ms' => 15000,
    'ai_timeout' => 180,
];
PHP
  ok "Config criada em $CONF_DIR/config.php"
else
  ok "Config existente preservada"
fi
chown root:www-data "$CONF_DIR/config.php"; chmod 0640 "$CONF_DIR/config.php"

install -d -m 0750 -o www-data -g www-data "$DATA_DIR" "$DATA_DIR/sessions" "$DATA_DIR/uploads" "$DATA_DIR/backups"

# Código: root é dono, www-data apenas lê
chown -R root:www-data "$APP_DIR"
find "$APP_DIR" -path "$APP_DIR/.git" -prune -o -type d -exec chmod 0750 {} +
find "$APP_DIR" -path "$APP_DIR/.git" -prune -o -type f -exec chmod 0640 {} +
chmod 0750 "$APP_DIR/bin/console" "$APP_DIR/install.sh"

# -----------------------------------------------------------------------------
step "Banco interno SQLite (migrations + admin)"
as_www() { runuser -u www-data -- "$@"; }
as_www php "$APP_DIR/bin/console" migrate
ADMIN_ARGS=()
[[ -n "${ADMIN_PASSWORD:-}" ]] && ADMIN_ARGS+=("--password=$ADMIN_PASSWORD")
INIT_OUT="$(as_www php "$APP_DIR/bin/console" admin:init "${ADMIN_ARGS[@]}")"
if grep -q '^ADMIN_CREATED' <<<"$INIT_OUT"; then
  ADMIN_PW="$(sed -n 's/^senha: //p' <<<"$INIT_OUT")"
  umask 077
  printf 'DB Oráculo Analyzer — credenciais iniciais (%s)\nURL: https://%s/\nusuario: admin\nsenha: %s\nA troca de senha é obrigatória no primeiro login. Apague este arquivo depois.\n' \
    "$(date -Is)" "$DOMAIN" "$ADMIN_PW" > "$CRED_FILE"
  ok "Usuário 'admin' criado — senha salva em $CRED_FILE (chmod 600)"
else
  ok "Administrador já existente preservado"
fi

# -----------------------------------------------------------------------------
step "PHP-FPM $PHPV"
cat > "/etc/php/$PHPV/fpm/conf.d/90-db-analyzer.ini" <<'INI'
expose_php = Off
memory_limit = 256M
max_execution_time = 300
upload_max_filesize = 2M
post_max_size = 4M
session.cookie_httponly = 1
session.use_strict_mode = 1
opcache.enable = 1
opcache.memory_consumption = 128
opcache.validate_timestamps = 1
opcache.revalidate_freq = 2
INI
PHP_SOCK="/run/php/php${PHPV}-fpm.sock"
systemctl enable --quiet "php${PHPV}-fpm"
systemctl restart "php${PHPV}-fpm"
ok "php${PHPV}-fpm ativo ($PHP_SOCK)"

# -----------------------------------------------------------------------------
step "Apache2 (VirtualHost, HTTPS, cabeçalhos de segurança)"
for m in $(apache2ctl -M 2>/dev/null | awk '/php[0-9.]*_module/{print $1}' | sed 's/_module//'); do a2dismod -q "$m" || true; done
a2dismod -q mpm_prefork >/dev/null 2>&1 || true
a2enmod -q mpm_event proxy proxy_fcgi setenvif rewrite headers ssl http2 >/dev/null
a2enconf -q "php${PHPV}-fpm" >/dev/null

CERT=/etc/ssl/certs/ssl-cert-snakeoil.pem
KEY=/etc/ssl/private/ssl-cert-snakeoil.key
[[ -f "$CERT" ]] || make-ssl-cert generate-default-snakeoil --force-overwrite
if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
  CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"; KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
fi

render_vhost() {
  sed -e "s#__SERVER_NAME__#$DOMAIN#g" -e "s#__APP_DIR__#$APP_DIR#g" -e "s#__PHP_SOCK__#$PHP_SOCK#g" \
      -e "s#__CERT__#$CERT#g" -e "s#__KEY__#$KEY#g" \
      "$APP_DIR/deploy/apache/db-analyzer.conf" > /etc/apache2/sites-available/db-analyzer.conf
}
cat > /etc/apache2/conf-available/db-analyzer-hardening.conf <<CONF
# Endurecimento global (DB Oráculo Analyzer)
ServerName $DOMAIN
ServerTokens Prod
ServerSignature Off
TraceEnable Off
CONF
a2enconf -q db-analyzer-hardening >/dev/null
render_vhost
a2ensite -q db-analyzer >/dev/null
a2dissite -q 000-default >/dev/null 2>&1 || true
apache2ctl configtest 2>&1 | grep -v "Syntax OK" || true
systemctl enable --quiet apache2
systemctl restart apache2

if [[ -n "$LE_EMAIL" && "$CERT" == *snakeoil* ]]; then
  step "Emitindo certificado Let's Encrypt para $DOMAIN"
  if certbot certonly --webroot -w "$APP_DIR/public" -d "$DOMAIN" -m "$LE_EMAIL" --agree-tos -n \
       --deploy-hook "systemctl reload apache2"; then
    CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"; KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    render_vhost
    systemctl reload apache2
    ok "Certificado válido instalado (renovação automática via certbot.timer)"
  else
    warn "Falha ao emitir certificado: mantido o autoassinado. Verifique DNS e porta 80."
  fi
fi
ok "Apache2 servindo https://$DOMAIN/"

# -----------------------------------------------------------------------------
step "Rotinas de manutenção (cron)"
cat > /etc/cron.d/db-analyzer <<CRON
# Backup diário do SQLite interno (mantém 14) e limpeza semanal de logs antigos
15 3 * * * www-data sqlite3 $DATA_DIR/app.sqlite ".backup '$DATA_DIR/backups/app-\$(date +\%F).sqlite'" && find $DATA_DIR/backups -name 'app-*.sqlite' -mtime +14 -delete
30 3 * * 0 www-data php $APP_DIR/bin/console logs:prune --days=180 >/dev/null
# Limpa sessões expiradas (o GC do PHP vem desativado no Debian)
*/30 * * * * www-data find $DATA_DIR/sessions -type f -name 'sess_*' -mmin +240 -delete
CRON
chmod 0644 /etc/cron.d/db-analyzer
ok "Backup diário em $DATA_DIR/backups"

# -----------------------------------------------------------------------------
echo -e "\n${G}════════════════════════════════════════════════════════════${N}"
echo -e "${G} DB Oráculo Analyzer instalado — $(git -C "$APP_DIR" log -1 --format='%h %s')${N}"
echo -e "${G}════════════════════════════════════════════════════════════${N}"
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo -e " URL ........: https://$DOMAIN/${IP:+  (ou https://$IP/)}"
if [[ -f "$CRED_FILE" ]]; then
  echo -e " Login ......: admin  (senha em ${Y}$CRED_FILE${N}; troca obrigatória no 1º acesso)"
fi
echo -e " Dados ......: $DATA_DIR   Config: $CONF_DIR/config.php"
echo -e " Reset senha : sudo -u www-data php $APP_DIR/bin/console user:password admin"
echo -e " Atualizar ..: rode novamente a mesma linha do curl"
[[ "$CERT" == *snakeoil* ]] && warn "Certificado autoassinado em uso. Para Let's Encrypt: DOMAIN=seu.dominio LE_EMAIL=voce@x.com"
}

main "$@" </dev/null
