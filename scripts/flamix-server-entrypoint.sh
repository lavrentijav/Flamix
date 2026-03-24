#!/usr/bin/env sh
set -eu

: "${FLAMIX_SERVER_HOST:=0.0.0.0}"
: "${FLAMIX_SERVER_PORT:=8443}"
: "${FLAMIX_WEB_HOST:=0.0.0.0}"
: "${FLAMIX_WEB_PORT:=8080}"
: "${FLAMIX_DB_PATH:=/var/lib/flamix/data/server.db}"
: "${FLAMIX_CERT_DIR:=/var/lib/flamix/certs}"
: "${FLAMIX_LOG_DIR:=/var/log/flamix}"

mkdir -p "$(dirname "$FLAMIX_DB_PATH")" "$FLAMIX_CERT_DIR" "$FLAMIX_LOG_DIR"

if [ "$(id -u)" = "0" ]; then
    chown -R flamix:flamix "$(dirname "$FLAMIX_DB_PATH")" "$FLAMIX_CERT_DIR" "$FLAMIX_LOG_DIR" /opt/flamix 2>/dev/null || true
    exec gosu flamix "$0" "$@"
fi

set -- python -u /opt/flamix/server/run.py \
    --host "$FLAMIX_SERVER_HOST" \
    --port "$FLAMIX_SERVER_PORT" \
    --db-path "$FLAMIX_DB_PATH" \
    --cert-dir "$FLAMIX_CERT_DIR" \
    --web-host "$FLAMIX_WEB_HOST" \
    --web-port "$FLAMIX_WEB_PORT"

if [ "${FLAMIX_WEB_DISABLED:-0}" = "1" ]; then
    set -- "$@" --web-disable
fi

exec "$@"
