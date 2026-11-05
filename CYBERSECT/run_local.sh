#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PROJECT_DIR}/../venv/bin/python"
UVICORN="${PROJECT_DIR}/../venv/bin/uvicorn"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/air-ds"
ENV_FILE="${CONFIG_DIR}/environment"

cd "$PROJECT_DIR"

if [[ ! -x "$PYTHON" || ! -x "$UVICORN" ]]; then
    printf 'Project virtual environment missing. Create it and install requirements first.\n' >&2
    exit 1
fi

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
    if ! command -v openssl >/dev/null 2>&1; then
        printf 'OpenSSL is required to generate local application keys.\n' >&2
        exit 1
    fi
    umask 077
    printf 'AIR_DS_API_KEY=%s\nSECRET_KEY=%s\nAIR_DS_GEOLOCATION_PROVIDER=maxmind\n' \
        "$(openssl rand -hex 32)" \
        "$(openssl rand -hex 32)" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    printf 'Created private local configuration in %s.\n' "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"

while IFS='=' read -r name value; do
    case "$name" in
        AIR_DS_API_KEY|SECRET_KEY|AIR_DS_GEOLOCATION_PROVIDER)
            if [[ -z "$value" ]]; then
                printf '%s is empty in %s.\n' "$name" "$ENV_FILE" >&2
                exit 1
            fi
            if [[ "$name" == "AIR_DS_GEOLOCATION_PROVIDER" && "$value" != "maxmind" && "$value" != "ipwhois" ]]; then
                printf 'AIR_DS_GEOLOCATION_PROVIDER must be maxmind or ipwhois in %s.\n' "$ENV_FILE" >&2
                exit 1
            fi
            export "$name=$value"
            ;;
        *)
            if [[ -n "$name" ]]; then
                printf 'Unexpected setting %s in %s.\n' "$name" "$ENV_FILE" >&2
                exit 1
            fi
            ;;
    esac
done < "$ENV_FILE"

if [[ -z "${AIR_DS_API_KEY:-}" || -z "${SECRET_KEY:-}" ]]; then
    printf 'AIR_DS_API_KEY and SECRET_KEY must be configured in %s.\n' "$ENV_FILE" >&2
    exit 1
fi

PORT="${AIR_DS_PORT:-8012}"
printf 'Dashboard API key: %s\n' "$AIR_DS_API_KEY"
printf 'Dashboard: http://localhost:%s/dashboard\n' "$PORT"
printf 'API docs:  http://localhost:%s/docs\n' "$PORT"
exec "$UVICORN" app.main:app --host 127.0.0.1 --port "$PORT"
