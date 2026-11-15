#!/usr/bin/env bash
set -euo pipefail

PORT="${CYBERSECT_PORT:-8012}"
if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    printf 'CYBERSECT_PORT must be a port number from 1 to 65535.\n' >&2
    exit 2
fi

BASE_URL="http://127.0.0.1:${PORT}"
if ! command -v curl >/dev/null 2>&1; then
    printf 'curl is required. Install it with your distribution package manager.\n' >&2
    exit 2
fi

if [[ ! -t 0 ]]; then
    printf 'Run this script in an interactive terminal so it can securely prompt for the API key.\n' >&2
    exit 2
fi

printf 'Checking CYBERSECT at %s ...\n' "$BASE_URL"
if ! curl --silent --show-error --fail --max-time 5 "$BASE_URL/" >/dev/null; then
    printf 'CYBERSECT is not responding. Start ./run_local.sh first.\n' >&2
    exit 1
fi

read -r -s -p 'Dashboard API key (input hidden): ' API_KEY
printf '\n'
if [[ -z "$API_KEY" ]]; then
    printf 'An API key is required for the upload and FIM demo steps.\n' >&2
    exit 2
fi

DEMO_FILE="$(mktemp)"
CURL_CONFIG="$(mktemp)"
RESPONSE_FILE="$(mktemp)"
chmod 600 "$CURL_CONFIG"
trap 'rm -f "$DEMO_FILE" "$CURL_CONFIG" "$RESPONSE_FILE"' EXIT
printf 'header = "X-AIR-DS-KEY: %s"\n' "$API_KEY" > "$CURL_CONFIG"
unset API_KEY
printf '# Inert lab sample: this file is uploaded for inspection only.\nos.system("echo CYBERSECT_LAB_DEMO")\n' > "$DEMO_FILE"

run_demo() {
    local title="$1"
    local expected_status="$2"
    local actual_status
    shift
    shift
    printf '\n=== %s ===\n' "$title"
    actual_status="$(curl --silent --show-error --max-time 15 \
        --output "$RESPONSE_FILE" --write-out '%{http_code}' "$@")"
    cat "$RESPONSE_FILE"
    printf '\nHTTP status: %s\n' "$actual_status"
    if [[ "$actual_status" != "$expected_status" ]]; then
        printf 'Expected HTTP %s for this demo step.\n' "$expected_status" >&2
        return 1
    fi
    printf '\n'
}

log_incident() {
    local attack_type="$1"
    local status
    printf 'Adding synthetic %s incident to the dashboard feed...\n' "$attack_type"
    status="$(curl --silent --show-error --max-time 10 --config "$CURL_CONFIG" \
        -H 'Content-Type: application/json' \
        --output "$RESPONSE_FILE" --write-out '%{http_code}' \
        --data "{\"source\":\"CYBERSECT_LOCAL_LAB_DEMO\",\"attack_type\":\"${attack_type}\",\"severity\":\"HIGH\",\"source_ip\":\"127.0.0.1\",\"target_asset\":\"localhost (lab demo)\"}" \
        "$BASE_URL/api/v1/alert")"
    cat "$RESPONSE_FILE"
    printf '\n'
    if [[ "$status" != '201' ]]; then
        printf 'Could not add the synthetic incident (HTTP %s). Check the dashboard API key.\n' "$status" >&2
        return 1
    fi
}

printf '\nAll requests below go only to 127.0.0.1. 403 is expected for the three blocked requests.\n'

run_demo 'Normal request (expected 200)' 200 \
    "$BASE_URL/"

run_demo 'URL-encoded SQL injection signature (expected 403, SQL_INJECTION)' 403 \
    --get --data-urlencode "id=1' OR '1'='1" "$BASE_URL/"
log_incident 'SQL_INJECTION'

run_demo 'XSS marker in a request header (expected 403, XSS)' 403 \
    -H 'X-Lab-Demo: <script>alert(1)</script>' "$BASE_URL/"
log_incident 'XSS'

run_demo 'Inert suspicious file upload (expected 403, SUSPICIOUS_FILE)' 403 \
    --config "$CURL_CONFIG" \
    -F "file=@${DEMO_FILE};filename=demo.py;type=text/x-python" \
    "$BASE_URL/api/v1/security/scan-file"
log_incident 'SUSPICIOUS_FILE'

run_demo 'FIM baseline mismatch (expected HTTP 200 and tamper_detected: true)' 200 \
    --config "$CURL_CONFIG" \
    -H 'Content-Type: application/json' \
    --data '{"file_path":"/app/main.py","current_hash":"lab-demo-mismatch","trigger_mode":"hash_change"}' \
    "$BASE_URL/api/v1/detect/fim-audit"
log_incident 'FILE_INTEGRITY'

printf 'Demo complete. Synthetic incidents should appear in the dashboard Incident Feed; proxy detections appear in Proxy Attack History.\n'
printf 'The FIM step submits a synthetic mismatching hash; it does not edit any file.\n'
