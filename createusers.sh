#!/bin/bash
set -e

cd "$(dirname "$0")"

DB="${DATABASE_PATH:-events.db}"
if [[ -z "${SEED_PASSWORD:-}" ]]; then
    echo "Set SEED_PASSWORD to the initial password for generated users." >&2
    exit 1
fi
if [[ ${#SEED_PASSWORD} -lt 4 ]]; then
    echo "SEED_PASSWORD must be at least 4 characters." >&2
    exit 1
fi

PASSWORD_HASH=$(printf '%s' "$SEED_PASSWORD" | openssl passwd -6 -stdin)

generate_sql() {
    echo "BEGIN TRANSACTION;"
    i=1
    for number in {1..4}; do
        for letter in {A..E}; do
            for place in {1..35}; do
                code="$number$letter$place"
                if [[ "$code" == "3A17" || "$code" == "3A35" ]]; then
                    role="admin"
                else
                    role="user"
                fi
                echo "INSERT OR IGNORE INTO users (name, code, password_hash, role) VALUES ('$code', '$code', '$PASSWORD_HASH', '$role');"
                i=$((i + 1))
                if [[ $i -gt 500 ]]; then
                    echo "COMMIT;"
                    return
                fi
            done
        done
    done
    echo "COMMIT;"
}

generate_sql | sqlite3 "$DB"
echo "Users created in $DB"