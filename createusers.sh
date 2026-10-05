#!/bin/bash
set -e

cd "$(dirname "$0")"

DB="${DATABASE_PATH:-events.db}"

declare -A PASSWORDS
PASSWORDS[1A]=445645
PASSWORDS[1B]=123456
PASSWORDS[1C]=738291
PASSWORDS[1D]=564823
PASSWORDS[1E]=901347
PASSWORDS[2A]=217836
PASSWORDS[2B]=385964
PASSWORDS[2C]=649172
PASSWORDS[2D]=473918
PASSWORDS[2E]=826504
PASSWORDS[3A]=154739
PASSWORDS[3B]=692481
PASSWORDS[3C]=318567
PASSWORDS[3D]=847203
PASSWORDS[3E]=560914
PASSWORDS[4A]=293648
PASSWORDS[4B]=781035
PASSWORDS[4C]=425896
PASSWORDS[4D]=936271
PASSWORDS[4E]=674512

declare -A HASHES
for key in "${!PASSWORDS[@]}"; do
    HASHES[$key]=$(printf '%s' "${PASSWORDS[$key]}" | openssl passwd -6 -stdin)
done

generate_sql() {
    echo "BEGIN TRANSACTION;"
    for number in 1 2 3 4; do
        for letter in A B C D E; do
            key="${number}${letter}"
            HASH="${HASHES[$key]}"
            for place in $(seq 1 35); do
                code="${number}${letter}${place}"
                if [[ "$code" == "3A17" || "$code" == "3A35" ]]; then
                    role="admin"
                else
                    role="user"
                fi
                echo "INSERT OR IGNORE INTO users (name, code, password_hash, role) VALUES ('$code', '$code', '$HASH', '$role');"
            done
        done
    done
    echo "COMMIT;"
}

generate_sql | sqlite3 "$DB"
echo "Użytkownicy utworzeni w $DB"
