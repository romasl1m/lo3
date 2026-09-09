#!/bin/bash
echo "BEGIN TRANSACTION;"
i=1
for number in {1..4}; do
    for letter in {A..E}; do
        for place in {1..35}; do
            code="$number$letter$place"
            if [ "$code" = "3A17" ] || [ "$code" = "3A35" ]; then
                role="admin"
            else
                role="user"
            fi
            echo "INSERT INTO users (name, code, password_hash, role) VALUES ('$code', '$code', '123', '$role');"
            i=$((i + 1))
            if [ $i -gt 500 ]; then
                echo "COMMIT;"
                exit
            fi
        done
    done
done
echo "COMMIT;"
