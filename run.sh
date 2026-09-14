#!/bin/bash
set -e

cd "$(dirname "$0")"

mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc)"
cd ..

rm -f events.db events.db-shm events.db-wal

./build/event_app &
APP_PID=$!

sleep 1

bash createusers.sh

wait $APP_PID
