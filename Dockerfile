FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    g++ \
    cmake \
    ninja-build \
    pkg-config \
    libasio-dev \
    libsqlite3-dev \
    sqlite3 \
    libcurl4-openssl-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN cmake -B /build -GNinja /app \
    && cmake --build /build

EXPOSE 8080

CMD ["/build/event_app"]
