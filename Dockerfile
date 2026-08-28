# --- Etap 1: budowanie na Linuksie (Alpine) ---
FROM rust:1.93-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build

# Warstwa cache dla zależności
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked || true

# Właściwy kod źródłowy
COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

# --- Etap 2: minimalistyczny obraz produkcyjny ---
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

# Kopiujemy gotową binarkę z etapu builder
COPY --from=builder /build/target/release/secret-agent /usr/local/bin/secret-agent

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/secret-agent"]