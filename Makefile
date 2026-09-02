.PHONY: all fmt check clippy test

all: fmt check clippy test

fcc: fmt check clippy

fmt:
	cargo fmt --all

check:
	cargo check --workspace --all-targets --all-features

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace --all-targets --all-features

docker-build:
	docker compose build

docker-up:
	docker network create kms_sec-net 2>/dev/null || true
	docker compose up -d --force-recreate

docker-down:
	docker compose down

dr: docker-down docker-up
dbr: fmt docker-down docker-build docker-up
