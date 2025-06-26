.PHONY: all run build fmt clean help

SERVER_DIR:=cmd/server
SERVER_BIN:=hathr-server
CLI_BIN:=hathr-cli
BINDIR:=bin
DOCKER_TAG:=hathr-backend
DOCKER_PORT:=8080

ifneq (,$(wildcard ./.env))
    include .env
    export
endif

all: build-server

build-server:
	@echo "🔨  Building $(SERVER_BIN)…"
	go build -o $(BINDIR)/$(SERVER_BIN) $(SERVER_DIR)/main.go
	@echo "✓  Built $(BINDIR)/$(SERVER_BIN)"

build-cli:
	@echo "🔨  Building $(CLI_BIN)…"
	go build -o $(BINDIR)/$(CLI_BIN) cmd/cli/main.go
	@echo "✓  Built $(BINDIR)/$(CLI_BIN)"

docker-build-server:
	@echo "🔨🐳 Building docker image $(SERVER_BIN)…"
	docker build -f server.Dockerfile . -t $(DOCKER_TAG)
	@echo "✓  Built $(DOCKER_TAG)"

run-server:
	@echo "🚀  Starting..."
	go run $(SERVER_DIR)/main.go

docker-run:
	@echo "🚀🐳  Starting docker image $(SERVER_BIN)..."
	docker run --env-file .env -e JWKS_PATH=/app/jwks.json --mount type=bind,src=jwks.json,dst=/app/jwks.json,ro -p $(DOCKER_PORT):8080 $(SERVER_BIN)

create-admin:
	@echo "👤  Creating admin user..."
	go run scripts/admin.go

fmt:
	@echo "🎨  Formatting code..."
	gofmt -l -s -w .

clean:
	@echo "🧹 Cleaning $(BINDIR)"
	rm $(BINDIR)/*

help:
	@cat Makefile
