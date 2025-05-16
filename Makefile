.PHONY: all run build fmt clean help

BINARY:=hathr
BINDIR:=bin
DOCKER_TAG:=hathr-backend
DOCKER_PORT:=8080

ifneq (,$(wildcard ./.env))
    include .env
    export
endif

all: build

build:
	@echo "🔨  Building $(BINARY)…"
	go build -o $(BINDIR)/$(BINARY) cmd/hathr/main.go
	@echo "✓  Built $(BINDIR)/$(BINARY)"

docker-build:
	@echo "🔨🐳 Building docker image $(BINARY)…"
	docker build . -t $(DOCKER_TAG)
	@echo "✓  Built $(DOCKER_TAG)"

run:
	@echo "🚀  Starting..."
	go run cmd/hathr/main.go

docker-run:
	@echo "🚀🐳  Starting docker image $(BINARY)..."
	docker run --env-file .env -e JWKS_PATH=/app/jwks.json --mount type=bind,src=jwks.json,dst=/app/jwks.json,ro -p $(DOCKER_PORT):8080 $(BINARY)

fmt:
	@echo "🎨  Formatting code..."
	gofmt -l -s -w .

clean:
	@echo "🧹 Cleaning $(BINDIR)"
	rm $(BINDIR)/*

help:
	@cat Makefile
