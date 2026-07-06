.DEFAULT_GOAL := help

.PHONY: build run run-vuln test eval trace-up trace-down detect deploy tidy fmt vet ollama-setup hooks help

build: ## Build hardened and vulnerable binaries into ./bin
	go build -o bin/gopherguard ./cmd/gopherguard
	go build -o bin/gopherguard-vuln ./cmd/gopherguard-vuln

run: ## Start hardened-mode agent on local Gemma, no API key needed
	go run ./cmd/gopherguard

run-vuln: ## Start fenced vulnerable-mode lab (localhost only)
	go run ./cmd/gopherguard-vuln --i-understand-this-is-insecure

test: ## Run the test suite
	go test ./...

eval: ## Run the eval gate: task-success, trajectory, injection-resistance (keyless)
	go test ./evals/...
	go run ./cmd/ggeval -config deploy/agent.yaml

trace-up: ## Start the local trace stack (OTel Collector + Tempo + ClickHouse + Grafana)
	docker compose -f detections/docker-compose.yaml up -d

trace-down: ## Stop the local trace stack
	docker compose -f detections/docker-compose.yaml down

detect: ## Run the trace-query detection demo over the OWASP pairs (fenced)
	go run ./cmd/gopherguard-vuln --i-understand-this-is-insecure --detect

deploy: ## Show the eval-gated Cloud Run canary pipeline (deploy/deploy.sh --execute to run it)
	bash deploy/deploy.sh --plan

tidy: ## Tidy go.mod/go.sum
	go mod tidy

fmt: ## Format all Go source
	go fmt ./...

vet: ## Run go vet across the module
	go vet ./...

ollama-setup: ## Onboarding: pull and start the local Gemma model via Ollama
	@echo "Run the following to set up local Gemma inference:"
	@echo "  ollama pull gemma2:2b"
	@echo "  ollama serve"

hooks: ## Install the pre-commit secret scan (run once per clone)
	git config core.hooksPath .githooks
	@echo "pre-commit secret scan installed (core.hooksPath = .githooks)"

help: ## Show this help
	@echo "gopherguard make targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
