.DEFAULT_GOAL := help

.PHONY: build run run-vuln test eval trace-up deploy tidy fmt vet ollama-setup help

build: ## Build hardened and vulnerable binaries into ./bin
	go build -o bin/gopherguard ./cmd/gopherguard
	go build -o bin/gopherguard-vuln ./cmd/gopherguard-vuln

run: ## Start hardened-mode agent on local Gemma, no API key needed
	go run ./cmd/gopherguard

run-vuln: ## Start fenced vulnerable-mode lab (localhost only)
	go run ./cmd/gopherguard-vuln --i-understand-this-is-insecure

test: ## Run the test suite
	go test ./...

eval: ## Run the eval suite (gates CI/CD)
	@echo "eval suite: implemented in M4"
	@exit 0

trace-up: ## Start local trace stack (Grafana/Tempo)
	@echo "trace stack (Grafana/Tempo): implemented in M3"
	@exit 0

deploy: ## Run the deploy pipeline (hardened only, never vuln mode)
	@echo "deploy pipeline: implemented in M4"
	@exit 0

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

help: ## Show this help
	@echo "gopherguard make targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
