.DEFAULT_GOAL := help

GOPATH := $(shell go env GOPATH)

# Load environment variables from .env file
include .env
export

.PHONY: help

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: up
up: # Start the development environment
	docker compose -f deploy/docker-compose.yaml up --detach --wait --build

.PHONY: down
down: # Stop the development environment
	docker compose -f deploy/docker-compose.yaml down

.PHONY: air
air: # Run the air live reloading tool
	go install github.com/air-verse/air@latest
	${GOPATH}/bin/air -c .air.toml

.PHONY: dev
dev: ## Run the development environment with database migration and live reloading
	docker compose -f deploy/docker-compose.yaml up --detach --wait --build db migrate
	${MAKE} air

.PHONY: build
build: ## Build the application
	go build -o tmp/main cmd/main.go

.PHONY: test
test: ## Run unit tests
	go test -v ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: test-race
test-race: ## Run tests with race detection
	go test -race -v ./...

.PHONY: test-integration
test-integration: ## Run integration tests (requires test database)
	go test -v -tags=integration ./...

.PHONY: bench
bench: ## Run benchmark tests
	go test -bench=. -benchmem ./...

.PHONY: lint
lint: ## Run linter
	golangci-lint run

.PHONY: fmt
fmt: ## Format code
	go fmt ./...
	goimports -w .

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: mod-tidy
mod-tidy: ## Tidy go modules
	go mod tidy

.PHONY: check
check: fmt vet lint test ## Run all checks (format, vet, lint, test)

.PHONY: docs
docs: ## Generate API documentation
	@echo "API documentation available at http://localhost:8080/docs"
	@echo "OpenAPI spec available at http://localhost:8080/api/openapi.yaml"

.PHONY: clean
clean: ## Clean build artifacts
	rm -f tmp/main coverage.out coverage.html

.PHONY: migrate-up
migrate-up: ## Run database migrations up
	go run cmd/main.go migrate up

.PHONY: migrate-down
migrate-down: ## Run database migrations down  
	go run cmd/main.go migrate down

.PHONY: migrate-create
migrate-create: ## Create new migration (usage: make migrate-create name=migration_name)
	@if [ -z "$(name)" ]; then echo "Usage: make migrate-create name=migration_name"; exit 1; fi
	go run cmd/main.go migrate create $(name)

.PHONY: install-tools
install-tools: ## Install development tools
	go install github.com/air-verse/air@latest
	go install golang.org/x/tools/cmd/goimports@latest
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin

.PHONY: docker-build
docker-build: ## Build Docker image
	docker build -f build/Dockerfile -t go-lock:latest .

.PHONY: docker-run
docker-run: ## Run Docker container
	docker run -p 8080:8080 --env-file .env go-lock:latest

.PHONY: security-scan
security-scan: ## Run security scan
	gosec ./...

# Cache-related targets
.PHONY: redis-start
redis-start: ## Start Redis for local development
	docker compose -f deploy/docker-compose.yaml up -d redis

.PHONY: redis-stop
redis-stop: ## Stop Redis
	docker compose -f deploy/docker-compose.yaml stop redis

.PHONY: cache-test
cache-test: ## Run cache tests (requires Redis)
	REDIS_TESTS=true go test -v ./internal/cache/...

.PHONY: cache-bench
cache-bench: ## Run cache benchmarks (requires Redis) 
	REDIS_TESTS=true go test -bench=. -benchmem ./internal/cache/...

.PHONY: cache-stats
cache-stats: ## Show Redis cache statistics
	docker exec -it $$(docker compose -f deploy/docker-compose.yaml ps -q redis) redis-cli info memory

# Helm deployment targets
.PHONY: helm-lint
helm-lint: ## Lint Helm chart
	helm lint deploy/helm/go-lock

.PHONY: helm-template
helm-template: ## Generate Kubernetes manifests from Helm chart
	helm template go-lock deploy/helm/go-lock --values deploy/helm/go-lock/values.yaml

.PHONY: helm-template-dev
helm-template-dev: ## Generate Kubernetes manifests for development
	helm template go-lock-dev deploy/helm/go-lock --values deploy/helm/go-lock/values-dev.yaml

.PHONY: helm-install-dev
helm-install-dev: ## Install Helm chart for development
	helm upgrade --install go-lock-dev deploy/helm/go-lock \
		--values deploy/helm/go-lock/values-dev.yaml \
		--create-namespace \
		--namespace go-lock-dev

.PHONY: helm-install-prod
helm-install-prod: ## Install Helm chart for production
	@echo "⚠️  Please review and update secrets in values-prod.yaml before deploying to production!"
	helm upgrade --install go-lock-prod deploy/helm/go-lock \
		--values deploy/helm/go-lock/values-prod.yaml \
		--create-namespace \
		--namespace go-lock-prod

.PHONY: helm-uninstall-dev
helm-uninstall-dev: ## Uninstall development Helm release
	helm uninstall go-lock-dev --namespace go-lock-dev

.PHONY: helm-uninstall-prod
helm-uninstall-prod: ## Uninstall production Helm release
	helm uninstall go-lock-prod --namespace go-lock-prod

.PHONY: k8s-deploy
k8s-deploy: ## Deploy using raw Kubernetes manifests
	kubectl apply -f deploy/kubernetes/

.PHONY: k8s-delete
k8s-delete: ## Delete Kubernetes deployment
	kubectl delete -f deploy/kubernetes/

.PHONY: all
all: clean fmt vet lint test build ## Run full build pipeline