.DEFAULT_GOAL := help

.PHONY: help

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build environment
	docker build \
	 --no-cache \
	 --file ./build/Dockerfile \
	 --target production-stage \
	 --tag go-lock:production \
	 .

.PHONY: run
run: ## Run build environment
	docker run \
	 -it \
	 --rm \
	 --publish 8080:8080 \
	 --volume ${PWD}:/app \
	 --env-file ./config/.env \
	 go-lock:production

.PHONY: dev
dev: ## Run build environment
	docker build \
	 --file ./build/Dockerfile \
	 --target development-stage \
	 --tag go-lock:development \
	 .
	docker run \
	 --rm \
	 -it \
	 --publish 8080:8080 \
	 --volume ${PWD}:/app \
	 --env-file ./config/.env \
	 go-lock:development

.PHONY: test
test: ## Run build environment
	docker build \
	 --file build/Dockerfile \
	 --tag go-lock-test \
	 --progress plain --no-cache \
	 --target test-stage \
	 .