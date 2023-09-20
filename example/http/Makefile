LOCAL_BIN_DIR := $(PWD)/bin

## golangci configuration
GOLANGCI_CONFIG_URL   := https://raw.githubusercontent.com/worldline-go/guide/main/lint/.golangci.yml
GOLANGCI_LINT_VERSION := v1.54.2
SWAG_VERSION := $(shell grep github.com/swaggo/swag go.mod | awk '{print $$2}')

.DEFAULT_GOAL := help

.PHONY: run-server run-client run keycloak docs golangci lint test coverage clean help

run-server: export ACTION := server-echo
run-server: run ## Run the application server echo
run-server-http: export ACTION := server-http
run-server-http: run ## Run the application server echo

run-client: export ACTION_URL ?= http://localhost:3000/info
run-client: export ACTION := client
run-client: run ## Run the application client

run: ## Run the application
	@go run .

keycloak: ## Run keycloak container
	docker run -it --rm -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:20.0.2 start-dev

bin/swag-$(SWAG_VERSION):
	@echo "> downloading swag@$(SWAG_VERSION)"
	GOBIN=$(LOCAL_BIN_DIR) go install github.com/swaggo/swag/cmd/swag@$(SWAG_VERSION)
	mv $(LOCAL_BIN_DIR)/swag $(LOCAL_BIN_DIR)/swag-$(SWAG_VERSION)

docs: bin/swag-$(SWAG_VERSION) ## Generate docs
	@$(LOCAL_BIN_DIR)/swag-$(SWAG_VERSION) init -g echo.go

.golangci.yml:
	@$(MAKE) golangci

golangci: ## Download .golangci.yml file
	@curl --insecure -o .golangci.yml -L'#' $(GOLANGCI_CONFIG_URL)

bin/golangci-lint-$(GOLANGCI_LINT_VERSION):
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LOCAL_BIN_DIR) $(GOLANGCI_LINT_VERSION)
	@mv $(LOCAL_BIN_DIR)/golangci-lint $(LOCAL_BIN_DIR)/golangci-lint-$(GOLANGCI_LINT_VERSION)

lint: .golangci.yml bin/golangci-lint-$(GOLANGCI_LINT_VERSION) ## Lint Go files
	@$(LOCAL_BIN_DIR)/golangci-lint-$(GOLANGCI_LINT_VERSION) --version
	@GOPATH="$(shell dirname $(PWD))" $(LOCAL_BIN_DIR)/golangci-lint-$(GOLANGCI_LINT_VERSION) run ./...

test: ## Run unit tests
	@go test -v -race ./...

coverage: ## Run unit tests with coverage
	@go test -v -race -cover -coverpkg=./... -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -func=coverage.out

html: ## Show html coverage result
	@go tool cover -html=./coverage.out

html-gen: ## Export html coverage result
	@go tool cover -html=./coverage.out -o ./coverage.html

html-wsl: html-gen ## Open html coverage result in wsl
	@explorer.exe `wslpath -w ./coverage.html` || true

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
