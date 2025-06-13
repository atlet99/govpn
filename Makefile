# Project-specific variables
BINARY_NAME := govpn
SERVER_BINARY := govpn-server
CLIENT_BINARY := govpn-client
CERTS_BINARY := govpn-certs
DEV_API_BINARY := govpn-dev-api
OUTPUT_DIR := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
SERVER_CMD_DIR := cmd/server
CLIENT_CMD_DIR := cmd/client
CERTS_CMD_DIR := cmd/generate_certs
DEV_API_CMD_DIR := cmd/dev-api
CERTS_DIR := certs
WEB_DIR := web
GOPATH ?= $(shell go env GOPATH)
GOLANGCI_LINT = $(GOPATH)/bin/golangci-lint
STATICCHECK = $(GOPATH)/bin/staticcheck

# Docker-specific variables
DOCKER_COMPOSE_FILE := docker/docker-compose.full.yml
DOCKER_COMPOSE_CMD := docker-compose -f $(DOCKER_COMPOSE_FILE)
DOCKER_SERVER_IMAGE := docker-govpn-server
DOCKER_CLIENT_IMAGE := docker-govpn-test-client

# Ensure the output directory exists
$(OUTPUT_DIR):
	@mkdir -p $(OUTPUT_DIR)

# Ensure certificates directory exists
$(CERTS_DIR):
	@mkdir -p $(CERTS_DIR)

# Default target
.PHONY: default
default: fmt vet lint staticcheck build test

# Development environment setup
.PHONY: dev-setup
dev-setup: install-deps install-lint install-staticcheck
	@echo "Setting up development environment..."
	@cd $(WEB_DIR) && npm install

# Start development environment (API + Web)
.PHONY: dev-start
dev-start: build-dev-api
	@echo "Starting development environment..."
	@./$(OUTPUT_DIR)/$(DEV_API_BINARY) -port 8080 -host 127.0.0.1 & \
	cd $(WEB_DIR) && npm run dev

# Build development API server
.PHONY: build-dev-api
build-dev-api: $(OUTPUT_DIR)
	@echo "Building development API server..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(DEV_API_BINARY) ./$(DEV_API_CMD_DIR)

# Build and run the certificate generator
.PHONY: generate-certs
generate-certs: $(CERTS_DIR)
	@echo "Generating certificates..."
	go run ./$(CERTS_CMD_DIR) -out $(CERTS_DIR)

# Build the certificate generator
.PHONY: build-certs
build-certs: $(OUTPUT_DIR)
	@echo "Building $(CERTS_BINARY) with version $(VERSION)..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(CERTS_BINARY) ./$(CERTS_CMD_DIR)

# Build and run the server locally
.PHONY: run-server
run-server:
	@echo "Running $(SERVER_BINARY)..."
	go run ./$(SERVER_CMD_DIR)

# Build and run the client locally
.PHONY: run-client
run-client:
	@echo "Running $(CLIENT_BINARY)..."
	go run ./$(CLIENT_CMD_DIR)

# Run all tests with race detection and coverage
.PHONY: test-with-race
test-with-race:
	@echo "Running all tests with race detection and coverage..."
	go test -v -race -cover ./...

# Run all tests with basic testing
.PHONY: test
test: migrate-testdb
	go test -v ./... -cover

# Install project dependencies
.PHONY: install-deps
install-deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod vendor

# Upgrade all project dependencies to their latest versions
.PHONY: upgrade-deps
upgrade-deps:
	@echo "Upgrading all dependencies to latest versions..."
	go get -u ./...
	go mod tidy
	go mod vendor
	@echo "Dependencies upgraded. Please test thoroughly before committing!"

# Clean up dependencies
.PHONY: clean-deps
clean-deps:
	@echo "Cleaning up vendor dependencies..."
	rm -rf vendor

# Build the server for the current OS/architecture
.PHONY: build-server
build-server: $(OUTPUT_DIR)
	@echo "Building $(SERVER_BINARY) with version $(VERSION)..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(SERVER_BINARY) ./$(SERVER_CMD_DIR)

# Build the client for the current OS/architecture
.PHONY: build-client
build-client: $(OUTPUT_DIR)
	@echo "Building $(CLIENT_BINARY) with version $(VERSION)..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(CLIENT_BINARY) ./$(CLIENT_CMD_DIR)

# Build all binaries
.PHONY: build
build: build-server build-client build-certs build-dev-api

# Build binaries for multiple platforms
.PHONY: build-cross
build-cross: $(OUTPUT_DIR)
	@echo "Building cross-platform binaries..."
	# Server binaries
	GOOS=linux   GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(SERVER_BINARY)-linux-amd64 ./$(SERVER_CMD_DIR)
	GOOS=darwin  GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(SERVER_BINARY)-darwin-amd64 ./$(SERVER_CMD_DIR)
	GOOS=darwin  GOARCH=arm64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(SERVER_BINARY)-darwin-arm64 ./$(SERVER_CMD_DIR)
	GOOS=windows GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(SERVER_BINARY)-windows-amd64.exe ./$(SERVER_CMD_DIR)
	
	# Client binaries
	GOOS=linux   GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(CLIENT_BINARY)-linux-amd64 ./$(CLIENT_CMD_DIR)
	GOOS=darwin  GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(CLIENT_BINARY)-darwin-amd64 ./$(CLIENT_CMD_DIR)
	GOOS=darwin  GOARCH=arm64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(CLIENT_BINARY)-darwin-arm64 ./$(CLIENT_CMD_DIR)
	GOOS=windows GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(CLIENT_BINARY)-windows-amd64.exe ./$(CLIENT_CMD_DIR)
	
	# Certificate generator binaries
	GOOS=linux   GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(CERTS_BINARY)-linux-amd64 ./$(CERTS_CMD_DIR)
	GOOS=darwin  GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(CERTS_BINARY)-darwin-amd64 ./$(CERTS_CMD_DIR)
	GOOS=darwin  GOARCH=arm64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(CERTS_BINARY)-darwin-arm64 ./$(CERTS_CMD_DIR)
	GOOS=windows GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(CERTS_BINARY)-windows-amd64.exe ./$(CERTS_CMD_DIR)
	
	# Development API server binaries
	GOOS=linux   GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(DEV_API_BINARY)-linux-amd64 ./$(DEV_API_CMD_DIR)
	GOOS=darwin  GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(DEV_API_BINARY)-darwin-amd64 ./$(DEV_API_CMD_DIR)
	GOOS=darwin  GOARCH=arm64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(DEV_API_BINARY)-darwin-arm64 ./$(DEV_API_CMD_DIR)
	GOOS=windows GOARCH=amd64   go build -ldflags="-X 'main.Version=$(VERSION)'" -o $(OUTPUT_DIR)/$(DEV_API_BINARY)-windows-amd64.exe ./$(DEV_API_CMD_DIR)
	
	@echo "Cross-platform binaries are available in $(OUTPUT_DIR):"
	@ls -1 $(OUTPUT_DIR)

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OUTPUT_DIR)

# Clean certificates
.PHONY: clean-certs
clean-certs:
	@echo "Cleaning certificates..."
	rm -rf $(CERTS_DIR)

# Clean web build artifacts
.PHONY: clean-web
clean-web:
	@echo "Cleaning web build artifacts..."
	@cd $(WEB_DIR) && rm -rf node_modules dist

# Check formatting of Go code
.PHONY: fmt
fmt:
	@echo "Checking code formatting..."
	@go fmt ./...

# Run go vet to analyze code
.PHONY: vet
vet:
	@echo "Running go vet..."
	go vet ./...

# Install golangci-lint
.PHONY: install-lint
install-lint:
	@echo "Installing golangci-lint..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Install staticcheck
.PHONY: install-staticcheck
install-staticcheck:
	@echo "Installing staticcheck..."
	@go install honnef.co/go/tools/cmd/staticcheck@latest

# Run linter
.PHONY: lint
lint:
	@if command -v $(GOLANGCI_LINT) >/dev/null 2>&1; then \
		echo "Running linter..."; \
		$(GOLANGCI_LINT) run; \
		echo "Linter passed!"; \
	else \
		echo "golangci-lint is not installed. Skipping linter. Run 'make install-lint' to install."; \
	fi

# Run staticcheck tool
.PHONY: staticcheck
staticcheck:
	@if command -v $(STATICCHECK) >/dev/null 2>&1; then \
		echo "Running staticcheck..."; \
		$(STATICCHECK) ./...; \
		echo "Staticcheck passed!"; \
	else \
		echo "staticcheck is not installed. Skipping staticcheck. Run 'make install-staticcheck' to install."; \
	fi

# Run all checks (linter and staticcheck)
.PHONY: check-all
check-all: lint staticcheck web-check
	@echo "All checks completed."

# Run linter with auto-fix
.PHONY: lint-fix
lint-fix:
	@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { echo "golangci-lint is not installed. Run make install-lint"; exit 1; }
	@echo "Running linter with auto-fix..."
	@$(GOLANGCI_LINT) run --fix

# Run tests with coverage report
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage report..."
	go test -v ./... -coverprofile=coverage.out && go tool cover -html=coverage.out

# Run benchmarks
.PHONY: benchmark
benchmark:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./... 

# Test database
.PHONY: createdb-test
createdb-test:
	@echo "Ensuring test database exists..."
	@psql -lqt | cut -d \| -f 1 | grep -qw govpn_test || createdb govpn_test

# Migrate test database
.PHONY: migrate-testdb
migrate-testdb: createdb-test
	@echo "Applying migrations to test database..."
	psql -d govpn_test -f pkg/storage/postgres/migrations/000001_init_test.up.sql

# Web check
.PHONY: web-check
web-check:
	@echo "Checking web build..."
	@cd $(WEB_DIR) && npm run type-check
	@echo "Web check completed!"

# ============================================================================
# Docker Operations
# ============================================================================

# Build Docker images
.PHONY: docker-build
docker-build:
	@echo "Building GoVPN Docker images..."
	$(DOCKER_COMPOSE_CMD) build govpn-server

# Build Docker images without cache
.PHONY: docker-build-clean
docker-build-clean:
	@echo "Building GoVPN Docker images (no cache)..."
	$(DOCKER_COMPOSE_CMD) build --no-cache --pull govpn-server

# Start Docker services
.PHONY: docker-up
docker-up:
	@echo "Starting GoVPN Docker services..."
	$(DOCKER_COMPOSE_CMD) up -d
	@echo "Services started successfully!"
	@echo ""
	@echo "Access points:"
	@echo "  GoVPN API:      http://localhost:8081"
	@echo "  GoVPN Metrics:  http://localhost:9090"
	@echo "  VPN Server:     localhost:1194 (UDP)"

# Stop Docker services
.PHONY: docker-down
docker-down:
	@echo "Stopping GoVPN Docker services..."
	$(DOCKER_COMPOSE_CMD) down

# Restart Docker services
.PHONY: docker-restart
docker-restart: docker-down docker-up

# Show Docker logs
.PHONY: docker-logs
docker-logs:
	@echo "Showing GoVPN server logs..."
	$(DOCKER_COMPOSE_CMD) logs -f govpn-server

# Show Docker logs (all services)
.PHONY: docker-logs-all
docker-logs-all:
	@echo "Showing all service logs..."
	$(DOCKER_COMPOSE_CMD) logs -f

# Get shell access to GoVPN container
.PHONY: docker-shell
docker-shell:
	@echo "Opening shell in GoVPN container..."
	docker exec -it govpn-real-server sh

# Check Docker service status
.PHONY: docker-status
docker-status:
	@echo "Docker service status:"
	$(DOCKER_COMPOSE_CMD) ps

# Clean Docker images and containers
.PHONY: docker-clean
docker-clean:
	@echo "Cleaning Docker containers and images..."
	$(DOCKER_COMPOSE_CMD) down
	docker image rm $(DOCKER_SERVER_IMAGE) -f 2>/dev/null || true
	docker image rm $(DOCKER_CLIENT_IMAGE) -f 2>/dev/null || true
	@echo "Docker cleanup completed."

# Full Docker cleanup (images, volumes, system)
.PHONY: docker-clean-full
docker-clean-full:
	@echo "Performing full Docker cleanup..."
	@echo "This will remove all containers, volumes and images!"
	$(DOCKER_COMPOSE_CMD) down -v --rmi all 2>/dev/null || true
	docker system prune -f
	@echo "Full Docker cleanup completed."

# Test Docker setup with OpenVPN client
.PHONY: docker-test
docker-test:
	@echo "Testing GoVPN Docker setup..."
	@echo "Running OpenVPN client test (10 second timeout)..."
	timeout 10 docker run --rm --network docker_govpn-full-network --cap-add=NET_ADMIN --device /dev/net/tun $(DOCKER_CLIENT_IMAGE) openvpn --config /etc/govpn/client/client.ovpn --verb 3 || echo "Test completed (expected timeout)"
	@echo ""
	@echo "Check server logs for connection attempts:"
	@echo "  make docker-logs"

# Build and test complete Docker setup
.PHONY: docker-dev-setup
docker-dev-setup: docker-clean-full docker-build-clean docker-up
	@echo "Waiting for services to start..."
	@sleep 5
	@echo ""
	@echo "Docker development environment ready!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Check logs: make docker-logs"
	@echo "2. Test setup: make docker-test"
	@echo "3. Access API: http://localhost:8081"

# Quick restart only GoVPN server
.PHONY: docker-restart-server
docker-restart-server:
	@echo "Restarting GoVPN server..."
	$(DOCKER_COMPOSE_CMD) restart govpn-server

# Display help information
.PHONY: help
help:
	@echo "GoVPN - OpenVPN Evolution in Go"
	@echo ""
	@echo "Available commands:"
	@echo "  Development Environment:"
	@echo "  ======================="
	@echo "  dev-setup            - Set up development environment (deps, tools, web)"
	@echo "  dev-start            - Start development environment (API + Web)"
	@echo "  build-dev-api        - Build development API server"
	@echo ""
	@echo "  Build and Run:"
	@echo "  =============="
	@echo "  default             - Run formatting, checks, linter, build and tests"
	@echo "  run-server          - Run server locally"
	@echo "  run-client          - Run client locally"
	@echo "  generate-certs      - Generate certificates for development/testing"
	@echo "  build               - Build all binaries for current OS/arch"
	@echo "  build-server        - Build server only"
	@echo "  build-client        - Build client only"
	@echo "  build-certs         - Build certificate generator only"
	@echo "  build-cross         - Build binaries for multiple platforms"
	@echo "  build-web           - Build web application"
	@echo "  createdb-test       - Create test database"
	@echo "  migrate-testdb      - Migrate test database"
	@echo ""
	@echo "  Testing:"
	@echo "  ========="
	@echo "  test                - Run all tests with standard coverage"
	@echo "  test-with-race      - Run all tests with race detection and coverage"
	@echo "  test-coverage       - Run tests with coverage report"
	@echo "  benchmark           - Run benchmarks"
	@echo "  web-check           - Check web build"
	@echo ""
	@echo "  Code Quality:"
	@echo "  ============="
	@echo "  fmt                 - Check and format code"
	@echo "  vet                 - Analyze code with go vet"
	@echo "  lint                - Run golangci-lint to check code"
	@echo "  lint-fix            - Run golangci-lint with auto-fix"
	@echo "  staticcheck         - Run staticcheck for static analysis"
	@echo "  check-all           - Run all code quality checks"
	@echo ""
	@echo "  Dependencies:"
	@echo "  ============"
	@echo "  install-deps        - Install project dependencies"
	@echo "  upgrade-deps        - Upgrade all project dependencies"
	@echo "  clean-deps          - Clean up vendor dependencies"
	@echo "  install-lint        - Install golangci-lint"
	@echo "  install-staticcheck - Install staticcheck"
	@echo ""
	@echo "  Cleaning:"
	@echo "  ========="
	@echo "  clean               - Clean build artifacts"
	@echo "  clean-certs         - Clean generated certificates"
	@echo "  clean-web           - Clean web build artifacts"
	@echo ""
	@echo "  Docker Operations:"
	@echo "  ================="
	@echo "  docker-build        - Build Docker images"
	@echo "  docker-up           - Start Docker services"
	@echo "  docker-down         - Stop Docker services"
	@echo "  docker-restart      - Restart Docker services"
	@echo "  docker-clean        - Clean Docker images and containers"
	@echo "  docker-clean-full   - Full Docker cleanup (images, volumes, system)"
	@echo "  docker-logs         - Show Docker logs"
	@echo "  docker-test         - Test Docker setup with OpenVPN client"
	@echo "  docker-shell        - Get shell access to GoVPN container"
	@echo ""
	@echo "Examples:"
	@echo "  make dev-setup      - Set up development environment"
	@echo "  make dev-start      - Start development environment"
	@echo "  make build          - Build all binaries"
	@echo "  make test           - Run tests"
	@echo "  make check-all      - Run all code quality checks"
	@echo "  make docker-build   - Build Docker images"
	@echo "  make docker-up      - Start Docker services"
	@echo "  make docker-test    - Test Docker setup"
