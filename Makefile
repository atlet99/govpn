# Project-specific variables
BINARY_NAME := govpn
SERVER_BINARY := govpn-server
CLIENT_BINARY := govpn-client
OUTPUT_DIR := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
SERVER_CMD_DIR := cmd/server
CLIENT_CMD_DIR := cmd/client

# Ensure the output directory exists
$(OUTPUT_DIR):
	@mkdir -p $(OUTPUT_DIR)

# Default target
.PHONY: default
default: fmt vet lint staticcheck build test

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
test:
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

# Build both server and client
.PHONY: build
build: build-server build-client

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
	
	@echo "Cross-platform binaries are available in $(OUTPUT_DIR):"
	@ls -1 $(OUTPUT_DIR)

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(OUTPUT_DIR)

# Run tests with coverage report
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage report..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run benchmarks
.PHONY: benchmark
benchmark:
	@echo "Running benchmarks..."
	go test -v -bench=. -benchmem ./...

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
	@echo "Running linter..."
	@~/go/bin/golangci-lint run

# Run staticcheck tool
.PHONY: staticcheck
staticcheck:
	@echo "Running staticcheck..."
	@~/go/bin/staticcheck ./...
	@echo "Staticcheck passed!"

# Run all checks (linter and staticcheck)
.PHONY: check-all
check-all: lint staticcheck
	@echo "All checks completed."

# Run linter with auto-fix
.PHONY: lint-fix
lint-fix:
	@echo "Running linter with auto-fix..."
	@golangci-lint run --fix

# Display help information
.PHONY: help
help:
	@echo "GoVPN - Эволюция OpenVPN на Go"
	@echo ""
	@echo "Доступные команды:"
	@echo "  Сборка и запуск:"
	@echo "  ================"
	@echo "  default         - Запуск форматирования, проверок, линтера, сборки и тестов"
	@echo "  run-server      - Запуск сервера локально"
	@echo "  run-client      - Запуск клиента локально"
	@echo "  build           - Сборка сервера и клиента для текущей ОС/архитектуры"
	@echo "  build-server    - Сборка только сервера"
	@echo "  build-client    - Сборка только клиента"
	@echo "  build-cross     - Сборка бинарных файлов для разных платформ"
	@echo ""
	@echo "  Тестирование:"
	@echo "  ============="
	@echo "  test            - Запуск всех тестов со стандартным покрытием"
	@echo "  test-with-race  - Запуск всех тестов с обнаружением гонок и покрытием"
	@echo "  test-coverage   - Запуск тестов с отчетом о покрытии"
	@echo "  benchmark       - Запуск бенчмарков"
	@echo ""
	@echo "  Качество кода:"
	@echo "  =============="
	@echo "  fmt             - Проверка и форматирование кода"
	@echo "  vet             - Анализ кода с помощью go vet"
	@echo "  lint            - Запуск golangci-lint для проверки кода"
	@echo "  lint-fix        - Запуск golangci-lint с автоисправлением"
	@echo "  staticcheck     - Запуск staticcheck для статического анализа кода"
	@echo "  check-all       - Запуск всех проверок качества кода"
	@echo ""
	@echo "  Зависимости:"
	@echo "  ============"
	@echo "  install-deps    - Установка зависимостей проекта"
	@echo "  upgrade-deps    - Обновление всех зависимостей проекта"
	@echo "  clean-deps      - Очистка зависимостей vendor"
	@echo "  install-lint    - Установка golangci-lint"
	@echo "  install-staticcheck - Установка staticcheck"
	@echo ""
	@echo "  Очистка:"
	@echo "  ========"
	@echo "  clean           - Очистка артефактов сборки"
	@echo ""
	@echo "Примеры:"
	@echo "  make build               - Сборка бинарных файлов"
	@echo "  make run-server          - Запуск сервера"
	@echo "  make test                - Запуск всех тестов"
	@echo "  make build-cross         - Сборка для разных платформ" 