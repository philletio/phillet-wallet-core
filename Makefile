# Phillet Wallet Core Makefile

.PHONY: help build test clean proto docker-build docker-run lint security-scan demo grpc-server grpc-client

# Default target
help:
	@echo "Available commands:"
	@echo "  build         - Build the application"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  clean         - Clean build artifacts"
	@echo "  proto         - Generate protobuf code"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo "  lint          - Run linters"
	@echo "  security-scan - Run security scans"
	@echo "  demo          - Run demo script"
	@echo "  grpc-server   - Build and run gRPC server"
	@echo "  grpc-client   - Build and run gRPC client"

# Build the application
build:
	@echo "Building Phillet Wallet Core..."
	go build -o bin/phillet-wallet-cli ./cmd/cli
	go build -o bin/phillet-wallet-grpc ./cmd/grpc-server
	go build -o bin/phillet-wallet-client ./cmd/grpc-client
	@echo "✅ Build completed"

# Run tests
test:
	@echo "Running tests..."
	go test ./internal/wallet -v
	@echo "✅ Tests completed"

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test ./internal/wallet -cover
	@echo "✅ Tests with coverage completed"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -f api/proto/*.pb.go
	@echo "✅ Clean completed"

# Generate protobuf code
proto:
	@echo "Generating protobuf code..."
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/proto/wallet.proto
	@echo "✅ Protobuf code generated"

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t phillet-wallet-core .
	@echo "✅ Docker image built"

# Run Docker container
docker-run:
	@echo "Running Docker container..."
	docker run -p 50051:50051 phillet-wallet-core
	@echo "✅ Docker container running"

# Run linters
lint:
	@echo "Running linters..."
	golangci-lint run
	@echo "✅ Linting completed"

# Run security scans
security-scan:
	@echo "Running security scans..."
	gosec ./...
	@echo "✅ Security scan completed"

# Run demo script
demo:
	@echo "Running demo..."
	./demo.sh
	@echo "✅ Demo completed"

# Build and run gRPC server
grpc-server: build
	@echo "Starting gRPC server..."
	./bin/phillet-wallet-grpc

# Build and run gRPC client
grpc-client: build
	@echo "Running gRPC client tests..."
	./bin/phillet-wallet-client

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod tidy
	go get google.golang.org/grpc
	go get google.golang.org/protobuf
	go get github.com/ethereum/go-ethereum/crypto
	go get github.com/tyler-smith/go-bip39
	@echo "✅ Dependencies installed"

# Setup development environment
setup: deps proto
	@echo "Setting up development environment..."
	@echo "✅ Development environment ready"

# Database commands
db-up:
	@echo "Starting database services..."
	docker-compose up -d postgres redis
	@echo "✅ Database services started"

db-down:
	@echo "Stopping database services..."
	docker-compose down
	@echo "✅ Database services stopped"

db-reset:
	@echo "Resetting database..."
	docker-compose down -v
	docker-compose up -d postgres redis
	@echo "✅ Database reset completed"

db-migrate:
	@echo "Running database migrations..."
	@docker-compose exec postgres psql -U postgres -d phillet_wallet -f /docker-entrypoint-initdb.d/001_initial_schema.sql
	@echo "✅ Database migrations completed"

db-migrate-local:
	@echo "Running database migrations locally..."
	@psql -h localhost -U postgres -d phillet_wallet -f migrations/001_initial_schema.sql
	@echo "✅ Database migrations completed"

db-migrate-status:
	@echo "Checking migration status..."
	@docker-compose exec postgres psql -U postgres -d phillet_wallet -c "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';"
	@echo "✅ Migration status checked"

# Development environment
dev: db-up
	@echo "Starting development environment..."
	docker-compose up wallet-core
	@echo "✅ Development environment started"

dev-full: db-up
	@echo "Starting full development environment..."
	docker-compose --profile tools --profile gateway up
	@echo "✅ Full development environment started"

# Run all tests and checks
check: test lint security-scan
	@echo "✅ All checks passed" 