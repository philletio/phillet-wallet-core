#!/bin/bash

echo "🚀 Phillet Wallet Core - Full Demo"
echo "=================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Build the application
echo "📦 Building application..."
make build

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful"

# Run tests
echo ""
echo "🧪 Running tests..."
make test

if [ $? -ne 0 ]; then
    echo "❌ Tests failed"
    exit 1
fi

echo "✅ All tests passed"

# Start database services
echo ""
echo "🗄️  Starting database services..."
make db-up

# Wait for database to be ready
echo "⏳ Waiting for database to be ready..."
sleep 10

# Test database connection
echo ""
echo "🔌 Testing database connection..."
# TODO: Add database connection test when repository is integrated

# Start gRPC server in background
echo ""
echo "🌐 Starting gRPC server..."
./bin/phillet-wallet-grpc &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Test gRPC client
echo ""
echo "🔧 Testing gRPC API..."
./bin/phillet-wallet-client

if [ $? -ne 0 ]; then
    echo "❌ gRPC client test failed"
    kill $SERVER_PID 2>/dev/null
    make db-down
    exit 1
fi

echo "✅ gRPC API test successful"

# Test JWT functionality
echo ""
echo "🔐 Testing JWT authentication..."
go test ./internal/auth -v

if [ $? -ne 0 ]; then
    echo "❌ JWT tests failed"
    kill $SERVER_PID 2>/dev/null
    make db-down
    exit 1
fi

echo "✅ JWT authentication test successful"

# Test configuration
echo ""
echo "⚙️  Testing configuration..."
go test ./internal/config -v

if [ $? -ne 0 ]; then
    echo "❌ Configuration tests failed"
    kill $SERVER_PID 2>/dev/null
    make db-down
    exit 1
fi

echo "✅ Configuration test successful"

# Stop server
echo ""
echo "🛑 Stopping gRPC server..."
kill $SERVER_PID 2>/dev/null

# Show available services
echo ""
echo "📊 Available Services:"
echo "  - PostgreSQL: localhost:5432"
echo "  - Redis: localhost:6379"
echo "  - gRPC Server: localhost:50051"
echo "  - pgAdmin: http://localhost:8080 (admin@phillet.io / admin123)"

# Stop database services
echo ""
echo "🗄️  Stopping database services..."
make db-down

echo ""
echo "🎉 Full Demo completed successfully!"
echo ""
echo "Next steps:"
echo "1. Run 'make dev' to start development environment"
echo "2. Run 'make dev-full' to start with pgAdmin and API Gateway"
echo "3. Check the README.md for more information"
echo "4. Explore the source code in internal/" 