#!/bin/bash

echo "🚀 Phillet Wallet Core gRPC Demo"
echo "================================"

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
    exit 1
fi

echo "✅ gRPC API test successful"

# Stop server
echo ""
echo "🛑 Stopping gRPC server..."
kill $SERVER_PID 2>/dev/null

echo ""
echo "🎉 gRPC Demo completed successfully!"
echo ""
echo "Next steps:"
echo "1. Run 'make grpc-server' to start the gRPC server"
echo "2. Run 'make grpc-client' to test the gRPC client"
echo "3. Use tools like grpcurl or BloomRPC to test the API"
echo "4. Check the README.md for more information" 