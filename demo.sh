#!/bin/bash

echo "🚀 Phillet Wallet Core Demo"
echo "=========================="

# Build the application
echo "📦 Building application..."
go build -o bin/phillet-wallet-core ./cmd

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful"

# Run tests
echo ""
echo "🧪 Running tests..."
go test ./internal/wallet -v

if [ $? -ne 0 ]; then
    echo "❌ Tests failed"
    exit 1
fi

echo "✅ All tests passed"

# Demo wallet generation
echo ""
echo "🎯 Demo: Wallet Generation"
echo "=========================="

# Create a test wallet
echo "Generating test wallet..."
./bin/phillet-wallet-core << EOF
1
demo_user_123
EOF

echo ""
echo "🎉 Demo completed successfully!"
echo ""
echo "Next steps:"
echo "1. Run './bin/phillet-wallet-core' for interactive mode"
echo "2. Check the README.md for more information"
echo "3. Explore the source code in internal/wallet/" 