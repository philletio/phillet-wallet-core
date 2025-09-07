# Phillet Wallet Core

Core wallet service for the Philosopher's Wallet platform, providing HD wallet management, transaction signing, and multi-chain support.

## 🚀 Current Status

**Этап 0 - Подготовка: ЗАВЕРШЕН ✅**
- ✅ Базовая структура проекта создана
- ✅ HD-кошелек с генерацией мнемонических фраз
- ✅ Поддержка импорта существующих кошельков
- ✅ Генерация Ethereum адресов
- ✅ Подпись и верификация сообщений
- ✅ CLI интерфейс для тестирования
- ✅ Полный набор тестов

**Этап 1 - Core Wallet & Auth: В ПРОГРЕССЕ 🔄**
- ✅ **gRPC API** - ПОЛНОСТЬЮ ЗАВЕРШЕН
- 🔄 JWT аутентификация
- 🔄 База данных PostgreSQL
- ⏳ Solana поддержка
- ⏳ HSM интеграция

## Features

- **HD Wallet Management**: BIP-32/44 hierarchical deterministic wallet generation
- **Multi-Chain Support**: Ethereum (работает), Polygon, BSC, Solana, TON (планируется)
- **Secure Key Management**: Mnemonic generation and import with passphrase support
- **Transaction Signing**: ECDSA signature support
- **gRPC API**: High-performance RPC interface with full wallet operations
- **CLI Interface**: Interactive command-line interface for testing
- **Comprehensive Testing**: Full test coverage for wallet operations

## Quick Start

### Prerequisites

- Go 1.21+
- Git
- Protocol Buffers compiler (protoc)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/philletio/phillet-wallet-core.git
   cd phillet-wallet-core
   ```

2. **Install dependencies**
   ```bash
   make deps
   ```

3. **Generate protobuf code**
   ```bash
   make proto
   ```

4. **Build the application**
   ```bash
   make build
   ```

5. **Run the demo**
   ```bash
   # CLI demo
   ./demo.sh
   
   # gRPC demo
   ./demo_grpc.sh
   ```

### Interactive Mode

```bash
./bin/phillet-wallet-core
```

Выберите опцию:
1. **Generate new wallet** - создать новый кошелек
2. **Import existing wallet** - импортировать существующий кошелек
3. **Start server mode** - запустить серверный режим

### gRPC Server

```bash
# Start gRPC server
make grpc-server

# Or directly
./bin/phillet-wallet-grpc
```

### gRPC Client Testing

```bash
# Test gRPC API
make grpc-client

# Or directly
./bin/phillet-wallet-client
```

## gRPC API

### Service Definition

```protobuf
service WalletService {
  rpc GenerateWallet(GenerateWalletRequest) returns (GenerateWalletResponse);
  rpc ImportWallet(ImportWalletRequest) returns (ImportWalletResponse);
  rpc GetAddresses(GetAddressesRequest) returns (GetAddressesResponse);
  rpc SignTransaction(SignTransactionRequest) returns (SignTransactionResponse);
  rpc SignMessage(SignMessageRequest) returns (SignMessageResponse);
  rpc VerifySignature(VerifySignatureRequest) returns (VerifySignatureResponse);
  rpc GetBalance(GetBalanceRequest) returns (GetBalanceResponse);
  rpc GetWalletInfo(GetWalletInfoRequest) returns (GetWalletInfoResponse);
}
```

### Example Usage

```go
// Connect to gRPC server
conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
client := proto.NewWalletServiceClient(conn)

// Generate new wallet
resp, err := client.GenerateWallet(ctx, &proto.GenerateWalletRequest{
    UserId:   "user123",
    Chains:   []proto.Chain{proto.Chain_CHAIN_ETHEREUM},
    WordCount: 24,
})

// Sign message
signResp, err := client.SignMessage(ctx, &proto.SignMessageRequest{
    WalletId:    resp.WalletId,
    Message:     []byte("Hello, World!"),
    AddressIndex: 0,
    Chain:       proto.Chain_CHAIN_ETHEREUM,
})
```

## Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run gRPC tests
make grpc-client

# Run all checks
make check
```

## Project Structure

```
phillet-wallet-core/
├── cmd/                    # Application entry points
│   ├── main.go            # CLI interface
│   ├── grpc_server.go     # gRPC server
│   └── grpc_client.go     # gRPC client for testing
├── internal/              # Private application code
│   ├── wallet/            # HD wallet implementation
│   │   ├── wallet.go      # Core wallet functionality
│   │   └── wallet_test.go # Tests
│   └── service/           # gRPC service implementation
│       └── wallet_service.go
├── api/                   # API definitions
│   └── proto/             # Protocol buffers
│       ├── wallet.proto   # API definition
│       ├── wallet.pb.go   # Generated Go code
│       └── wallet_grpc.pb.go # Generated gRPC code
├── bin/                   # Build artifacts
├── demo.sh               # CLI demo script
├── demo_grpc.sh          # gRPC demo script
├── Makefile              # Build automation
├── Dockerfile            # Container configuration
└── README.md             # This file
```

## API Reference

### Wallet Generation

```go
// Create new HD wallet
wallet, err := wallet.NewHDWallet("user123")
if err != nil {
    log.Fatal(err)
}

// Get mnemonic phrase
mnemonic := wallet.GetMnemonic()

// Generate Ethereum address
address, privateKey, err := wallet.GenerateEthereumAddress(0)
```

### Wallet Import

```go
// Import existing wallet
mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
wallet, err := wallet.ImportHDWallet(mnemonic, "user123")
```

### Message Signing

```go
// Sign message
message := []byte("Hello, Philosopher's Wallet!")
signature, err := wallet.SignMessage(message, privateKey)

// Verify signature
valid, err := wallet.VerifySignature(message, signature, address)
```

## Development

### Available Commands

```bash
make help              # Show all available commands
make build             # Build the application
make test              # Run tests
make test-coverage     # Run tests with coverage
make clean             # Clean build artifacts
make proto             # Generate protobuf code
make demo              # Run CLI demo script
make grpc-server       # Build and run gRPC server
make grpc-client       # Build and run gRPC client
make deps              # Install dependencies
make setup             # Setup development environment
make check             # Run all tests and checks
```

### Code Quality

```bash
# Run linters (when configured)
make lint

# Run security scans (when configured)
make security-scan
```

## Security

### Key Management

- Private keys are never stored in plain text
- Mnemonics are generated using cryptographically secure entropy
- Secure key derivation using BIP-39 standard
- Message signing with ECDSA

### Best Practices

1. **Environment Variables**: Use strong, unique secrets
2. **Network Security**: Use TLS for all connections
3. **Access Control**: Implement proper RBAC
4. **Audit Logging**: Log all wallet operations
5. **Regular Updates**: Keep dependencies updated

## Roadmap

### Completed ✅
- [x] HD wallet generation (BIP-39)
- [x] Mnemonic import/export
- [x] Ethereum address generation
- [x] Message signing and verification
- [x] CLI interface
- [x] Comprehensive testing
- [x] **gRPC API** - Full implementation

### In Progress 🔄
- [ ] JWT authentication
- [ ] PostgreSQL integration
- [ ] Multi-chain support (Solana, Polygon, BSC)

### Planned ⏳
- [ ] Hardware Security Module (HSM) integration
- [ ] Advanced transaction types
- [ ] Multi-signature support
- [ ] Performance optimizations
- [ ] Docker containerization
- [ ] Kubernetes deployment

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run linting and tests
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:

- Create an issue on GitHub
- Check the documentation
- Review the test examples

---

**Philosopher's Wallet** - The IDE for crypto operations 🧠⚡ 