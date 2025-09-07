package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/philletio/phillet-wallet-core/api/proto"
	"github.com/philletio/phillet-wallet-core/internal/config"
	"github.com/philletio/phillet-wallet-core/internal/repository"
	"github.com/philletio/phillet-wallet-core/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func startGRPCServer() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database connection
	db, err := repository.NewPostgresConnection(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize repository
	repo := repository.NewPostgresRepository(db)

	// Test database connection
	ctx := context.Background()
	if err := repo.Ping(ctx); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("Successfully connected to database")

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Create wallet service with repository and config
	walletService := service.NewWalletService(repo, cfg)

	// Register wallet service
	proto.RegisterWalletServiceServer(grpcServer, walletService)

	// Enable reflection for development
	reflection.Register(grpcServer)

	// Start gRPC server
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.GRPCPort))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Starting gRPC server on port %d", cfg.Server.GRPCPort)

	// Graceful shutdown
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down gRPC server...")
	grpcServer.GracefulStop()
}

func main() {
	fmt.Println("=== Phillet Wallet Core gRPC Server ===")
	fmt.Println("Starting gRPC server...")

	startGRPCServer()
}
