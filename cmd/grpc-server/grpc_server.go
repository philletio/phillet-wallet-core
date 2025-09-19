package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/philletio/phillet-wallet-core/api/proto"
	"github.com/philletio/phillet-wallet-core/internal/config"
	"github.com/philletio/phillet-wallet-core/internal/ratelimit"
	"github.com/philletio/phillet-wallet-core/internal/repository"
	"github.com/philletio/phillet-wallet-core/internal/service"
	redis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func startGRPCServer() {
	// Load configuration
	cfg := config.Load()

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

	// Create rate limiter
	rateLimiter := ratelimit.NewRateLimiter(&ratelimit.Config{
		DefaultRate:  10.0, // 10 requests per second
		DefaultBurst: 20,   // burst of 20 requests
		MethodLimits: map[string]ratelimit.MethodLimit{
			"/phillet.wallet.WalletService/GenerateWallet": {
				Rate:  5.0, // 5 requests per second for wallet generation
				Burst: 10,
			},
			"/phillet.wallet.WalletService/ImportWallet": {
				Rate:  5.0, // 5 requests per second for wallet import
				Burst: 10,
			},
			"/phillet.wallet.WalletService/SignMessage": {
				Rate:  20.0, // 20 requests per second for signing
				Burst: 50,
			},
			"/phillet.wallet.WalletService/SignTransaction": {
				Rate:  15.0, // 15 requests per second for transaction signing
				Burst: 30,
			},
		},
		CleanupInterval: 5 * time.Minute,
	})

	// Create gRPC server with rate limiting interceptor
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(ratelimit.RateLimitInterceptor(rateLimiter)),
	)

	// Create wallet service with repository and config
	walletService := service.NewWalletService(repo, cfg)

	// Initialize Redis cache if configured
	if cfg.Cache.RedisAddr != "" {
		cache := redis.NewClient(&redis.Options{
			Addr:     cfg.Cache.RedisAddr,
			Password: cfg.Cache.RedisPassword,
			DB:       cfg.Cache.RedisDB,
		})
		if err := cache.Ping(ctx).Err(); err != nil {
			log.Printf("Redis not available: %v", err)
		} else {
			walletService = walletService.WithCache(cache)
			log.Println("Redis cache enabled")
		}
	}

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
