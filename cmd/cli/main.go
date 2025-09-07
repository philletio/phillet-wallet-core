package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/philletio/phillet-wallet-core/internal/wallet"
)

func main() {
	fmt.Println("=== Phillet Wallet Core ===")
	fmt.Println("1. Generate new wallet")
	fmt.Println("2. Import existing wallet")
	fmt.Println("3. Start server mode")
	fmt.Print("Choose option (1-3): ")

	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		generateWallet(reader)
	case "2":
		importWallet(reader)
	case "3":
		startServer()
	default:
		fmt.Println("Invalid choice. Exiting.")
	}
}

func generateWallet(reader *bufio.Reader) {
	fmt.Print("Enter user ID: ")
	userID, _ := reader.ReadString('\n')
	userID = strings.TrimSpace(userID)

	if userID == "" {
		fmt.Println("User ID cannot be empty")
		return
	}

	// Generate new wallet
	wallet, err := wallet.NewHDWallet(userID)
	if err != nil {
		log.Fatalf("Failed to generate wallet: %v", err)
	}

	fmt.Println("\n=== Generated Wallet ===")
	fmt.Printf("User ID: %s\n", wallet.GetUserID())
	fmt.Printf("Mnemonic: %s\n", wallet.GetMnemonic())
	fmt.Println("\n⚠️  IMPORTANT: Save this mnemonic phrase securely!")
	fmt.Println("   It's the only way to recover your wallet.")

	// Generate Ethereum address
	address, _, err := wallet.GenerateEthereumAddress(0)
	if err != nil {
		log.Printf("Failed to generate address: %v", err)
	} else {
		fmt.Printf("Ethereum Address: %s\n", address)
	}
}

func importWallet(reader *bufio.Reader) {
	fmt.Print("Enter user ID: ")
	userID, _ := reader.ReadString('\n')
	userID = strings.TrimSpace(userID)

	if userID == "" {
		fmt.Println("User ID cannot be empty")
		return
	}

	fmt.Print("Enter mnemonic phrase: ")
	mnemonic, _ := reader.ReadString('\n')
	mnemonic = strings.TrimSpace(mnemonic)

	if mnemonic == "" {
		fmt.Println("Mnemonic cannot be empty")
		return
	}

	// Import wallet
	wallet, err := wallet.ImportHDWallet(mnemonic, userID)
	if err != nil {
		log.Fatalf("Failed to import wallet: %v", err)
	}

	fmt.Println("\n=== Imported Wallet ===")
	fmt.Printf("User ID: %s\n", wallet.GetUserID())
	fmt.Printf("Mnemonic: %s\n", wallet.GetMnemonic())

	// Generate Ethereum address
	address, _, err := wallet.GenerateEthereumAddress(0)
	if err != nil {
		log.Printf("Failed to generate address: %v", err)
	} else {
		fmt.Printf("Ethereum Address: %s\n", address)
	}
}

func startServer() {
	fmt.Println("Starting Phillet Wallet Core server...")

	// Simple TCP server for now
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Starting server on :50051")

	// Graceful shutdown
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				log.Printf("Accept error: %v", err)
				return
			}
			log.Printf("New connection from: %s", conn.RemoteAddr())
			conn.Close()
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	lis.Close()
}
