package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/philletio/phillet-wallet-core/api/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	fmt.Println("=== Phillet Wallet Core gRPC Client ===")

	// Connect to gRPC server
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Create client
	client := proto.NewWalletServiceClient(conn)

	// Set timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// Test 1: Generate new wallet
	fmt.Println("\n1. Testing GenerateWallet...")
	generateResp, err := client.GenerateWallet(ctx, &proto.GenerateWalletRequest{
		UserId:    "test_user_123",
		Chains:    []proto.Chain{proto.Chain_CHAIN_ETHEREUM},
		WordCount: 24,
	})
	if err != nil {
		log.Printf("GenerateWallet failed: %v", err)
	} else {
		fmt.Printf("✅ Generated wallet: %s\n", generateResp.WalletId)
		fmt.Printf("   Mnemonic: %s\n", generateResp.Mnemonic)
		fmt.Printf("   Addresses: %d\n", len(generateResp.Addresses))
		for _, addr := range generateResp.Addresses {
			fmt.Printf("   - %s: %s\n", addr.Chain, addr.Address)
		}
	}

	// Test 2: Get wallet info
	if generateResp != nil {
		fmt.Println("\n2. Testing GetWalletInfo...")
		infoResp, err := client.GetWalletInfo(ctx, &proto.GetWalletInfoRequest{
			WalletId: generateResp.WalletId,
		})
		if err != nil {
			log.Printf("GetWalletInfo failed: %v", err)
		} else {
			fmt.Printf("✅ Wallet info: User=%s, Chains=%d, Addresses=%d\n",
				infoResp.UserId, len(infoResp.SupportedChains), infoResp.AddressCount)
		}

		// Test 3: Sign message
		fmt.Println("\n3. Testing SignMessage...")
		message := []byte("Hello, Philosopher's Wallet!")
		signResp, err := client.SignMessage(ctx, &proto.SignMessageRequest{
			WalletId:     generateResp.WalletId,
			Message:      message,
			AddressIndex: 0,
			Chain:        proto.Chain_CHAIN_ETHEREUM,
		})
		if err != nil {
			log.Printf("SignMessage failed: %v", err)
		} else {
			fmt.Printf("✅ Message signed: %s\n", signResp.SignatureHex)

			// Test 4: Verify signature
			fmt.Println("\n4. Testing VerifySignature...")
			verifyResp, err := client.VerifySignature(ctx, &proto.VerifySignatureRequest{
				Message:   message,
				Signature: signResp.Signature,
				Address:   generateResp.Addresses[0].Address,
				Chain:     proto.Chain_CHAIN_ETHEREUM,
			})
			if err != nil {
				log.Printf("VerifySignature failed: %v", err)
			} else {
				fmt.Printf("✅ Signature verified: %t\n", verifyResp.IsValid)
			}
		}

		// Test 5: Get addresses
		fmt.Println("\n5. Testing GetAddresses...")
		addressesResp, err := client.GetAddresses(ctx, &proto.GetAddressesRequest{
			WalletId:   generateResp.WalletId,
			Chains:     []proto.Chain{proto.Chain_CHAIN_ETHEREUM},
			StartIndex: 0,
			Count:      3,
		})
		if err != nil {
			log.Printf("GetAddresses failed: %v", err)
		} else {
			fmt.Printf("✅ Generated %d addresses:\n", len(addressesResp.Addresses))
			for _, addr := range addressesResp.Addresses {
				fmt.Printf("   - Index %d: %s\n", addr.Index, addr.Address)
			}
		}
	}

	// Test 6: Import wallet
	fmt.Println("\n6. Testing ImportWallet...")
	testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	importResp, err := client.ImportWallet(ctx, &proto.ImportWalletRequest{
		UserId:   "test_user_import",
		Mnemonic: testMnemonic,
		Chains:   []proto.Chain{proto.Chain_CHAIN_ETHEREUM},
	})
	if err != nil {
		log.Printf("ImportWallet failed: %v", err)
	} else {
		fmt.Printf("✅ Imported wallet: %s\n", importResp.WalletId)
		fmt.Printf("   Addresses: %d\n", len(importResp.Addresses))
	}

	fmt.Println("\n🎉 All tests completed!")
}
