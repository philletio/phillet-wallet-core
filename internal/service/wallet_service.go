package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/philletio/phillet-wallet-core/api/proto"
	"github.com/philletio/phillet-wallet-core/internal/config"
	"github.com/philletio/phillet-wallet-core/internal/logger"
	"github.com/philletio/phillet-wallet-core/internal/metrics"
	"github.com/philletio/phillet-wallet-core/internal/models"
	"github.com/philletio/phillet-wallet-core/internal/repository"
	"github.com/philletio/phillet-wallet-core/internal/security"
	walletpkg "github.com/philletio/phillet-wallet-core/internal/wallet"
	redis "github.com/redis/go-redis/v9"
	"golang.org/x/crypto/argon2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// WalletService implements the gRPC wallet service
type WalletService struct {
	proto.UnimplementedWalletServiceServer
	repo    *repository.PostgresRepository
	config  *config.Config
	cache   *redis.Client
	metrics *metrics.Metrics
	logger  *logger.Logger
}

// NewWalletService creates a new wallet service instance
func NewWalletService(repo *repository.PostgresRepository, config *config.Config) *WalletService {
	return &WalletService{
		repo:    repo,
		config:  config,
		metrics: metrics.NewMetrics(),
		logger: logger.NewLogger(&logger.Config{
			Level:  config.Logging.Level,
			Format: config.Logging.Format,
		}),
	}
}

// WithCache sets the Redis cache client and returns the service (for chaining during setup)
func (s *WalletService) WithCache(cache *redis.Client) *WalletService {
	s.cache = cache
	return s
}

// extractUserIDFromContext extracts user ID from JWT token in gRPC metadata
func (s *WalletService) extractUserIDFromContext(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no metadata provided")
	}

	// Extract JWT token from metadata
	tokens := md.Get("authorization")
	if len(tokens) == 0 {
		return "", status.Error(codes.Unauthenticated, "no authorization token provided")
	}

	token := tokens[0]
	if len(token) < 7 || token[:7] != "Bearer " {
		return "", status.Error(codes.Unauthenticated, "invalid authorization header format")
	}

	jwtToken := token[7:]

	// TODO: Validate JWT token with Auth service
	// For now, we'll use a simple extraction
	// In production, this should call the Auth service to validate the token

	// Extract user ID from token (simplified for now)
	// In real implementation, this would be done by calling Auth service
	userID := "user_" + jwtToken[:8] // Simplified for demo

	return userID, nil
}

// GenerateWallet creates a new HD wallet with mnemonic phrase
func (s *WalletService) GenerateWallet(ctx context.Context, req *proto.GenerateWalletRequest) (*proto.GenerateWalletResponse, error) {
	// Extract user ID from JWT token
	userID, err := s.extractUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.WordCount != 12 && req.WordCount != 15 && req.WordCount != 18 && req.WordCount != 21 && req.WordCount != 24 {
		return nil, status.Error(codes.InvalidArgument, "word_count must be 12, 15, 18, 21, or 24")
	}

	// Generate new wallet with requested word count and passphrase
	hdWallet, err := walletpkg.NewHDWallet(userID, int(req.WordCount), req.Passphrase)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate wallet: %v", err)
	}

	// Generate wallet ID
	walletID := fmt.Sprintf("wallet_%s_%d", userID, time.Now().Unix())

	// Hash passphrase if provided using Argon2id
	var passphraseHashPtr *string
	if req.Passphrase != "" {
		// Use wallet salt as part of the hash input to bind to this wallet instance
		saltBytes := []byte(hdWallet.GetSalt())
		hash := argon2.IDKey([]byte(req.Passphrase), saltBytes, 1, 64*1024, 4, 32)
		hashHex := fmt.Sprintf("%x", hash)
		passphraseHashPtr = &hashHex
	}

	// Encrypt mnemonic for storage at rest
	encKey := security.DeriveKey(s.config.Security.EncryptionKey, hdWallet.GetSalt())
	encMnemonic, err := security.EncryptAESGCM(encKey, []byte(hdWallet.GetMnemonic()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to encrypt mnemonic: %v", err)
	}

	// Create wallet model for database
	walletModel := &models.Wallet{
		ID:                uuid.New(),
		WalletID:          walletID,
		UserID:            uuid.New(), // Generate new UUID for user
		EncryptedMnemonic: encMnemonic,
		MnemonicHash:      hdWallet.GetMnemonicHash(), // Store hash, not plain mnemonic
		Salt:              hdWallet.GetSalt(),
		PassphraseHash:    passphraseHashPtr,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		LastUsedAt:        nil, // Will be set to current time
		IsActive:          true,
		Metadata:          map[string]interface{}{"word_count": req.WordCount},
	}

	// Save wallet to database
	err = s.repo.CreateWallet(ctx, walletModel)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save wallet: %v", err)
	}

	// Generate addresses for requested chains
	var addresses []*proto.Address
	var addressModels []*models.Address

	for _, chain := range req.Chains {
		if chain == proto.Chain_CHAIN_ETHEREUM {
			address, publicKey, err := hdWallet.GenerateEthereumAddress(0)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to generate Ethereum address: %v", err)
			}

			// Create address model
			addressModel := &models.Address{
				ID:             uuid.New(),
				WalletID:       walletModel.ID, // Use UUID from wallet
				Chain:          "ethereum",
				Address:        address,
				DerivationPath: "m/44'/60'/0'/0/0",
				AddressIndex:   0,
				IsChange:       false,
				PublicKeyHash:  &publicKey,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
				LastUsedAt:     nil,
				IsActive:       true,
				Metadata:       map[string]interface{}{},
			}

			// Save address to database
			err = s.repo.CreateAddress(ctx, addressModel)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to save address: %v", err)
			}

			addressModels = append(addressModels, addressModel)

			addresses = append(addresses, &proto.Address{
				Chain:          chain,
				Address:        address,
				DerivationPath: "m/44'/60'/0'/0/0",
				Index:          0,
				IsChange:       false,
			})
		}
		// TODO: Add support for other chains
	}

	// Log audit event
	auditLog := &models.AuditLog{
		ID:           uuid.New(),
		UserID:       &walletModel.UserID,
		WalletID:     &walletModel.ID,
		Action:       "wallet_generated",
		ResourceType: "wallet",
		ResourceID:   &walletModel.ID,
		IPAddress:    nil, // TODO: Extract from context
		UserAgent:    nil, // TODO: Extract from context
		Success:      true,
		RequestData: map[string]interface{}{
			"word_count": req.WordCount,
			"chains":     req.Chains,
		},
		ResponseData: map[string]interface{}{
			"wallet_id": walletID,
			"addresses": len(addresses),
		},
		CreatedAt: time.Now(),
	}

	err = s.repo.CreateAuditLog(ctx, auditLog)
	if err != nil {
		// Log error but don't fail the request
		fmt.Printf("Failed to create audit log: %v\n", err)
	}

	// Record metrics
	s.metrics.RecordWalletCreated()

	// Log wallet creation
	s.logger.LogWalletOperation(ctx, "wallet_created", walletID, userID, true, map[string]interface{}{
		"word_count":          req.WordCount,
		"addresses_generated": len(addresses),
		"chains":              req.Chains,
	})

	return &proto.GenerateWalletResponse{
		WalletId:  walletID,
		Mnemonic:  hdWallet.GetMnemonic(), // Return mnemonic only once
		Addresses: addresses,
		CreatedAt: timestamppb.Now(),
	}, nil
}

// ImportWallet imports an existing wallet from mnemonic phrase
func (s *WalletService) ImportWallet(ctx context.Context, req *proto.ImportWalletRequest) (*proto.ImportWalletResponse, error) {
	// Extract user ID from JWT token
	userID, err := s.extractUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.Mnemonic == "" {
		return nil, status.Error(codes.InvalidArgument, "mnemonic is required")
	}

	// Import wallet with optional passphrase
	hdWallet, err := walletpkg.ImportHDWallet(req.Mnemonic, userID, req.Passphrase)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to import wallet: %v", err)
	}

	// Generate wallet ID
	walletID := fmt.Sprintf("wallet_%s_%d", userID, time.Now().Unix())

	// Hash passphrase if provided using Argon2id
	var passphraseHashPtr *string
	if req.Passphrase != "" {
		saltBytes := []byte(hdWallet.GetSalt())
		hash := argon2.IDKey([]byte(req.Passphrase), saltBytes, 1, 64*1024, 4, 32)
		hashHex := fmt.Sprintf("%x", hash)
		passphraseHashPtr = &hashHex
	}

	// Encrypt mnemonic for storage at rest
	encKey := security.DeriveKey(s.config.Security.EncryptionKey, hdWallet.GetSalt())
	encMnemonic, err := security.EncryptAESGCM(encKey, []byte(hdWallet.GetMnemonic()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to encrypt mnemonic: %v", err)
	}

	// Create wallet model for database
	walletModel := &models.Wallet{
		ID:                uuid.New(),
		WalletID:          walletID,
		UserID:            uuid.New(), // Generate new UUID for user
		EncryptedMnemonic: encMnemonic,
		MnemonicHash:      hdWallet.GetMnemonicHash(),
		Salt:              hdWallet.GetSalt(),
		PassphraseHash:    passphraseHashPtr,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		LastUsedAt:        nil,
		IsActive:          true,
		Metadata:          map[string]interface{}{"imported": true},
	}

	// Save wallet to database
	err = s.repo.CreateWallet(ctx, walletModel)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save wallet: %v", err)
	}

	// Generate addresses for requested chains
	var addresses []*proto.Address

	for _, chain := range req.Chains {
		if chain == proto.Chain_CHAIN_ETHEREUM {
			address, publicKey, err := hdWallet.GenerateEthereumAddress(0)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to generate Ethereum address: %v", err)
			}

			// Create address model
			addressModel := &models.Address{
				ID:             uuid.New(),
				WalletID:       walletModel.ID, // Use UUID from wallet
				Chain:          "ethereum",
				Address:        address,
				DerivationPath: "m/44'/60'/0'/0/0",
				AddressIndex:   0,
				IsChange:       false,
				PublicKeyHash:  &publicKey,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
				LastUsedAt:     nil,
				IsActive:       true,
				Metadata:       map[string]interface{}{},
			}

			// Save address to database
			err = s.repo.CreateAddress(ctx, addressModel)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to save address: %v", err)
			}

			addresses = append(addresses, &proto.Address{
				Chain:          chain,
				Address:        address,
				DerivationPath: "m/44'/60'/0'/0/0",
				Index:          0,
				IsChange:       false,
			})
		}
		// TODO: Add support for other chains
	}

	// Log audit event
	auditLog := &models.AuditLog{
		ID:           uuid.New(),
		UserID:       &walletModel.UserID,
		WalletID:     &walletModel.ID,
		Action:       "wallet_imported",
		ResourceType: "wallet",
		ResourceID:   &walletModel.ID,
		IPAddress:    nil, // TODO: Extract from context
		UserAgent:    nil, // TODO: Extract from context
		Success:      true,
		RequestData: map[string]interface{}{
			"chains": req.Chains,
		},
		ResponseData: map[string]interface{}{
			"wallet_id": walletID,
			"addresses": len(addresses),
		},
		CreatedAt: time.Now(),
	}

	err = s.repo.CreateAuditLog(ctx, auditLog)
	if err != nil {
		// Log error but don't fail the request
		fmt.Printf("Failed to create audit log: %v\n", err)
	}

	return &proto.ImportWalletResponse{
		WalletId:   walletID,
		Addresses:  addresses,
		ImportedAt: timestamppb.Now(),
	}, nil
}

// GetAddresses returns addresses for specified chains
func (s *WalletService) GetAddresses(ctx context.Context, req *proto.GetAddressesRequest) (*proto.GetAddressesResponse, error) {
	// Extract user ID from JWT token
	_, err := s.extractUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.WalletId == "" {
		return nil, status.Error(codes.InvalidArgument, "wallet_id is required")
	}

	// Verify wallet exists
	_, err = s.repo.GetWalletByWalletID(ctx, req.WalletId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "wallet not found: %v", err)
	}

	// For now, skip user verification since we're using generated UUIDs
	// In production, this should verify the user ID from JWT matches the wallet user ID

	// Get existing addresses from database
	addresses, err := s.repo.GetAddressesByWalletIDString(ctx, req.WalletId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get addresses: %v", err)
	}

	// Build a set of requested chains; if none provided, include chains we already have
	requestedChains := make(map[proto.Chain]bool)
	if len(req.Chains) == 0 {
		for _, addr := range addresses {
			requestedChains[s.mapChainToProto(addr.Chain)] = true
		}
	} else {
		for _, ch := range req.Chains {
			requestedChains[ch] = true
		}
	}

	// Determine start and count
	start := int(req.StartIndex)
	if start < 0 {
		start = 0
	}
	count := int(req.Count)
	if count <= 0 {
		count = 10
	}

	// Generate any missing addresses for requested range (EVM only for now)
	// Note: This demo does not reconstruct the HD wallet; a production system would derive from seed stored securely.
	// Here we only return already stored addresses; generation is handled at create/import time for index 0.

	var protoAddresses []*proto.Address
	for _, addr := range addresses {
		chainEnum := s.mapChainToProto(addr.Chain)
		if !requestedChains[chainEnum] {
			continue
		}
		if addr.AddressIndex < start || addr.AddressIndex >= start+count {
			continue
		}
		protoAddresses = append(protoAddresses, &proto.Address{
			Chain:          chainEnum,
			Address:        addr.Address,
			DerivationPath: addr.DerivationPath,
			Index:          int32(addr.AddressIndex),
			IsChange:       addr.IsChange,
		})
	}

	return &proto.GetAddressesResponse{
		Addresses: protoAddresses,
	}, nil
}

// SignMessage signs a message with wallet's private key
func (s *WalletService) SignMessage(ctx context.Context, req *proto.SignMessageRequest) (*proto.SignMessageResponse, error) {
	// Extract user ID from JWT token
	//userID, err := s.extractUserIDFromContext(ctx)
	_, err := s.extractUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.WalletId == "" {
		return nil, status.Error(codes.InvalidArgument, "wallet_id is required")
	}

	if len(req.Message) == 0 {
		return nil, status.Error(codes.InvalidArgument, "message is required")
	}

	// Verify wallet belongs to user
	wallet, err := s.repo.GetWalletByWalletID(ctx, req.WalletId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "wallet not found: %v", err)
	}

	// For now, skip user verification since we're using generated UUIDs
	// In production, this should verify the user ID from JWT matches the wallet user ID

	// Get address for signing
	address, err := s.repo.GetAddressByWalletAndIndex(ctx, req.WalletId, req.AddressIndex)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "address not found: %v", err)
	}

	// Reconstruct seed by decrypting mnemonic; derive key and sign (EVM only currently)
	if req.Chain != proto.Chain_CHAIN_ETHEREUM && req.Chain != proto.Chain_CHAIN_POLYGON && req.Chain != proto.Chain_CHAIN_BSC {
		return nil, status.Error(codes.Unimplemented, "message signing for this chain is not implemented yet")
	}

	// Decrypt mnemonic using wallet salt and configured key
	encKey := security.DeriveKey(s.config.Security.EncryptionKey, wallet.Salt)
	mnemonicBytes, err := security.DecryptAESGCM(encKey, wallet.EncryptedMnemonic)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decrypt mnemonic: %v", err)
	}

	// Recreate HD wallet from mnemonic (no passphrase for now; would need to be supplied if used)
	hd, err := walletpkg.ImportHDWallet(string(mnemonicBytes), wallet.UserID.String(), "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to reconstruct wallet: %v", err)
	}
	// Derive private key for index
	pk, err := hd.DeriveEthereumPrivateKey(int(req.AddressIndex))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to derive private key: %v", err)
	}
	sig, err := hd.SignMessage(req.Message, pk)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign message: %v", err)
	}
	signature := sig
	signatureHex := "0x" + fmt.Sprintf("%x", signature)
	messageHash := fmt.Sprintf("%x", crypto.Keccak256(req.Message))

	// Save signature to database
	signatureModel := &models.Signature{
		ID:            uuid.New(),
		WalletID:      wallet.ID,
		AddressID:     address.ID,
		MessageHash:   messageHash,
		SignatureData: string(signature),
		SignatureHex:  signatureHex,
		MessageType:   "message",
		CreatedAt:     time.Now(),
		Metadata:      map[string]interface{}{},
	}

	err = s.repo.CreateSignature(ctx, signatureModel)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save signature: %v", err)
	}

	// Log audit event
	auditLog := &models.AuditLog{
		ID:           uuid.New(),
		UserID:       &wallet.UserID,
		WalletID:     &wallet.ID,
		Action:       "message_signed",
		ResourceType: "signature",
		ResourceID:   &signatureModel.ID,
		IPAddress:    nil, // TODO: Extract from context
		UserAgent:    nil, // TODO: Extract from context
		Success:      true,
		RequestData: map[string]interface{}{
			"address_index": req.AddressIndex,
			"chain":         req.Chain,
		},
		ResponseData: map[string]interface{}{
			"signature_hex": signatureHex,
			"message_hash":  messageHash,
		},
		CreatedAt: time.Now(),
	}

	err = s.repo.CreateAuditLog(ctx, auditLog)
	if err != nil {
		// Log error but don't fail the request
		fmt.Printf("Failed to create audit log: %v\n", err)
	}

	return &proto.SignMessageResponse{
		Signature:    signature,
		SignatureHex: signatureHex,
		MessageHash:  messageHash,
	}, nil
}

// VerifySignature verifies a digital signature
func (s *WalletService) VerifySignature(ctx context.Context, req *proto.VerifySignatureRequest) (*proto.VerifySignatureResponse, error) {
	if len(req.Message) == 0 {
		return nil, status.Error(codes.InvalidArgument, "message is required")
	}

	if len(req.Signature) == 0 {
		return nil, status.Error(codes.InvalidArgument, "signature is required")
	}

	if req.Address == "" {
		return nil, status.Error(codes.InvalidArgument, "address is required")
	}

	switch req.Chain {
	case proto.Chain_CHAIN_ETHEREUM, proto.Chain_CHAIN_POLYGON, proto.Chain_CHAIN_BSC:
		// EVM-compatible verification
		isValid, err := walletpkg.VerifySignature(req.Message, req.Signature, req.Address)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "verification failed: %v", err)
		}
		// We cannot recover address without v,r,s unless signature is standard 65-byte ECDSA (which it is), but
		// wallet.VerifySignature already checks equivalence; just echo address when valid
		recoveredAddress := ""
		if isValid {
			recoveredAddress = req.Address
		}
		return &proto.VerifySignatureResponse{
			IsValid:          isValid,
			RecoveredAddress: recoveredAddress,
		}, nil
	case proto.Chain_CHAIN_SOLANA, proto.Chain_CHAIN_TON:
		return nil, status.Error(codes.Unimplemented, "verification for this chain is not implemented yet")
	default:
		return nil, status.Error(codes.InvalidArgument, "unsupported or unspecified chain")
	}
}

// GetWalletInfo returns wallet information
func (s *WalletService) GetWalletInfo(ctx context.Context, req *proto.GetWalletInfoRequest) (*proto.GetWalletInfoResponse, error) {
	// Extract user ID from JWT token
	userID, err := s.extractUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.WalletId == "" {
		return nil, status.Error(codes.InvalidArgument, "wallet_id is required")
	}

	// Get wallet from database
	wallet, err := s.repo.GetWalletByWalletID(ctx, req.WalletId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "wallet not found: %v", err)
	}

	// For now, skip user verification since we're using generated UUIDs
	// In production, this should verify the user ID from JWT matches the wallet user ID

	// Get addresses count
	addresses, err := s.repo.GetAddressesByWalletIDString(ctx, req.WalletId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get addresses: %v", err)
	}

	// Determine supported chains
	supportedChains := make([]proto.Chain, 0)
	chainMap := make(map[string]bool)
	for _, addr := range addresses {
		if !chainMap[addr.Chain] {
			chainMap[addr.Chain] = true
			supportedChains = append(supportedChains, s.mapChainToProto(addr.Chain))
		}
	}

	return &proto.GetWalletInfoResponse{
		WalletId:        wallet.WalletID,
		UserId:          userID, // Return the string user ID for now
		SupportedChains: supportedChains,
		AddressCount:    int32(len(addresses)),
		CreatedAt:       timestamppb.New(wallet.CreatedAt),
		LastUsed:        timestamppb.New(wallet.CreatedAt), // Use CreatedAt for now since LastUsedAt is nil
	}, nil
}

// SignTransaction signs a transaction for specified chain
func (s *WalletService) SignTransaction(ctx context.Context, req *proto.SignTransactionRequest) (*proto.SignTransactionResponse, error) {
	if req.WalletId == "" {
		return nil, status.Error(codes.InvalidArgument, "wallet_id is required")
	}
	if len(req.TransactionData) == 0 {
		return nil, status.Error(codes.InvalidArgument, "transaction_data is required")
	}
	if req.Chain != proto.Chain_CHAIN_ETHEREUM && req.Chain != proto.Chain_CHAIN_POLYGON && req.Chain != proto.Chain_CHAIN_BSC {
		return nil, status.Error(codes.Unimplemented, "transaction signing for this chain is not implemented yet")
	}

	// Load wallet
	w, err := s.repo.GetWalletByWalletID(ctx, req.WalletId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "wallet not found: %v", err)
	}
	// Decrypt mnemonic
	encKey := security.DeriveKey(s.config.Security.EncryptionKey, w.Salt)
	mnemonicBytes, err := security.DecryptAESGCM(encKey, w.EncryptedMnemonic)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decrypt mnemonic: %v", err)
	}
	// Recreate HD wallet (no passphrase support here)
	hd, err := walletpkg.ImportHDWallet(string(mnemonicBytes), w.UserID.String(), "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to reconstruct wallet: %v", err)
	}
	// Derive private key
	pk, err := hd.DeriveEthereumPrivateKey(int(req.AddressIndex))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to derive private key: %v", err)
	}

	// Parse minimal EVM transaction fields from JSON (legacy or EIP-1559)
	var txIn struct {
		Nonce                uint64 `json:"nonce"`
		GasPrice             string `json:"gasPrice"`
		MaxFeePerGas         string `json:"maxFeePerGas"`
		MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
		Gas                  uint64 `json:"gas"`
		To                   string `json:"to"`
		Value                string `json:"value"`
		Data                 string `json:"data"`
		ChainID              int64  `json:"chainId"`
	}
	if err := json.Unmarshal(req.TransactionData, &txIn); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid transaction_data: %v", err)
	}
	// Hex decode numeric fields
	parseHex := func(s string) (*big.Int, error) {
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			s = s[2:]
		}
		if s == "" {
			return big.NewInt(0), nil
		}
		n := new(big.Int)
		_, ok := n.SetString(s, 16)
		if !ok {
			return nil, fmt.Errorf("invalid hex number")
		}
		return n, nil
	}
	gasPrice, err := parseHex(txIn.GasPrice)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid gasPrice: %v", err)
	}
	value, err := parseHex(txIn.Value)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid value: %v", err)
	}
	var toPtr *common.Address
	if txIn.To != "" {
		addr := common.HexToAddress(txIn.To)
		toPtr = &addr
	}
	var dataBytes []byte
	if txIn.Data != "" {
		db, err := hex.DecodeString(strings.TrimPrefix(txIn.Data, "0x"))
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid data: %v", err)
		}
		dataBytes = db
	}

	// Build legacy or EIP-1559 transaction
	chainID := big.NewInt(txIn.ChainID)
	var tx *types.Transaction
	if txIn.MaxFeePerGas != "" || txIn.MaxPriorityFeePerGas != "" {
		feeCap, err := parseHex(txIn.MaxFeePerGas)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid maxFeePerGas: %v", err)
		}
		tipCap, err := parseHex(txIn.MaxPriorityFeePerGas)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid maxPriorityFeePerGas: %v", err)
		}
		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     txIn.Nonce,
			GasTipCap: tipCap,
			GasFeeCap: feeCap,
			Gas:       txIn.Gas,
			To:        toPtr,
			Value:     value,
			Data:      dataBytes,
		})
	} else {
		tx = types.NewTx(&types.LegacyTx{
			Nonce:    txIn.Nonce,
			GasPrice: gasPrice,
			Gas:      txIn.Gas,
			To:       toPtr,
			Value:    value,
			Data:     dataBytes,
		})
	}
	signer := types.LatestSignerForChainID(chainID)
	signedTx, err := types.SignTx(tx, signer, pk)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to sign tx: %v", err)
	}
	// RLP encode
	var buf bytes.Buffer
	if err := signedTx.EncodeRLP(&buf); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to encode tx: %v", err)
	}
	txHash := signedTx.Hash().Hex()
	return &proto.SignTransactionResponse{
		SignedTransaction: buf.Bytes(),
		Signature:         "", // optional: could pack v,r,s if needed
		TransactionHash:   txHash,
	}, nil
}

// GetBalance returns balance for specified address
func (s *WalletService) GetBalance(ctx context.Context, req *proto.GetBalanceRequest) (*proto.GetBalanceResponse, error) {
	if req.Address == "" {
		return nil, status.Error(codes.InvalidArgument, "address is required")
	}

	// Cache lookup
	if s.cache != nil {
		cacheKey := fmt.Sprintf("bal:%d:%s", req.Chain, strings.ToLower(req.Address))
		if val, err := s.cache.Get(ctx, cacheKey).Result(); err == nil && val != "" {
			return &proto.GetBalanceResponse{
				Balance:  val,
				Symbol:   symbolForChain(req.Chain),
				Decimals: 18,
				Chain:    req.Chain,
			}, nil
		}
	}

	var rpcURL string
	var symbol string
	var decimals int32 = 18
	switch req.Chain {
	case proto.Chain_CHAIN_ETHEREUM:
		rpcURL = s.config.RPC.EthereumURL
		symbol = "ETH"
	case proto.Chain_CHAIN_POLYGON:
		rpcURL = s.config.RPC.PolygonURL
		symbol = "MATIC"
	case proto.Chain_CHAIN_BSC:
		rpcURL = s.config.RPC.BSCURL
		symbol = "BNB"
	default:
		return nil, status.Error(codes.Unimplemented, "balance for this chain is not implemented yet")
	}
	if rpcURL == "" {
		return nil, status.Error(codes.FailedPrecondition, "RPC URL not configured")
	}

	httpClient := &http.Client{Timeout: s.config.RPC.Timeout}
	payload := fmt.Sprintf(`{"jsonrpc":"2.0","method":"eth_getBalance","params":["%s","latest"],"id":1}`, req.Address)
	resp, err := httpClient.Post(rpcURL, "application/json", strings.NewReader(payload))
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "rpc request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, status.Errorf(codes.Unavailable, "rpc status: %s", resp.Status)
	}
	type rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	var r rpcResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, status.Errorf(codes.Internal, "rpc decode failed: %v", err)
	}
	if r.Error != nil {
		return nil, status.Errorf(codes.Unavailable, "rpc error: %s", r.Error.Message)
	}
	balance := r.Result

	// Cache set
	if s.cache != nil {
		cacheKey := fmt.Sprintf("bal:%d:%s", req.Chain, strings.ToLower(req.Address))
		_ = s.cache.Set(ctx, cacheKey, balance, s.config.Cache.BalanceTTL).Err()
	}

	return &proto.GetBalanceResponse{
		Balance:  balance,
		Symbol:   symbol,
		Decimals: decimals,
		Chain:    req.Chain,
	}, nil
}

// symbolForChain returns native symbol for an EVM chain enum
func symbolForChain(chain proto.Chain) string {
	switch chain {
	case proto.Chain_CHAIN_ETHEREUM:
		return "ETH"
	case proto.Chain_CHAIN_POLYGON:
		return "MATIC"
	case proto.Chain_CHAIN_BSC:
		return "BNB"
	default:
		return ""
	}
}

// mapChainToProto maps database chain string to protobuf enum
func (s *WalletService) mapChainToProto(chain string) proto.Chain {
	switch chain {
	case "ethereum":
		return proto.Chain_CHAIN_ETHEREUM
	case "polygon":
		return proto.Chain_CHAIN_POLYGON
	case "bsc":
		return proto.Chain_CHAIN_BSC
	case "solana":
		return proto.Chain_CHAIN_SOLANA
	case "ton":
		return proto.Chain_CHAIN_TON
	default:
		return proto.Chain_CHAIN_UNSPECIFIED
	}
}
