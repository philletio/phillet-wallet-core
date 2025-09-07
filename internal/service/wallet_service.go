package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/philletio/phillet-wallet-core/api/proto"
	"github.com/philletio/phillet-wallet-core/internal/config"
	"github.com/philletio/phillet-wallet-core/internal/models"
	"github.com/philletio/phillet-wallet-core/internal/repository"
	"github.com/philletio/phillet-wallet-core/internal/wallet"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// WalletService implements the gRPC wallet service
type WalletService struct {
	proto.UnimplementedWalletServiceServer
	repo   *repository.PostgresRepository
	config *config.Config
}

// NewWalletService creates a new wallet service instance
func NewWalletService(repo *repository.PostgresRepository, config *config.Config) *WalletService {
	return &WalletService{
		repo:   repo,
		config: config,
	}
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

	// Generate new wallet
	hdWallet, err := wallet.NewHDWallet(userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate wallet: %v", err)
	}

	// Generate wallet ID
	walletID := fmt.Sprintf("wallet_%s_%d", userID, time.Now().Unix())

	// Create wallet model for database
	walletModel := &models.Wallet{
		ID:             uuid.New(),
		WalletID:       walletID,
		UserID:         uuid.New(),                 // Generate new UUID for user
		MnemonicHash:   hdWallet.GetMnemonicHash(), // Store hash, not plain mnemonic
		Salt:           hdWallet.GetSalt(),
		PassphraseHash: nil, // TODO: Add passphrase support
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		LastUsedAt:     nil, // Will be set to current time
		IsActive:       true,
		Metadata:       map[string]interface{}{"word_count": req.WordCount},
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

	// Import wallet
	hdWallet, err := wallet.ImportHDWallet(req.Mnemonic, userID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to import wallet: %v", err)
	}

	// Generate wallet ID
	walletID := fmt.Sprintf("wallet_%s_%d", userID, time.Now().Unix())

	// Create wallet model for database
	walletModel := &models.Wallet{
		ID:             uuid.New(),
		WalletID:       walletID,
		UserID:         uuid.New(), // Generate new UUID for user
		MnemonicHash:   hdWallet.GetMnemonicHash(),
		Salt:           hdWallet.GetSalt(),
		PassphraseHash: nil, // TODO: Add passphrase support
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		LastUsedAt:     nil,
		IsActive:       true,
		Metadata:       map[string]interface{}{"imported": true},
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

	// Get addresses from database
	addresses, err := s.repo.GetAddressesByWalletIDString(ctx, req.WalletId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get addresses: %v", err)
	}

	var protoAddresses []*proto.Address
	for _, addr := range addresses {
		protoAddresses = append(protoAddresses, &proto.Address{
			Chain:          s.mapChainToProto(addr.Chain),
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

	// TODO: Reconstruct HD wallet from stored data for signing
	// For now, we'll return a mock signature
	signature := []byte("mock_signature")
	signatureHex := "0x" + fmt.Sprintf("%x", signature)
	messageHash := fmt.Sprintf("%x", req.Message)

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

	// TODO: Implement actual signature verification
	// For now, return mock result
	isValid := true
	recoveredAddress := req.Address

	return &proto.VerifySignatureResponse{
		IsValid:          isValid,
		RecoveredAddress: recoveredAddress,
	}, nil
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
	// TODO: Implement transaction signing
	return nil, status.Error(codes.Unimplemented, "transaction signing not implemented yet")
}

// GetBalance returns balance for specified address
func (s *WalletService) GetBalance(ctx context.Context, req *proto.GetBalanceRequest) (*proto.GetBalanceResponse, error) {
	// TODO: Implement balance checking
	return nil, status.Error(codes.Unimplemented, "balance checking not implemented yet")
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
