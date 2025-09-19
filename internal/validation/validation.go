package validation

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/philletio/phillet-wallet-core/api/proto"
	"github.com/philletio/phillet-wallet-core/internal/errors"
)

// Validator provides validation for gRPC requests
type Validator struct{}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateGenerateWalletRequest validates GenerateWalletRequest
func (v *Validator) ValidateGenerateWalletRequest(ctx context.Context, req *proto.GenerateWalletRequest) error {
	if req == nil {
		return errors.New(errors.ErrorCodeInvalidInput, "request cannot be nil")
	}

	// Validate user ID
	if err := errors.ValidateRequired("user_id", req.UserId); err != nil {
		return err
	}

	// Validate word count
	if req.WordCount != 0 {
		if err := errors.ValidateRange("word_count", int(req.WordCount), 12, 24); err != nil {
			return err
		}
		if req.WordCount%3 != 0 {
			return errors.NewInvalidInput("word_count", "word count must be a multiple of 3")
		}
	}

	// Validate passphrase length (if provided)
	if req.Passphrase != "" && len(req.Passphrase) < 8 {
		return errors.NewInvalidInput("passphrase", "passphrase must be at least 8 characters long")
	}

	return nil
}

// ValidateImportWalletRequest validates ImportWalletRequest
func (v *Validator) ValidateImportWalletRequest(ctx context.Context, req *proto.ImportWalletRequest) error {
	if req == nil {
		return errors.New(errors.ErrorCodeInvalidInput, "request cannot be nil")
	}

	// Validate user ID
	if err := errors.ValidateRequired("user_id", req.UserId); err != nil {
		return err
	}

	// Validate mnemonic
	if err := errors.ValidateRequired("mnemonic", req.Mnemonic); err != nil {
		return err
	}
	if err := errors.ValidateMnemonic(req.Mnemonic); err != nil {
		return err
	}

	// Validate passphrase length (if provided)
	if req.Passphrase != "" && len(req.Passphrase) < 8 {
		return errors.NewInvalidInput("passphrase", "passphrase must be at least 8 characters long")
	}

	return nil
}

// ValidateGetWalletInfoRequest validates GetWalletInfoRequest
func (v *Validator) ValidateGetWalletInfoRequest(ctx context.Context, req *proto.GetWalletInfoRequest) error {
	if req == nil {
		return errors.New(errors.ErrorCodeInvalidInput, "request cannot be nil")
	}

	// Validate wallet ID
	if err := errors.ValidateRequired("wallet_id", req.WalletId); err != nil {
		return err
	}

	return nil
}

// ValidateGetAddressesRequest validates GetAddressesRequest
func (v *Validator) ValidateGetAddressesRequest(ctx context.Context, req *proto.GetAddressesRequest) error {
	if req == nil {
		return errors.New(errors.ErrorCodeInvalidInput, "request cannot be nil")
	}

	// Validate wallet ID
	if err := errors.ValidateRequired("wallet_id", req.WalletId); err != nil {
		return err
	}

	// Validate chains
	for i, chain := range req.Chains {
		if chain == proto.Chain_CHAIN_UNSPECIFIED {
			return errors.NewInvalidInput(fmt.Sprintf("chains[%d]", i), "chain cannot be unspecified")
		}
	}

	// Validate pagination
	if req.StartIndex < 0 {
		return errors.NewInvalidInput("start_index", "start index cannot be negative")
	}
	if req.Count < 0 {
		return errors.NewInvalidInput("count", "count cannot be negative")
	}
	if req.Count > 100 {
		return errors.NewInvalidInput("count", "count cannot exceed 100")
	}

	return nil
}

// ValidateSignMessageRequest validates SignMessageRequest
func (v *Validator) ValidateSignMessageRequest(ctx context.Context, req *proto.SignMessageRequest) error {
	if req == nil {
		return errors.New(errors.ErrorCodeInvalidInput, "request cannot be nil")
	}

	// Validate wallet ID
	if err := errors.ValidateRequired("wallet_id", req.WalletId); err != nil {
		return err
	}

	// Validate message
	if len(req.Message) == 0 {
		return errors.NewMissingField("message")
	}

	// Validate chain
	if req.Chain == proto.Chain_CHAIN_UNSPECIFIED {
		return errors.NewInvalidInput("chain", "chain cannot be unspecified")
	}

	// Validate address index
	if req.AddressIndex < 0 {
		return errors.NewInvalidInput("address_index", "address index cannot be negative")
	}

	return nil
}

// ValidateSignTransactionRequest validates SignTransactionRequest
func (v *Validator) ValidateSignTransactionRequest(ctx context.Context, req *proto.SignTransactionRequest) error {
	if req == nil {
		return errors.New(errors.ErrorCodeInvalidInput, "request cannot be nil")
	}

	// Validate wallet ID
	if err := errors.ValidateRequired("wallet_id", req.WalletId); err != nil {
		return err
	}

	// Validate chain
	if req.Chain == proto.Chain_CHAIN_UNSPECIFIED {
		return errors.NewInvalidInput("chain", "chain cannot be unspecified")
	}

	// Validate address index
	if req.AddressIndex < 0 {
		return errors.NewInvalidInput("address_index", "address index cannot be negative")
	}

	// Validate transaction data
	if len(req.TransactionData) == 0 {
		return errors.NewMissingField("transaction_data")
	}

	// Basic JSON validation
	if !strings.HasPrefix(strings.TrimSpace(string(req.TransactionData)), "{") {
		return errors.NewInvalidFormat("transaction_data", "valid JSON object")
	}

	return nil
}

// ValidateGetBalanceRequest validates GetBalanceRequest
func (v *Validator) ValidateGetBalanceRequest(ctx context.Context, req *proto.GetBalanceRequest) error {
	if req == nil {
		return errors.New(errors.ErrorCodeInvalidInput, "request cannot be nil")
	}

	// Validate address
	if err := errors.ValidateRequired("address", req.Address); err != nil {
		return err
	}

	// Validate chain
	if req.Chain == proto.Chain_CHAIN_UNSPECIFIED {
		return errors.NewInvalidInput("chain", "chain cannot be unspecified")
	}

	return nil
}

// ValidateVerifySignatureRequest validates VerifySignatureRequest
func (v *Validator) ValidateVerifySignatureRequest(ctx context.Context, req *proto.VerifySignatureRequest) error {
	if req == nil {
		return errors.New(errors.ErrorCodeInvalidInput, "request cannot be nil")
	}

	// Validate message
	if len(req.Message) == 0 {
		return errors.NewMissingField("message")
	}

	// Validate signature
	if len(req.Signature) == 0 {
		return errors.NewMissingField("signature")
	}

	// Validate address
	if err := errors.ValidateRequired("address", req.Address); err != nil {
		return err
	}
	if err := errors.ValidateAddress(req.Address); err != nil {
		return err
	}

	// Validate chain
	if req.Chain == proto.Chain_CHAIN_UNSPECIFIED {
		return errors.NewInvalidInput("chain", "chain cannot be unspecified")
	}

	return nil
}

// ValidateHealthRequest validates HealthRequest
func (v *Validator) ValidateHealthRequest(ctx context.Context, req *proto.HealthRequest) error {
	// Health request has no fields to validate
	return nil
}

// ValidateEthereumAddress validates Ethereum address format
func (v *Validator) ValidateEthereumAddress(address string) error {
	// Ethereum address should be 42 characters (0x + 40 hex chars)
	if len(address) != 42 {
		return errors.NewInvalidAddress(address)
	}
	if !strings.HasPrefix(address, "0x") {
		return errors.NewInvalidAddress(address)
	}

	// Check if it's valid hex
	hexPattern := regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	if !hexPattern.MatchString(address) {
		return errors.NewInvalidAddress(address)
	}

	return nil
}

// ValidateSolanaAddress validates Solana address format
func (v *Validator) ValidateSolanaAddress(address string) error {
	// Solana addresses are base58 encoded and typically 32-44 characters
	if len(address) < 32 || len(address) > 44 {
		return errors.NewInvalidAddress(address)
	}

	// Basic base58 pattern check (simplified)
	base58Pattern := regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]+$`)
	if !base58Pattern.MatchString(address) {
		return errors.NewInvalidAddress(address)
	}

	return nil
}

// ValidateTONAddress validates TON address format
func (v *Validator) ValidateTONAddress(address string) error {
	// TON addresses can be in different formats
	// Basic validation for common TON address patterns
	if len(address) < 10 {
		return errors.NewInvalidAddress(address)
	}

	// Check for common TON address patterns
	// This is a simplified validation - in production you'd use proper TON address validation
	if strings.Contains(address, ":") {
		// Raw format: workchain:hash
		parts := strings.Split(address, ":")
		if len(parts) != 2 {
			return errors.NewInvalidAddress(address)
		}
	} else if strings.HasPrefix(address, "UQ") || strings.HasPrefix(address, "EQ") {
		// User-friendly format
		return nil
	} else {
		// Try to validate as hex
		hexPattern := regexp.MustCompile(`^[0-9a-fA-F]+$`)
		if !hexPattern.MatchString(address) {
			return errors.NewInvalidAddress(address)
		}
	}

	return nil
}

// ValidateTransactionData validates transaction data JSON
func (v *Validator) ValidateTransactionData(data string) error {
	// Basic JSON structure validation
	requiredFields := []string{"to", "value", "gas", "nonce"}

	for _, field := range requiredFields {
		if !strings.Contains(data, fmt.Sprintf(`"%s"`, field)) {
			return errors.NewInvalidInput("transaction_data", fmt.Sprintf("missing required field: %s", field))
		}
	}

	return nil
}

// ValidatePagination validates pagination parameters
func (v *Validator) ValidatePagination(limit, offset int32) error {
	if limit < 0 {
		return errors.NewInvalidInput("limit", "limit cannot be negative")
	}
	if limit > 100 {
		return errors.NewInvalidInput("limit", "limit cannot exceed 100")
	}
	if offset < 0 {
		return errors.NewInvalidInput("offset", "offset cannot be negative")
	}
	return nil
}

// ValidateUUID validates UUID format
func (v *Validator) ValidateUUID(field, value string) error {
	if err := errors.ValidateRequired(field, value); err != nil {
		return err
	}

	// Basic UUID format validation
	uuidPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidPattern.MatchString(strings.ToLower(value)) {
		return errors.NewInvalidFormat(field, "valid UUID format")
	}

	return nil
}

// ValidateWordCount validates mnemonic word count
func (v *Validator) ValidateWordCount(wordCount int32) error {
	validCounts := []int32{12, 15, 18, 21, 24}
	for _, count := range validCounts {
		if wordCount == count {
			return nil
		}
	}
	return errors.NewInvalidInput("word_count", "word count must be 12, 15, 18, 21, or 24")
}

// ValidateChainSupport validates if chain is supported
func (v *Validator) ValidateChainSupport(chain proto.Chain) error {
	supportedChains := map[proto.Chain]bool{
		proto.Chain_CHAIN_ETHEREUM: true,
		proto.Chain_CHAIN_POLYGON:  true,
		proto.Chain_CHAIN_BSC:      true,
		proto.Chain_CHAIN_SOLANA:   true,
		proto.Chain_CHAIN_TON:      true,
	}

	if !supportedChains[chain] {
		return errors.NewInvalidChain(chain.String())
	}

	return nil
}
