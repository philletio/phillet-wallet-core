package errors

import (
	"errors"
	"fmt"
	"strings"
)

// ErrorCode represents standardized error codes
type ErrorCode string

const (
	// Validation errors
	ErrorCodeInvalidInput     ErrorCode = "INVALID_INPUT"
	ErrorCodeMissingField     ErrorCode = "MISSING_FIELD"
	ErrorCodeInvalidFormat    ErrorCode = "INVALID_FORMAT"
	ErrorCodeOutOfRange       ErrorCode = "OUT_OF_RANGE"
	ErrorCodeInvalidChain     ErrorCode = "INVALID_CHAIN"
	ErrorCodeInvalidAddress   ErrorCode = "INVALID_ADDRESS"
	ErrorCodeInvalidMnemonic  ErrorCode = "INVALID_MNEMONIC"
	ErrorCodeInvalidSignature ErrorCode = "INVALID_SIGNATURE"

	// Authentication/Authorization errors
	ErrorCodeUnauthorized ErrorCode = "UNAUTHORIZED"
	ErrorCodeForbidden    ErrorCode = "FORBIDDEN"
	ErrorCodeInvalidToken ErrorCode = "INVALID_TOKEN"
	ErrorCodeTokenExpired ErrorCode = "TOKEN_EXPIRED"

	// Resource errors
	ErrorCodeNotFound          ErrorCode = "NOT_FOUND"
	ErrorCodeAlreadyExists     ErrorCode = "ALREADY_EXISTS"
	ErrorCodeResourceExhausted ErrorCode = "RESOURCE_EXHAUSTED"

	// Business logic errors
	ErrorCodeInsufficientFunds    ErrorCode = "INSUFFICIENT_FUNDS"
	ErrorCodeInvalidTransaction   ErrorCode = "INVALID_TRANSACTION"
	ErrorCodeUnsupportedOperation ErrorCode = "UNSUPPORTED_OPERATION"

	// System errors
	ErrorCodeInternal           ErrorCode = "INTERNAL_ERROR"
	ErrorCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrorCodeTimeout            ErrorCode = "TIMEOUT"
	ErrorCodeDatabaseError      ErrorCode = "DATABASE_ERROR"
	ErrorCodeCacheError         ErrorCode = "CACHE_ERROR"
	ErrorCodeRPCError           ErrorCode = "RPC_ERROR"
	ErrorCodeEncryptionError    ErrorCode = "ENCRYPTION_ERROR"
)

// WalletError represents a structured error with code, message, and details
type WalletError struct {
	Code    ErrorCode         `json:"code"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
	Cause   error             `json:"-"`
}

// Error implements the error interface
func (e *WalletError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *WalletError) Unwrap() error {
	return e.Cause
}

// New creates a new WalletError
func New(code ErrorCode, message string) *WalletError {
	return &WalletError{
		Code:    code,
		Message: message,
		Details: make(map[string]string),
	}
}

// Wrap wraps an existing error with a WalletError
func Wrap(err error, code ErrorCode, message string) *WalletError {
	return &WalletError{
		Code:    code,
		Message: message,
		Cause:   err,
		Details: make(map[string]string),
	}
}

// WithDetail adds a detail to the error
func (e *WalletError) WithDetail(key, value string) *WalletError {
	if e.Details == nil {
		e.Details = make(map[string]string)
	}
	e.Details[key] = value
	return e
}

// WithDetails adds multiple details to the error
func (e *WalletError) WithDetails(details map[string]string) *WalletError {
	if e.Details == nil {
		e.Details = make(map[string]string)
	}
	for k, v := range details {
		e.Details[k] = v
	}
	return e
}

// Common error constructors
func NewInvalidInput(field, reason string) *WalletError {
	return New(ErrorCodeInvalidInput, fmt.Sprintf("Invalid input for field '%s': %s", field, reason)).
		WithDetail("field", field).
		WithDetail("reason", reason)
}

func NewMissingField(field string) *WalletError {
	return New(ErrorCodeMissingField, fmt.Sprintf("Required field '%s' is missing", field)).
		WithDetail("field", field)
}

func NewInvalidFormat(field, format string) *WalletError {
	return New(ErrorCodeInvalidFormat, fmt.Sprintf("Invalid format for field '%s', expected: %s", field, format)).
		WithDetail("field", field).
		WithDetail("expected_format", format)
}

func NewOutOfRange(field string, value, min, max interface{}) *WalletError {
	return New(ErrorCodeOutOfRange, fmt.Sprintf("Field '%s' value %v is out of range [%v, %v]", field, value, min, max)).
		WithDetail("field", field).
		WithDetail("value", fmt.Sprintf("%v", value)).
		WithDetail("min", fmt.Sprintf("%v", min)).
		WithDetail("max", fmt.Sprintf("%v", max))
}

func NewInvalidChain(chain string) *WalletError {
	return New(ErrorCodeInvalidChain, fmt.Sprintf("Invalid or unsupported chain: %s", chain)).
		WithDetail("chain", chain)
}

func NewInvalidAddress(address string) *WalletError {
	return New(ErrorCodeInvalidAddress, fmt.Sprintf("Invalid address format: %s", address)).
		WithDetail("address", address)
}

func NewInvalidMnemonic(reason string) *WalletError {
	return New(ErrorCodeInvalidMnemonic, fmt.Sprintf("Invalid mnemonic: %s", reason)).
		WithDetail("reason", reason)
}

func NewNotFound(resource, id string) *WalletError {
	return New(ErrorCodeNotFound, fmt.Sprintf("%s with ID '%s' not found", resource, id)).
		WithDetail("resource", resource).
		WithDetail("id", id)
}

func NewAlreadyExists(resource, id string) *WalletError {
	return New(ErrorCodeAlreadyExists, fmt.Sprintf("%s with ID '%s' already exists", resource, id)).
		WithDetail("resource", resource).
		WithDetail("id", id)
}

func NewUnauthorized(reason string) *WalletError {
	return New(ErrorCodeUnauthorized, fmt.Sprintf("Unauthorized: %s", reason)).
		WithDetail("reason", reason)
}

func NewInternalError(operation string, cause error) *WalletError {
	return Wrap(cause, ErrorCodeInternal, fmt.Sprintf("Internal error during %s", operation)).
		WithDetail("operation", operation)
}

func NewDatabaseError(operation string, cause error) *WalletError {
	return Wrap(cause, ErrorCodeDatabaseError, fmt.Sprintf("Database error during %s", operation)).
		WithDetail("operation", operation)
}

func NewRPCError(chain, operation string, cause error) *WalletError {
	return Wrap(cause, ErrorCodeRPCError, fmt.Sprintf("RPC error for %s during %s", chain, operation)).
		WithDetail("chain", chain).
		WithDetail("operation", operation)
}

func NewEncryptionError(operation string, cause error) *WalletError {
	return Wrap(cause, ErrorCodeEncryptionError, fmt.Sprintf("Encryption error during %s", operation)).
		WithDetail("operation", operation)
}

// IsWalletError checks if an error is a WalletError
func IsWalletError(err error) bool {
	var walletErr *WalletError
	return errors.As(err, &walletErr)
}

// GetWalletError extracts WalletError from an error chain
func GetWalletError(err error) *WalletError {
	var walletErr *WalletError
	if errors.As(err, &walletErr) {
		return walletErr
	}
	return nil
}

// Validation helpers
func ValidateRequired(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return NewMissingField(field)
	}
	return nil
}

func ValidateRange(field string, value, min, max int) error {
	if value < min || value > max {
		return NewOutOfRange(field, value, min, max)
	}
	return nil
}

func ValidateChain(chain string) error {
	validChains := map[string]bool{
		"ethereum": true,
		"polygon":  true,
		"bsc":      true,
		"solana":   true,
		"ton":      true,
	}
	if !validChains[chain] {
		return NewInvalidChain(chain)
	}
	return nil
}

func ValidateAddress(address string) error {
	if strings.TrimSpace(address) == "" {
		return NewInvalidAddress(address)
	}
	// Basic validation - in production, use proper address validation libraries
	if len(address) < 10 {
		return NewInvalidAddress(address)
	}
	return nil
}

func ValidateMnemonic(mnemonic string) error {
	if strings.TrimSpace(mnemonic) == "" {
		return NewInvalidMnemonic("mnemonic cannot be empty")
	}
	words := strings.Fields(mnemonic)
	if len(words) != 12 && len(words) != 15 && len(words) != 18 && len(words) != 21 && len(words) != 24 {
		return NewInvalidMnemonic("mnemonic must have 12, 15, 18, 21, or 24 words")
	}
	return nil
}
