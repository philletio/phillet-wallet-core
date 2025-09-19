package errors

import (
	"errors"
	"testing"
)

func TestNew(t *testing.T) {
	err := New(ErrorCodeInvalidInput, "test message")

	if err.Code != ErrorCodeInvalidInput {
		t.Errorf("Expected code %s, got %s", ErrorCodeInvalidInput, err.Code)
	}

	if err.Message != "test message" {
		t.Errorf("Expected message 'test message', got '%s'", err.Message)
	}

	if err.Cause != nil {
		t.Errorf("Expected nil cause, got %v", err.Cause)
	}
}

func TestWrap(t *testing.T) {
	originalErr := errors.New("original error")
	err := Wrap(originalErr, ErrorCodeInternal, "wrapped message")

	if err.Code != ErrorCodeInternal {
		t.Errorf("Expected code %s, got %s", ErrorCodeInternal, err.Code)
	}

	if err.Message != "wrapped message" {
		t.Errorf("Expected message 'wrapped message', got '%s'", err.Message)
	}

	if err.Cause != originalErr {
		t.Errorf("Expected cause to be original error, got %v", err.Cause)
	}
}

func TestWithDetail(t *testing.T) {
	err := New(ErrorCodeInvalidInput, "test message")
	err = err.WithDetail("field", "value")

	if err.Details["field"] != "value" {
		t.Errorf("Expected detail 'field' to be 'value', got '%s'", err.Details["field"])
	}
}

func TestWithDetails(t *testing.T) {
	err := New(ErrorCodeInvalidInput, "test message")
	details := map[string]string{
		"field1": "value1",
		"field2": "value2",
	}
	err = err.WithDetails(details)

	if err.Details["field1"] != "value1" {
		t.Errorf("Expected detail 'field1' to be 'value1', got '%s'", err.Details["field1"])
	}

	if err.Details["field2"] != "value2" {
		t.Errorf("Expected detail 'field2' to be 'value2', got '%s'", err.Details["field2"])
	}
}

func TestError(t *testing.T) {
	err := New(ErrorCodeInvalidInput, "test message")
	errorString := err.Error()

	expected := "[INVALID_INPUT] test message"
	if errorString != expected {
		t.Errorf("Expected error string '%s', got '%s'", expected, errorString)
	}
}

func TestErrorWithCause(t *testing.T) {
	originalErr := errors.New("original error")
	err := Wrap(originalErr, ErrorCodeInternal, "wrapped message")
	errorString := err.Error()

	expected := "[INTERNAL_ERROR] wrapped message: original error"
	if errorString != expected {
		t.Errorf("Expected error string '%s', got '%s'", expected, errorString)
	}
}

func TestUnwrap(t *testing.T) {
	originalErr := errors.New("original error")
	err := Wrap(originalErr, ErrorCodeInternal, "wrapped message")

	unwrapped := err.Unwrap()
	if unwrapped != originalErr {
		t.Errorf("Expected unwrapped error to be original error, got %v", unwrapped)
	}
}

func TestIsWalletError(t *testing.T) {
	walletErr := New(ErrorCodeInvalidInput, "test message")
	regularErr := errors.New("regular error")

	if !IsWalletError(walletErr) {
		t.Error("Expected IsWalletError to return true for WalletError")
	}

	if IsWalletError(regularErr) {
		t.Error("Expected IsWalletError to return false for regular error")
	}
}

func TestGetWalletError(t *testing.T) {
	walletErr := New(ErrorCodeInvalidInput, "test message")
	regularErr := errors.New("regular error")

	retrievedErr := GetWalletError(walletErr)
	if retrievedErr != walletErr {
		t.Error("Expected GetWalletError to return the same WalletError")
	}

	retrievedErr = GetWalletError(regularErr)
	if retrievedErr != nil {
		t.Error("Expected GetWalletError to return nil for regular error")
	}
}

func TestNewInvalidInput(t *testing.T) {
	err := NewInvalidInput("field", "reason")

	if err.Code != ErrorCodeInvalidInput {
		t.Errorf("Expected code %s, got %s", ErrorCodeInvalidInput, err.Code)
	}

	if err.Details["field"] != "field" {
		t.Errorf("Expected detail 'field' to be 'field', got '%s'", err.Details["field"])
	}

	if err.Details["reason"] != "reason" {
		t.Errorf("Expected detail 'reason' to be 'reason', got '%s'", err.Details["reason"])
	}
}

func TestNewMissingField(t *testing.T) {
	err := NewMissingField("field")

	if err.Code != ErrorCodeMissingField {
		t.Errorf("Expected code %s, got %s", ErrorCodeMissingField, err.Code)
	}

	if err.Details["field"] != "field" {
		t.Errorf("Expected detail 'field' to be 'field', got '%s'", err.Details["field"])
	}
}

func TestNewNotFound(t *testing.T) {
	err := NewNotFound("wallet", "123")

	if err.Code != ErrorCodeNotFound {
		t.Errorf("Expected code %s, got %s", ErrorCodeNotFound, err.Code)
	}

	if err.Details["resource"] != "wallet" {
		t.Errorf("Expected detail 'resource' to be 'wallet', got '%s'", err.Details["resource"])
	}

	if err.Details["id"] != "123" {
		t.Errorf("Expected detail 'id' to be '123', got '%s'", err.Details["id"])
	}
}

func TestValidateRequired(t *testing.T) {
	err := ValidateRequired("field", "")
	if err == nil {
		t.Error("Expected ValidateRequired to return error for empty string")
	}

	err = ValidateRequired("field", "value")
	if err != nil {
		t.Error("Expected ValidateRequired to return nil for non-empty string")
	}
}

func TestValidateRange(t *testing.T) {
	err := ValidateRange("field", 5, 1, 10)
	if err != nil {
		t.Error("Expected ValidateRange to return nil for value in range")
	}

	err = ValidateRange("field", 0, 1, 10)
	if err == nil {
		t.Error("Expected ValidateRange to return error for value below range")
	}

	err = ValidateRange("field", 15, 1, 10)
	if err == nil {
		t.Error("Expected ValidateRange to return error for value above range")
	}
}

func TestValidateChain(t *testing.T) {
	err := ValidateChain("ethereum")
	if err != nil {
		t.Error("Expected ValidateChain to return nil for valid chain")
	}

	err = ValidateChain("invalid")
	if err == nil {
		t.Error("Expected ValidateChain to return error for invalid chain")
	}
}

func TestValidateAddress(t *testing.T) {
	err := ValidateAddress("0x1234567890123456789012345678901234567890")
	if err != nil {
		t.Error("Expected ValidateAddress to return nil for valid address")
	}

	err = ValidateAddress("")
	if err == nil {
		t.Error("Expected ValidateAddress to return error for empty address")
	}

	err = ValidateAddress("short")
	if err == nil {
		t.Error("Expected ValidateAddress to return error for short address")
	}
}

func TestValidateMnemonic(t *testing.T) {
	err := ValidateMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Error("Expected ValidateMnemonic to return nil for valid 12-word mnemonic")
	}

	err = ValidateMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if err != nil {
		t.Error("Expected ValidateMnemonic to return nil for valid 24-word mnemonic")
	}

	err = ValidateMnemonic("")
	if err == nil {
		t.Error("Expected ValidateMnemonic to return error for empty mnemonic")
	}

	err = ValidateMnemonic("abandon abandon")
	if err == nil {
		t.Error("Expected ValidateMnemonic to return error for invalid word count")
	}
}
