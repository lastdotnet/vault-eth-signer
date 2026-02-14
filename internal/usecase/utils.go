package usecase

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"regexp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/hashicorp/vault/sdk/framework"
)

var (
	errInvalidType = errors.New("invalid input type")

	// serviceNameRegex validates service names to prevent storage key injection.
	// Only allows alphanumeric, dots, hyphens, and underscores. No slashes, no path traversal.
	serviceNameRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
)

// validateServiceName ensures the service name is safe for use as a storage key component.
// Rejects empty strings, path traversal attempts (../), slashes, and control characters.
func validateServiceName(name string) error {
	if name == "" {
		return fmt.Errorf("serviceName is required")
	}
	if !serviceNameRegex.MatchString(name) {
		return fmt.Errorf("serviceName must be 1-64 chars, alphanumeric/dot/hyphen/underscore, no slashes or special chars")
	}
	return nil
}

// getStringField safely extracts a string field from FieldData without panicking on type assertion.
func getStringField(data *framework.FieldData, field string) (string, error) {
	raw, ok := data.GetOk(field)
	if !ok {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("field %q: %w", field, errInvalidType)
	}
	return s, nil
}

func newTransactionWithDynamicFee(
	to *common.Address,
	nonce uint64,
	gasFeeCap *big.Int,
	gasTipCap *big.Int,
	gas uint64,
	data []byte,
	value *big.Int,
	chainID *big.Int,
	accessList types.AccessList,
) *types.Transaction {
	return types.NewTx(&types.DynamicFeeTx{
		ChainID:    chainID,
		To:         to,
		Nonce:      nonce,
		GasFeeCap:  gasFeeCap,
		GasTipCap:  gasTipCap,
		Gas:        gas,
		Value:      value,
		Data:       data,
		AccessList: accessList,
	})
}

func newLegacyTransaction(
	to *common.Address,
	nonce uint64,
	gasPrice *big.Int,
	gas uint64,
	data []byte,
	value *big.Int,
) *types.Transaction {
	return types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gas,
		To:       to,
		Value:    value,
		Data:     data,
	})
}

func zeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

func validNumber(input string) *big.Int {
	if input == "" {
		return big.NewInt(0)
	}
	matched, err := regexp.MatchString("([0-9])", input)
	if !matched || err != nil {
		return nil
	}
	amount, ok := math.ParseBig256(input)
	if !ok {
		return nil
	}
	if amount.Sign() < 0 {
		return nil
	}
	return amount
}


