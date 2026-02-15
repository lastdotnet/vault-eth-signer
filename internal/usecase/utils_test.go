package usecase

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestKey() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

func TestValidateServiceName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{"valid simple", "my-service", false, ""},
		{"valid with dots", "my.service.v2", false, ""},
		{"valid with underscores", "my_service_123", false, ""},
		{"valid single char", "a", false, ""},
		{"valid max length", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false, ""},
		{"empty string", "", true, "serviceName is required"},
		{"path traversal", "../secrets", true, "serviceName must be"},
		{"contains slash", "my/service", true, "serviceName must be"},
		{"contains backslash", "my\\service", true, "serviceName must be"},
		{"starts with dot", ".hidden", true, "serviceName must be"},
		{"starts with hyphen", "-invalid", true, "serviceName must be"},
		{"too long", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX", true, "serviceName must be"},
		{"contains space", "my service", true, "serviceName must be"},
		{"contains percent", "my%2fservice", true, "serviceName must be"},
		{"null byte", "my\x00service", true, "serviceName must be"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateServiceName(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidNumber(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   *big.Int
		isNil  bool
	}{
		{"empty string", "", big.NewInt(0), false},
		{"zero", "0", big.NewInt(0), false},
		{"positive integer", "12345", big.NewInt(12345), false},
		{"hex with 0x prefix", "0x10", big.NewInt(16), false},
		{"hex nonce", "0x2", big.NewInt(2), false},
		{"no digits", "abc", nil, true},
		{"just letters", "xyz", nil, true},
		{"negative number", "-1", nil, true},
		{"very large number", "115792089237316195423570985008687907853269984665640564039457584007913129639935", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validNumber(tc.input)
			if tc.isNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				if tc.want != nil {
					assert.Equal(t, 0, result.Cmp(tc.want), "expected %s got %s", tc.want.String(), result.String())
				}
			}
		})
	}
}

func TestZeroKey(t *testing.T) {
	key, err := generateTestKey()
	require.NoError(t, err)

	origBits := make([]big.Word, len(key.D.Bits()))
	copy(origBits, key.D.Bits())
	assert.NotEmpty(t, origBits)

	zeroKey(key)

	for _, b := range key.D.Bits() {
		assert.Equal(t, big.Word(0), b)
	}
}

func TestGetStringField(t *testing.T) {
	schema := map[string]*framework.FieldSchema{
		"name":    {Type: framework.TypeString},
		"missing": {Type: framework.TypeString},
	}

	t.Run("present string field", func(t *testing.T) {
		data := &framework.FieldData{
			Raw:    map[string]interface{}{"name": "hello"},
			Schema: schema,
		}
		val, err := getStringField(data, "name")
		require.NoError(t, err)
		assert.Equal(t, "hello", val)
	})

	t.Run("absent field returns empty", func(t *testing.T) {
		data := &framework.FieldData{
			Raw:    map[string]interface{}{},
			Schema: schema,
		}
		val, err := getStringField(data, "missing")
		require.NoError(t, err)
		assert.Equal(t, "", val)
	})

	t.Run("integer coerced to string by SDK", func(t *testing.T) {
		data := &framework.FieldData{
			Raw:    map[string]interface{}{"name": 12345},
			Schema: schema,
		}
		val, err := getStringField(data, "name")
		require.NoError(t, err)
		assert.Equal(t, "12345", val)
	})

	t.Run("non-string type from non-string schema triggers error", func(t *testing.T) {
		intSchema := map[string]*framework.FieldSchema{
			"count": {Type: framework.TypeInt},
		}
		data := &framework.FieldData{
			Raw:    map[string]interface{}{"count": 42},
			Schema: intSchema,
		}
		_, err := getStringField(data, "count")
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})
}

func TestGetBoolField(t *testing.T) {
	schema := map[string]*framework.FieldSchema{
		"flag": {Type: framework.TypeBool, Default: false},
	}

	t.Run("present bool field", func(t *testing.T) {
		data := &framework.FieldData{
			Raw:    map[string]interface{}{"flag": true},
			Schema: schema,
		}
		val, err := getBoolField(data, "flag")
		require.NoError(t, err)
		assert.True(t, val)
	})

	t.Run("absent field returns false", func(t *testing.T) {
		data := &framework.FieldData{
			Raw:    map[string]interface{}{},
			Schema: schema,
		}
		val, err := getBoolField(data, "flag")
		require.NoError(t, err)
		assert.False(t, val)
	})

	t.Run("type mismatch returns error", func(t *testing.T) {
		badSchema := map[string]*framework.FieldSchema{
			"flag": {Type: framework.TypeString},
		}
		data := &framework.FieldData{
			Raw:    map[string]interface{}{"flag": "true"},
			Schema: badSchema,
		}
		_, err := getBoolField(data, "flag")
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})
}

func TestUint64FromBig(t *testing.T) {
	val, err := uint64FromBig(big.NewInt(1))
	require.NoError(t, err)
	assert.Equal(t, uint64(1), val)

	overflow := new(big.Int).Add(new(big.Int).SetUint64(^uint64(0)), big.NewInt(1))
	_, err = uint64FromBig(overflow)
	require.Error(t, err)
	assert.ErrorIs(t, err, errValueTooLarge)
}

func TestNewTransactionWithDynamicFee(t *testing.T) {
	to := common.HexToAddress("0xf809410b0d6f047c603deb311979cd413e025a84")
	tx := newTransactionWithDynamicFee(
		&to, 5, big.NewInt(100), big.NewInt(10), 21000,
		[]byte{0x01}, big.NewInt(0), big.NewInt(1), nil,
	)
	assert.Equal(t, uint64(5), tx.Nonce())
	assert.Equal(t, uint64(21000), tx.Gas())
	assert.Equal(t, big.NewInt(100), tx.GasFeeCap())
	assert.Equal(t, big.NewInt(10), tx.GasTipCap())
}

func TestNewLegacyTransaction(t *testing.T) {
	to := common.HexToAddress("0xf809410b0d6f047c603deb311979cd413e025a84")
	tx := newLegacyTransaction(&to, 3, big.NewInt(50), 21000, []byte{0x01}, big.NewInt(0))
	assert.Equal(t, uint64(3), tx.Nonce())
	assert.Equal(t, uint64(21000), tx.Gas())
	assert.Equal(t, big.NewInt(50), tx.GasPrice())
}

func TestNewLegacyTransactionContractCreation(t *testing.T) {
	tx := newLegacyTransaction(nil, 0, big.NewInt(0), 90000, []byte{0xab, 0xcd}, big.NewInt(0))
	assert.Nil(t, tx.To())
}
