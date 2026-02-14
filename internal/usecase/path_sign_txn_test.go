package usecase

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	txTestSvc     = "keeper-service"
	txTestPK      = "3ee65159f7aa057c482b1041f18f37ce90ef5e460cb46fd3fa0c40fbae41c7e1"
	txTestAddress = "0xBffc2f3Df75367B0f246aF6Ae42AFf59A33f2704"
	txTestTo      = "0xf809410b0d6f047c603deb311979cd413e025a84"
	txTestData    = "60fe47b10000000000000000000000000000000000000000000000000000000000000014"
)

func createTxTestService(t *testing.T, b logical.Backend) logical.Storage {
	t.Helper()
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": txTestSvc,
		"privateKey":  txTestPK,
	}
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	storage := req.Storage

	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"serviceName": txTestSvc,
	}
	_, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	return storage
}

func validTxData() map[string]interface{} {
	return map[string]interface{}{
		"address":  txTestAddress,
		"data":     txTestData,
		"to":       txTestTo,
		"gas":      "2000",
		"nonce":    "0x2",
		"gasPrice": "0",
		"chainId":  "1",
	}
}

func TestBackend_signTx(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.ReadOperation, "key-managers/"+txTestSvc)
	req.Storage = storage
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Len(t, resp.Data["addresses"], 2)

	pk, err := crypto.HexToECDSA(txTestPK)
	require.NoError(t, err)
	publicKeyECDSA, ok := pk.Public().(*ecdsa.PublicKey)
	require.True(t, ok)
	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	contractData := "608060405234801561001057600080fd5b506040516020806101d783398101604052516000556101a3806100346000396000f3006080604052600436106100615763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416632a1afcd981146100665780632c46b2051461008d57806360fe47b1146100a25780636d4ce63c1461008d575b600080fd5b34801561007257600080fd5b5061007b6100ba565b60408051918252519081900360200190f35b34801561009957600080fd5b5061007b6100c0565b3480156100ae57600080fd5b5061007b6004356100c6565b60005481565b60005490565b60006064821061013757604080517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601960248201527f56616c75652063616e206e6f74206265206f7665722031303000000000000000604482015290519081900360640190fd5b60008290556040805183815290517f9455957c3b77d1d4ed071e2b469dd77e37fc5dfd3b4d44dc8a997cc97c7b3d499181900360200190a15050600054905600a165627a7a72305820a22d4674e519555e6f065ccf98b5bd479e108895cbddc10cba200c775d0008730029000000000000000000000000000000000000000000000000000000000000000a"
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"address":  txTestAddress,
		"data":     contractData,
		"gas":      2000,
		"nonce":    "0x2",
		"gasPrice": 0,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	tx := &types.Transaction{}
	signatureBytes, err := hexutil.Decode(resp.Data["signedTx"].(string))
	require.NoError(t, err)
	err = tx.DecodeRLP(rlp.NewStream(bytes.NewReader(signatureBytes), 0))
	require.NoError(t, err)

	v, _, _ := tx.RawSignatureValues()
	assert.True(t, v.Cmp(big.NewInt(27)) == 0 || v.Cmp(big.NewInt(28)) == 0, "v should be 27 or 28")
	sender, _ := types.Sender(types.HomesteadSigner{}, tx)
	assert.Equal(t, address.Hex(), sender.Hex())

	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"data":     txTestData,
		"address":  txTestAddress,
		"to":       txTestTo,
		"gas":      2000,
		"nonce":    "0x3",
		"gasPrice": 0,
		"chainId":  "12345",
	}
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	tx = &types.Transaction{}
	signatureBytes, err = hexutil.Decode(resp.Data["signedTx"].(string))
	require.NoError(t, err)
	err = tx.DecodeRLP(rlp.NewStream(bytes.NewReader(signatureBytes), 0))
	require.NoError(t, err)

	v, _, _ = tx.RawSignatureValues()
	assert.True(t, v.Cmp(big.NewInt(24725)) == 0 || v.Cmp(big.NewInt(24726)) == 0, "v should be 24725 or 24726")
	sender, _ = types.Sender(types.LatestSignerForChainID(big.NewInt(12345)), tx)
	assert.Equal(t, address.Hex(), sender.Hex())

	req.Data = map[string]interface{}{
		"input":     txTestData,
		"address":   txTestAddress,
		"to":        txTestTo,
		"gas":       2500,
		"nonce":     "0x3",
		"gasFeeCap": "1",
		"gasTipCap": "0",
		"chainId":   "1",
	}
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	tx = &types.Transaction{}
	signatureBytes, err = hexutil.Decode(resp.Data["signedTx"].(string))
	require.NoError(t, err)
	err = tx.DecodeRLP(rlp.NewStream(bytes.NewReader(signatureBytes), 0))
	require.NoError(t, err)

	v, _, _ = tx.RawSignatureValues()
	assert.True(t, v.Cmp(big.NewInt(1)) == 0)
	sender, _ = types.Sender(types.LatestSignerForChainID(big.NewInt(1)), tx)
	assert.Equal(t, address.Hex(), sender.Hex())
}

func TestBackend_signTxInvalidNonce(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	data := validTxData()
	data["nonce"] = "0x"
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "invalid nonce")
}

func TestBackend_signTxMissingDataAndInput(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"address":  txTestAddress,
		"to":       txTestTo,
		"gas":      "2000",
		"nonce":    "0x2",
		"gasPrice": "0",
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "either 'data' or 'input' field is required")
}

func TestBackend_signTxInvalidHexData(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	data := validTxData()
	data["data"] = "0xZZZZnotvalidhex"
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	require.Error(t, err)
}

func TestBackend_signTxMissingAddress(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	data := validTxData()
	delete(data, "address")
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "address is required")
}

func TestBackend_signTxInvalidAddress(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	data := validTxData()
	data["address"] = "not-an-address"
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "invalid Ethereum address")
}

func TestBackend_signTxInvalidValue(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	data := validTxData()
	data["value"] = "not-a-number"
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "invalid amount")
}

func TestBackend_signTxInvalidToAddress(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	data := validTxData()
	data["to"] = "not-an-address"
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "invalid 'to' address")
}

func TestBackend_signTxNilGasPriceLegacy(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	data := validTxData()
	data["gasPrice"] = "abc"
	delete(data, "gasFeeCap")
	delete(data, "gasTipCap")
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "invalid gas price")
}

func TestBackend_signTxInvalidGasFeeCap(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	data := validTxData()
	data["gasFeeCap"] = "invalid"
	data["gasTipCap"] = "0"
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "invalid gasFeeCap")
}

func TestBackend_signTxInvalidGasTipCap(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	data := validTxData()
	data["gasFeeCap"] = "1"
	data["gasTipCap"] = "invalid"
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "invalid gasTipCap")
}

func TestBackend_signTxInvalidChainId(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	data := validTxData()
	data["chainId"] = "not-a-chain"
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "invalid chainId")
}

func TestBackend_signTxInvalidGasLimit(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	data := validTxData()
	data["gas"] = "not-a-number"
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "invalid gas limit")
}

func TestBackend_signTxContractCreation(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"address":  txTestAddress,
		"data":     txTestData,
		"gas":      "90000",
		"nonce":    "0x0",
		"gasPrice": "0",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Data["signedTx"])
	assert.NotEmpty(t, resp.Data["txHash"])
}

func TestBackend_signTxNonexistentService(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/nonexistent/txn/sign")
	req.Storage = storage
	data := validTxData()
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "does not exist")
}

func TestBackend_signTxAddressMismatch(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	data := validTxData()
	data["address"] = "0x0000000000000000000000000000000000000001"
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "no private key for the input address")
}

func TestBackend_signTxStorageError(t *testing.T) {
	b, _ := newTestBackend(t)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	sm := NewStorageMock(0, 0, 0, 0)
	req.Storage = sm
	data := validTxData()
	req.Data = data
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "error retrieving signing keyManager")
}

func TestBackend_signTxCorruptStoredKey(t *testing.T) {
	b, _ := newTestBackend(t)
	be := b.(*Backend)

	km := &KeyManager{
		ServiceName: "corrupt-svc",
		KeyPairs: []*KeyPair{
			{
				PrivateKey: "not-a-valid-hex-key-at-all",
				PublicKey:  "fake",
				Address:    txTestAddress,
			},
		},
	}

	storage := &logical.InmemStorage{}
	entry, err := logical.StorageEntryJSON("key-managers/corrupt-svc", km)
	require.NoError(t, err)
	require.NoError(t, storage.Put(context.Background(), entry))

	txSchema := map[string]*framework.FieldSchema{
		"name":       {Type: framework.TypeString},
		"data":       {Type: framework.TypeString},
		"input":      {Type: framework.TypeString},
		"address":    {Type: framework.TypeString},
		"to":         {Type: framework.TypeString, Default: ""},
		"value":      {Type: framework.TypeString},
		"nonce":      {Type: framework.TypeString},
		"gas":        {Type: framework.TypeString, Default: "90000"},
		"gasPrice":   {Type: framework.TypeString, Default: "0"},
		"gasFeeCap":  {Type: framework.TypeString},
		"gasTipCap":  {Type: framework.TypeString},
		"chainId":    {Type: framework.TypeString, Default: "0"},
		"accessList": {Type: framework.TypeString, Default: ""},
	}
	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"name": "corrupt-svc", "data": txTestData, "address": txTestAddress,
			"to": txTestTo, "gas": "90000", "nonce": "0x0", "gasPrice": "0",
		},
		Schema: txSchema,
	}
	req := &logical.Request{Storage: storage}
	_, err = be.signTx(context.Background(), req, data)
	assert.ErrorContains(t, err, "error reconstructing private key")
}

func TestBackend_signTxWithAccessList(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"address":    txTestAddress,
		"data":       txTestData,
		"to":         txTestTo,
		"gas":        "2000",
		"nonce":      "0x5",
		"gasFeeCap":  "100",
		"gasTipCap":  "10",
		"chainId":    "1",
		"accessList": `[{"address":"0xf809410b0d6f047c603deb311979cd413e025a84","storageKeys":["0x0000000000000000000000000000000000000000000000000000000000000000"]}]`,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Data["signedTx"])
}

func TestBackend_signTxInvalidAccessList(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"address":    txTestAddress,
		"data":       txTestData,
		"to":         txTestTo,
		"gas":        "2000",
		"nonce":      "0x5",
		"gasFeeCap":  "100",
		"gasTipCap":  "10",
		"chainId":    "1",
		"accessList": `{not valid json`,
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "invalid accessList JSON")
}

func TestBackend_signTxCaseInsensitiveAddress(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	data := validTxData()
	data["address"] = "0xbffc2f3df75367b0f246af6ae42aff59a33f2704"
	req.Data = data
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Data["signedTx"])
}

func TestBackend_signTxInputFieldFallback(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createTxTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+txTestSvc+"/txn/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"address":  txTestAddress,
		"input":    txTestData,
		"to":       txTestTo,
		"gas":      "2000",
		"nonce":    "0x2",
		"gasPrice": "0",
		"chainId":  "1",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Data["signedTx"])
}

func TestBackend_signTxValidateAndGetTxEdgeCases(t *testing.T) {
	b, _ := newTestBackend(t)
	be := b.(*Backend)

	goodSchema := func() map[string]*framework.FieldSchema {
		return map[string]*framework.FieldSchema{
			"name":       {Type: framework.TypeString},
			"data":       {Type: framework.TypeString},
			"input":      {Type: framework.TypeString},
			"address":    {Type: framework.TypeString},
			"to":         {Type: framework.TypeString, Default: ""},
			"value":      {Type: framework.TypeString},
			"nonce":      {Type: framework.TypeString},
			"gas":        {Type: framework.TypeString, Default: "90000"},
			"gasPrice":   {Type: framework.TypeString, Default: "0"},
			"gasFeeCap":  {Type: framework.TypeString},
			"gasTipCap":  {Type: framework.TypeString},
			"chainId":    {Type: framework.TypeString, Default: "0"},
			"accessList": {Type: framework.TypeString, Default: ""},
		}
	}

	goodRaw := func() map[string]interface{} {
		return map[string]interface{}{
			"name": "svc", "data": txTestData, "address": txTestAddress,
			"to": txTestTo, "gas": "90000", "nonce": "0x0", "gasPrice": "0",
		}
	}

	t.Run("data without 0x prefix gets normalized", func(t *testing.T) {
		data := &framework.FieldData{
			Raw: map[string]interface{}{
				"name": "svc", "data": "aabbcc", "address": txTestAddress,
				"to": txTestTo, "gas": "90000", "nonce": "0x0", "gasPrice": "0",
			},
			Schema: goodSchema(),
		}
		result, err := be.validateAndGetTx(data)
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("short data (<=2 chars) fails decode", func(t *testing.T) {
		data := &framework.FieldData{
			Raw: map[string]interface{}{
				"name": "svc", "data": "ab", "address": txTestAddress,
				"to": txTestTo, "gas": "90000", "nonce": "0x0", "gasPrice": "0",
			},
			Schema: goodSchema(),
		}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
	})

	t.Run("name field type error", func(t *testing.T) {
		s := goodSchema()
		s["name"] = &framework.FieldSchema{Type: framework.TypeInt}
		data := &framework.FieldData{Raw: map[string]interface{}{"name": 42}, Schema: s}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("data field type error", func(t *testing.T) {
		s := goodSchema()
		s["data"] = &framework.FieldSchema{Type: framework.TypeInt}
		r := goodRaw()
		r["data"] = 42
		data := &framework.FieldData{Raw: r, Schema: s}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("input field type error when data empty", func(t *testing.T) {
		s := goodSchema()
		s["input"] = &framework.FieldSchema{Type: framework.TypeInt}
		r := goodRaw()
		delete(r, "data")
		r["input"] = 42
		data := &framework.FieldData{Raw: r, Schema: s}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("address field type error", func(t *testing.T) {
		s := goodSchema()
		s["address"] = &framework.FieldSchema{Type: framework.TypeInt}
		r := goodRaw()
		r["address"] = 42
		data := &framework.FieldData{Raw: r, Schema: s}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("value field type error", func(t *testing.T) {
		s := goodSchema()
		s["value"] = &framework.FieldSchema{Type: framework.TypeInt}
		r := goodRaw()
		r["value"] = 42
		data := &framework.FieldData{Raw: r, Schema: s}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("to field type error", func(t *testing.T) {
		s := goodSchema()
		s["to"] = &framework.FieldSchema{Type: framework.TypeInt}
		r := goodRaw()
		r["to"] = 42
		data := &framework.FieldData{Raw: r, Schema: s}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("chainId field type error", func(t *testing.T) {
		s := goodSchema()
		s["chainId"] = &framework.FieldSchema{Type: framework.TypeInt}
		r := goodRaw()
		r["chainId"] = 42
		data := &framework.FieldData{Raw: r, Schema: s}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("gas field type error", func(t *testing.T) {
		s := goodSchema()
		s["gas"] = &framework.FieldSchema{Type: framework.TypeInt}
		r := goodRaw()
		r["gas"] = 42
		data := &framework.FieldData{Raw: r, Schema: s}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("gasPrice field type error", func(t *testing.T) {
		s := goodSchema()
		s["gasPrice"] = &framework.FieldSchema{Type: framework.TypeInt}
		r := goodRaw()
		r["gasPrice"] = 42
		data := &framework.FieldData{Raw: r, Schema: s}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("gasFeeCap field type error", func(t *testing.T) {
		s := goodSchema()
		s["gasFeeCap"] = &framework.FieldSchema{Type: framework.TypeInt}
		r := goodRaw()
		r["gasFeeCap"] = 42
		data := &framework.FieldData{Raw: r, Schema: s}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("gasTipCap field type error", func(t *testing.T) {
		s := goodSchema()
		s["gasTipCap"] = &framework.FieldSchema{Type: framework.TypeInt}
		r := goodRaw()
		r["gasTipCap"] = 42
		data := &framework.FieldData{Raw: r, Schema: s}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("nonce field type error", func(t *testing.T) {
		s := goodSchema()
		s["nonce"] = &framework.FieldSchema{Type: framework.TypeInt}
		r := goodRaw()
		r["nonce"] = 42
		data := &framework.FieldData{Raw: r, Schema: s}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("accessList field type error in dynamic fee path", func(t *testing.T) {
		s := goodSchema()
		s["accessList"] = &framework.FieldSchema{Type: framework.TypeInt}
		r := goodRaw()
		r["gasFeeCap"] = "100"
		r["gasTipCap"] = "10"
		r["nonce"] = "0x1"
		r["accessList"] = 42
		data := &framework.FieldData{Raw: r, Schema: s}
		_, err := be.validateAndGetTx(data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})
}
