package usecase

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	signTestSvc          = "test-service"
	signTestPrivateKey   = "3ee65159f7aa057c482b1041f18f37ce90ef5e460cb46fd3fa0c40fbae41c7e1"
	signTestAddress      = "0xBffc2f3Df75367B0f246aF6Ae42AFf59A33f2704"
	signTestPublicKeyHex = "045809f2cb46e0a05b7e535e765dc3c658d2a196170f80570900483a46c7875720a2a885656d77181d1107bee5b2f2758a5be3fe58037693c10e7adf16746367bc"
)

func createSignTestService(t *testing.T, b logical.Backend) logical.Storage {
	t.Helper()
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": signTestSvc,
		"privateKey":  signTestPrivateKey,
	}
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	return req.Storage
}

func TestBackend_sign(t *testing.T) {
	b, _ := newTestBackend(t)

	privateKey, err := crypto.HexToECDSA(signTestPrivateKey)
	require.NoError(t, err)
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	storage := createSignTestService(t, b)

	dataToSign := []byte("data that should be signed")
	hash := crypto.Keccak256Hash(dataToSign)
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+signTestSvc+"/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash":            "0x" + common.Bytes2Hex(hash.Bytes()),
		"address":         address.String(),
		"allowRawSigning": true,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	sig := resp.Data["signature"].(string)

	sigPublicKey, err := crypto.Ecrecover(hash.Bytes(), common.Hex2Bytes(sig))
	require.NoError(t, err)
	assert.Equal(t, sigPublicKey, common.Hex2Bytes(signTestPublicKeyHex))
}

func TestBackend_signCaseInsensitiveAddress(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createSignTestService(t, b)

	hash := crypto.Keccak256Hash([]byte("test"))
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+signTestSvc+"/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash":            "0x" + common.Bytes2Hex(hash.Bytes()),
		"address":         "0xbffc2f3df75367b0f246af6ae42aff59a33f2704",
		"allowRawSigning": true,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Data["signature"])
}

func TestBackend_signEmptyHash(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createSignTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+signTestSvc+"/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash":    "",
		"address": signTestAddress,
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "hash is required")
}

func TestBackend_signInvalidHashHex(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createSignTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+signTestSvc+"/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash":    "not-hex-at-all",
		"address": signTestAddress,
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "invalid hash hex encoding")
}

func TestBackend_signHashWrongLength(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createSignTestService(t, b)

	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+signTestSvc+"/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash":    "0xaabbccdd",
		"address": signTestAddress,
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "hash must be exactly 32 bytes")
}

func TestBackend_signMissingAddress(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createSignTestService(t, b)

	hash := crypto.Keccak256Hash([]byte("test"))
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+signTestSvc+"/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash": "0x" + common.Bytes2Hex(hash.Bytes()),
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "address is required")
}

func TestBackend_signInvalidAddress(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createSignTestService(t, b)

	hash := crypto.Keccak256Hash([]byte("test"))
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+signTestSvc+"/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash":    "0x" + common.Bytes2Hex(hash.Bytes()),
		"address": "not-an-address",
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "invalid Ethereum address")
}

func TestBackend_signNonexistentService(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createSignTestService(t, b)

	hash := crypto.Keccak256Hash([]byte("test"))
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/nonexistent/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash":            "0x" + common.Bytes2Hex(hash.Bytes()),
		"address":         signTestAddress,
		"allowRawSigning": true,
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "does not exist")
}

func TestBackend_signAddressNotInKeyManager(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createSignTestService(t, b)

	hash := crypto.Keccak256Hash([]byte("test"))
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+signTestSvc+"/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash":            "0x" + common.Bytes2Hex(hash.Bytes()),
		"address":         "0x0000000000000000000000000000000000000001",
		"allowRawSigning": true,
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "no private key for the input address")
}

func TestBackend_signStorageError(t *testing.T) {
	b, _ := newTestBackend(t)

	hash := crypto.Keccak256Hash([]byte("test"))
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+signTestSvc+"/sign")
	sm := NewStorageMock(0, 0, 0, 0)
	req.Storage = sm
	req.Data = map[string]interface{}{
		"hash":            "0x" + common.Bytes2Hex(hash.Bytes()),
		"address":         signTestAddress,
		"allowRawSigning": true,
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "error retrieving signing keyManager")
}

func TestBackend_signCorruptStoredKey(t *testing.T) {
	b, _ := newTestBackend(t)
	be := b.(*Backend)

	km := &KeyManager{
		ServiceName: "corrupt-sign-svc",
		KeyPairs: []*KeyPair{
			{
				PrivateKey: "not-valid-hex",
				PublicKey:  "fake",
				Address:    signTestAddress,
			},
		},
	}

	storage := &logical.InmemStorage{}
	entry, err := logical.StorageEntryJSON("key-managers/corrupt-sign-svc", km)
	require.NoError(t, err)
	require.NoError(t, storage.Put(context.Background(), entry))

	hash := crypto.Keccak256Hash([]byte("test"))
	signSchema := map[string]*framework.FieldSchema{
		"name":            {Type: framework.TypeString},
		"hash":            {Type: framework.TypeString, Default: ""},
		"address":         {Type: framework.TypeString},
		"allowRawSigning": {Type: framework.TypeBool, Default: false},
	}
	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":            "corrupt-sign-svc",
			"hash":            "0x" + common.Bytes2Hex(hash.Bytes()),
			"address":         signTestAddress,
			"allowRawSigning": true,
		},
		Schema: signSchema,
	}
	req := &logical.Request{Storage: storage}
	_, err = be.sign(context.Background(), req, data)
	assert.ErrorContains(t, err, "error reconstructing private key")
}

func TestBackend_signEmptyKeyPairs(t *testing.T) {
	b, _ := newTestBackend(t)
	be := b.(*Backend)

	km := &KeyManager{
		ServiceName: "empty-keys-svc",
		KeyPairs:    []*KeyPair{},
	}

	storage := &logical.InmemStorage{}
	entry, err := logical.StorageEntryJSON("key-managers/empty-keys-svc", km)
	require.NoError(t, err)
	require.NoError(t, storage.Put(context.Background(), entry))

	hash := crypto.Keccak256Hash([]byte("test"))
	signSchema := map[string]*framework.FieldSchema{
		"name":            {Type: framework.TypeString},
		"hash":            {Type: framework.TypeString, Default: ""},
		"address":         {Type: framework.TypeString},
		"allowRawSigning": {Type: framework.TypeBool, Default: false},
	}
	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"name":            "empty-keys-svc",
			"hash":            "0x" + common.Bytes2Hex(hash.Bytes()),
			"address":         signTestAddress,
			"allowRawSigning": true,
		},
		Schema: signSchema,
	}
	req := &logical.Request{Storage: storage}
	_, err = be.sign(context.Background(), req, data)
	assert.ErrorContains(t, err, "does not have a key pair")
}

func TestBackend_signDirectEdgeCases(t *testing.T) {
	b, _ := newTestBackend(t)
	be := b.(*Backend)
	ctx := context.Background()

	t.Run("empty name with storage returns key not found", func(t *testing.T) {
		hash := "0x" + common.Bytes2Hex(crypto.Keccak256Hash([]byte("test")).Bytes())
		data := &framework.FieldData{
			Raw: map[string]interface{}{"hash": hash, "address": signTestAddress, "allowRawSigning": true},
			Schema: map[string]*framework.FieldSchema{
				"name":            {Type: framework.TypeString},
				"hash":            {Type: framework.TypeString, Default: ""},
				"address":         {Type: framework.TypeString},
				"allowRawSigning": {Type: framework.TypeBool, Default: false},
			},
		}
		req := &logical.Request{Storage: &logical.InmemStorage{}}
		_, err := be.sign(ctx, req, data)
		require.Error(t, err)
		assert.ErrorContains(t, err, "does not exist")
	})

	t.Run("name field type error", func(t *testing.T) {
		data := &framework.FieldData{
			Raw: map[string]interface{}{"name": 42},
			Schema: map[string]*framework.FieldSchema{
				"name":    {Type: framework.TypeInt},
				"hash":    {Type: framework.TypeString, Default: ""},
				"address": {Type: framework.TypeString},
			},
		}
		req := &logical.Request{Storage: &logical.InmemStorage{}}
		_, err := be.sign(ctx, req, data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("hash field type error", func(t *testing.T) {
		data := &framework.FieldData{
			Raw: map[string]interface{}{"name": "svc", "hash": 42},
			Schema: map[string]*framework.FieldSchema{
				"name": {Type: framework.TypeString},
				"hash": {Type: framework.TypeInt},
				"address": {Type: framework.TypeString},
			},
		}
		req := &logical.Request{Storage: &logical.InmemStorage{}}
		_, err := be.sign(ctx, req, data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("address field type error", func(t *testing.T) {
		hash := "0x" + common.Bytes2Hex(crypto.Keccak256Hash([]byte("test")).Bytes())
		data := &framework.FieldData{
			Raw: map[string]interface{}{"name": "svc", "hash": hash, "address": 42},
			Schema: map[string]*framework.FieldSchema{
				"name":    {Type: framework.TypeString},
				"hash":    {Type: framework.TypeString, Default: ""},
				"address": {Type: framework.TypeInt},
			},
		}
		req := &logical.Request{Storage: &logical.InmemStorage{}}
		_, err := be.sign(ctx, req, data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})
}

func TestBackend_signRequiresUnsafeOptIn(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := createSignTestService(t, b)

	hash := crypto.Keccak256Hash([]byte("test"))
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/"+signTestSvc+"/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash":    "0x" + common.Bytes2Hex(hash.Bytes()),
		"address": signTestAddress,
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "raw hash signing is disabled by default")
}
