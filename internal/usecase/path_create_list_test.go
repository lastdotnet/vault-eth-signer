package usecase

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackend_createKeyManager(t *testing.T) {
	b, _ := newTestBackend(t)

	const (
		testSvc1 = "test1-service"
		testSvc2 = "test2-service"
	)

	// create test1
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data["serviceName"] = testSvc2
	storage := req.Storage
	_, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// create test2
	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"serviceName": testSvc1,
		"privateKey":  "3ee65159f7aa057c482b1041f18f37ce90ef5e460cb46fd3fa0c40fbae41c7e1",
	}
	_, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	req = logical.TestRequest(t, logical.ListOperation, "key-managers")
	req.Storage = storage
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	expectedList := &logical.Response{
		Data: map[string]interface{}{
			"keys": []string{testSvc1, testSvc2},
		},
	}

	assert.Equal(t, expectedList, resp)

	// read key-manager by service name
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/"+testSvc1)
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	expectedKm := &logical.Response{
		Data: map[string]interface{}{
			"service_name": testSvc1,
			"addresses": []string{
				"0xBffc2f3Df75367B0f246aF6Ae42AFf59A33f2704",
			},
		},
	}

	assert.Equal(t, expectedKm, resp)
}

func TestBackend_createKeyManagerFailure1(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": "valid-service",
	}
	sm := NewStorageMock(0, 1, 0, 0)
	req.Storage = sm
	_, err := b.HandleRequest(context.Background(), req)

	assert.ErrorContains(t, err, "failed to put")
}

func TestBackend_createKeyManagerFailure2(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	data := map[string]interface{}{
		"serviceName": "test-service",
		"privateKey":  "abc",
	}
	req.Data = data
	sm := NewStorageMock(0, 1, 0, 0)
	req.Storage = sm
	_, err := b.HandleRequest(context.Background(), req)

	assert.Equal(t, "privateKey must be a 32-byte hexadecimal string", err.Error())
}

func TestBackend_createKeyManagerFailure3(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	data := map[string]interface{}{
		"serviceName": "test-service",
		// use N for the secp256k1 curve to trigger an error
		"privateKey": "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
	}
	req.Data = data
	sm := NewStorageMock(0, 1, 0, 0)
	req.Storage = sm
	_, err := b.HandleRequest(context.Background(), req)

	assert.Equal(t, "error reconstructing private key from input hex, invalid private key, >=N", err.Error())
}

func TestBackend_listPoliciesFailure1(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.ListOperation, "key-managers")
	sm := NewStorageMock(0, 0, 0, 0)
	req.Storage = sm
	_, err := b.HandleRequest(context.Background(), req)

	assert.Equal(t, "failed to list", err.Error())
}

func TestBackend_createKeyManagerEmptyServiceName(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": "",
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "serviceName is required")
}

func TestBackend_createKeyManagerPathTraversal(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": "../secrets",
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "serviceName must be")
}

func TestBackend_createKeyManagerSlashInName(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": "my/service",
	}
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "serviceName must be")
}

func TestBackend_createKeyManagerWith0xPrefix(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": "prefix-svc",
		"privateKey":  "0x3ee65159f7aa057c482b1041f18f37ce90ef5e460cb46fd3fa0c40fbae41c7e1",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, "0xBffc2f3Df75367B0f246aF6Ae42AFf59A33f2704", resp.Data["address"])
}

func TestBackend_createKeyManagerDuplicateAddressNotAppended(t *testing.T) {
	b, _ := newTestBackend(t)
	storageReq := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	storage := storageReq.Storage

	for i := 0; i < 2; i++ {
		req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
		req.Storage = storage
		req.Data = map[string]interface{}{
			"serviceName": "dupe-svc",
			"privateKey":  "3ee65159f7aa057c482b1041f18f37ce90ef5e460cb46fd3fa0c40fbae41c7e1",
		}
		_, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
	}

	req := logical.TestRequest(t, logical.ReadOperation, "key-managers/dupe-svc")
	req.Storage = storage
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Len(t, resp.Data["addresses"], 1)
}

func TestBackend_createKeyManagerStorageRetrievalError(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": "err-svc",
	}
	sm := NewStorageMock(0, 0, 0, 0)
	req.Storage = sm
	_, err := b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "failed to get")
}

func TestBackend_createKeyManagerAppendToExisting(t *testing.T) {
	b, _ := newTestBackend(t)

	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": "append-svc",
	}
	storage := req.Storage
	_, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)

	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"serviceName": "append-svc",
	}
	_, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)

	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/append-svc")
	req.Storage = storage
	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Len(t, resp.Data["addresses"], 2)
}

func TestBackend_listKeyManagersSuccess(t *testing.T) {
	b, _ := newTestBackend(t)
	sm := NewStorageMock(1, 0, 0, 0)
	req := logical.TestRequest(t, logical.ListOperation, "key-managers")
	req.Storage = sm
	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, []string{"service1", "service2"}, resp.Data["keys"])
}

func TestBackend_createKeyManagerDirectErrors(t *testing.T) {
	b, _ := newTestBackend(t)
	be := b.(*Backend)
	ctx := context.Background()

	t.Run("missing serviceName returns error", func(t *testing.T) {
		data := &framework.FieldData{
			Raw: map[string]interface{}{},
			Schema: map[string]*framework.FieldSchema{
				"serviceName": {Type: framework.TypeString, Default: ""},
				"privateKey":  {Type: framework.TypeString, Default: ""},
			},
		}
		req := &logical.Request{Storage: &logical.InmemStorage{}}
		_, err := be.createKeyManager(ctx, req, data)
		require.Error(t, err)
		assert.ErrorContains(t, err, "serviceName is required")
	})

	t.Run("serviceName field type error", func(t *testing.T) {
		data := &framework.FieldData{
			Raw: map[string]interface{}{"serviceName": 42},
			Schema: map[string]*framework.FieldSchema{
				"serviceName": {Type: framework.TypeInt},
				"privateKey":  {Type: framework.TypeString, Default: ""},
			},
		}
		req := &logical.Request{Storage: &logical.InmemStorage{}}
		_, err := be.createKeyManager(ctx, req, data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("privateKey field type error", func(t *testing.T) {
		data := &framework.FieldData{
			Raw: map[string]interface{}{"serviceName": "valid-svc", "privateKey": 42},
			Schema: map[string]*framework.FieldSchema{
				"serviceName": {Type: framework.TypeString, Default: ""},
				"privateKey":  {Type: framework.TypeInt},
			},
		}
		req := &logical.Request{Storage: &logical.InmemStorage{}}
		_, err := be.createKeyManager(ctx, req, data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})
}

func TestBackend_readDeleteDirectErrors(t *testing.T) {
	b, _ := newTestBackend(t)
	be := b.(*Backend)
	ctx := context.Background()

	t.Run("readKeyManager nonexistent returns error", func(t *testing.T) {
		data := &framework.FieldData{
			Raw:    map[string]interface{}{"name": "does-not-exist"},
			Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
		}
		req := &logical.Request{Storage: &logical.InmemStorage{}}
		_, err := be.readKeyManager(ctx, req, data)
		require.Error(t, err)
		assert.ErrorContains(t, err, "keyManager does not exist")
	})

	t.Run("deleteKeyManager nonexistent returns nil", func(t *testing.T) {
		data := &framework.FieldData{
			Raw:    map[string]interface{}{"name": "does-not-exist"},
			Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
		}
		req := &logical.Request{Storage: &logical.InmemStorage{}}
		resp, err := be.deleteKeyManager(ctx, req, data)
		assert.NoError(t, err)
		assert.Nil(t, resp)
	})

	t.Run("readKeyManager name field type error", func(t *testing.T) {
		data := &framework.FieldData{
			Raw:    map[string]interface{}{"name": 42},
			Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeInt}},
		}
		req := &logical.Request{Storage: &logical.InmemStorage{}}
		_, err := be.readKeyManager(ctx, req, data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})

	t.Run("deleteKeyManager name field type error", func(t *testing.T) {
		data := &framework.FieldData{
			Raw:    map[string]interface{}{"name": 42},
			Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeInt}},
		}
		req := &logical.Request{Storage: &logical.InmemStorage{}}
		_, err := be.deleteKeyManager(ctx, req, data)
		require.Error(t, err)
		assert.ErrorIs(t, err, errInvalidType)
	})
}
