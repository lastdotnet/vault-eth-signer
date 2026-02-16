package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFactory(t *testing.T) {
	b, storage := newTestBackend(t)
	assert.NotNil(t, b)
	assert.NotNil(t, storage)
}

func TestFactory_NilConfig(t *testing.T) {
	assert.Panics(t, func() {
		Factory(context.Background(), nil)
	})
}

func TestPathExistenceCheck_Exists(t *testing.T) {
	b, _ := newTestBackend(t)

	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": "exist-svc",
	}
	storage := req.Storage
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	be := b.(*Backend)
	checkReq := &logical.Request{
		Storage: storage,
		Path:    "key-managers/exist-svc",
	}
	exists, err := be.pathExistenceCheck(context.Background(), checkReq, nil)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestPathExistenceCheck_NotExists(t *testing.T) {
	b, _ := newTestBackend(t)

	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": "some-svc",
	}
	storage := req.Storage
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	be := b.(*Backend)
	checkReq := &logical.Request{
		Storage: storage,
		Path:    "key-managers/nonexistent",
	}
	exists, err := be.pathExistenceCheck(context.Background(), checkReq, nil)
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestPathExistenceCheck_StorageError(t *testing.T) {
	b, _ := newTestBackend(t)
	be := b.(*Backend)

	sm := NewStorageMock(0, 0, 0, 0)
	checkReq := &logical.Request{
		Storage: sm,
		Path:    "key-managers/test",
	}
	_, err := be.pathExistenceCheck(context.Background(), checkReq, nil)
	assert.ErrorContains(t, err, "existence check failed")
}

func TestKeyManagerExistenceCheck_Exists(t *testing.T) {
	b, _ := newTestBackend(t)

	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": "km-exist-svc",
	}
	storage := req.Storage
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	be := b.(*Backend)
	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": "km-exist-svc"},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	}
	checkReq := &logical.Request{Storage: storage}
	exists, err := be.keyManagerExistenceCheck(context.Background(), checkReq, data)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestKeyManagerExistenceCheck_NotExists(t *testing.T) {
	b, _ := newTestBackend(t)

	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": "some-svc2",
	}
	storage := req.Storage
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	be := b.(*Backend)
	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": "nonexistent"},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	}
	checkReq := &logical.Request{Storage: storage}
	exists, err := be.keyManagerExistenceCheck(context.Background(), checkReq, data)
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestKeyManagerExistenceCheck_StorageError(t *testing.T) {
	b, _ := newTestBackend(t)
	be := b.(*Backend)

	sm := NewStorageMock(0, 0, 0, 0)
	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": "test"},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	}
	checkReq := &logical.Request{Storage: sm}
	_, err := be.keyManagerExistenceCheck(context.Background(), checkReq, data)
	assert.ErrorContains(t, err, "existence check failed")
}

func TestKeyManagerExistenceCheck_EmptyName(t *testing.T) {
	b, _ := newTestBackend(t)
	be := b.(*Backend)

	data := &framework.FieldData{
		Raw:    map[string]interface{}{},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	}
	checkReq := &logical.Request{Storage: &logical.InmemStorage{}}
	exists, err := be.keyManagerExistenceCheck(context.Background(), checkReq, data)
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestKeyManagerExistenceCheck_NameTypeError(t *testing.T) {
	b, _ := newTestBackend(t)
	be := b.(*Backend)

	data := &framework.FieldData{
		Raw:    map[string]interface{}{"name": 42},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeInt}},
	}
	checkReq := &logical.Request{Storage: &logical.InmemStorage{}}
	_, err := be.keyManagerExistenceCheck(context.Background(), checkReq, data)
	require.Error(t, err)
	assert.ErrorIs(t, err, errInvalidType)
}

type corruptStorage struct {
	logical.InmemStorage
	getVal []byte
}

func (c *corruptStorage) Get(_ context.Context, _ string) (*logical.StorageEntry, error) {
	return &logical.StorageEntry{Value: c.getVal}, nil
}

func (c *corruptStorage) Put(_ context.Context, _ *logical.StorageEntry) error {
	return errors.New("put error")
}

func TestRetrieveKeyManager_CorruptJSON(t *testing.T) {
	b, _ := newTestBackend(t)
	be := b.(*Backend)

	cs := &corruptStorage{getVal: []byte("not valid json{")}
	req := &logical.Request{Storage: cs}
	_, err := be.retrieveKeyManager(context.Background(), req, "test")
	assert.Error(t, err)
}
