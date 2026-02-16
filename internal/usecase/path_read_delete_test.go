package usecase

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackend_readKeyManagerFailure1(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.ReadOperation, "key-managers/my-service")
	sm := NewStorageMock(0, 0, 0, 0)
	req.Storage = sm
	resp, err := b.HandleRequest(context.Background(), req)

	assert.Nil(t, resp)
	assert.Equal(t, "failed to get", err.Error())
}

func TestBackend_readKeyManagerFailure2(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.ReadOperation, "key-managers/my-service")
	sm := NewStorageMock(0, 0, 0, 0)
	req.Storage = sm
	resp, err := b.HandleRequest(context.Background(), req)

	assert.Nil(t, resp)
	assert.Equal(t, "failed to get", err.Error())
}

func TestBackend_readKeyManagerFailure3(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.ReadOperation, "key-managers/my-service")
	sm := NewStorageMock(0, 1, 0, 0)
	req.Storage = sm
	resp, _ := b.HandleRequest(context.Background(), req)

	assert.Nil(t, resp)
}

func TestBackend_readKeyManagerSuccess(t *testing.T) {
	b, _ := newTestBackend(t)

	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": "read-svc",
		"privateKey":  "3ee65159f7aa057c482b1041f18f37ce90ef5e460cb46fd3fa0c40fbae41c7e1",
	}
	storage := req.Storage
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/read-svc")
	req.Storage = storage
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "read-svc", resp.Data["service_name"])
	addrs := resp.Data["addresses"].([]string)
	assert.Len(t, addrs, 1)
	assert.Equal(t, "0xBffc2f3Df75367B0f246aF6Ae42AFf59A33f2704", addrs[0])
}

func TestBackend_deleteKeyManagerFailure1(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.DeleteOperation, "key-managers/my-service")
	sm := NewStorageMock(0, 0, 0, 0)
	req.Storage = sm
	resp, err := b.HandleRequest(context.Background(), req)

	assert.Nil(t, resp)
	assert.Equal(t, "failed to get", err.Error())
}

func TestBackend_deleteKeyManagerFailure2(t *testing.T) {
	b, _ := newTestBackend(t)
	req := logical.TestRequest(t, logical.DeleteOperation, "key-managers/my-service")
	sm := NewStorageMock(0, 1, 0, 0)
	req.Storage = sm
	resp, err := b.HandleRequest(context.Background(), req)

	assert.Nil(t, resp)
	assert.Nil(t, err)
}

func TestBackend_deleteKeyManagerSuccess(t *testing.T) {
	b, _ := newTestBackend(t)

	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Data = map[string]interface{}{
		"serviceName": "del-svc",
	}
	storage := req.Storage
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/del-svc")
	req.Storage = storage
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, resp)

	req = logical.TestRequest(t, logical.DeleteOperation, "key-managers/del-svc")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	assert.Nil(t, err)
	assert.Nil(t, resp)

	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/del-svc")
	req.Storage = storage
	_, err = b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "keyManager does not exist")
}

func TestBackend_deleteKeyManagerStorageDeleteError(t *testing.T) {
	b, _ := newTestBackend(t)

	des := &deleteErrorStorage{}

	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers")
	req.Storage = des
	req.Data = map[string]interface{}{
		"serviceName": "del-err-svc",
	}
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	req = logical.TestRequest(t, logical.DeleteOperation, "key-managers/del-err-svc")
	req.Storage = des
	_, err = b.HandleRequest(context.Background(), req)
	assert.ErrorContains(t, err, "failed to delete from storage")
}

func TestBackend_deleteKeyManagerUsesRequestedPath(t *testing.T) {
	b, _ := newTestBackend(t)
	storage := &logical.InmemStorage{}

	corrupt := &KeyManager{ServiceName: "other-name", KeyPairs: []*KeyPair{}}
	entry, err := logical.StorageEntryJSON("key-managers/requested-name", corrupt)
	require.NoError(t, err)
	require.NoError(t, storage.Put(context.Background(), entry))

	other := &KeyManager{ServiceName: "other-name", KeyPairs: []*KeyPair{}}
	entry, err = logical.StorageEntryJSON("key-managers/other-name", other)
	require.NoError(t, err)
	require.NoError(t, storage.Put(context.Background(), entry))

	req := logical.TestRequest(t, logical.DeleteOperation, "key-managers/requested-name")
	req.Storage = storage
	_, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	requestedEntry, err := storage.Get(context.Background(), "key-managers/requested-name")
	require.NoError(t, err)
	assert.Nil(t, requestedEntry)

	otherEntry, err := storage.Get(context.Background(), "key-managers/other-name")
	require.NoError(t, err)
	assert.NotNil(t, otherEntry)
}
