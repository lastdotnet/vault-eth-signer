package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathSign(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern:        "key-managers/" + framework.GenericNameRegex("name") + "/sign",
		ExistenceCheck: b.keyManagerExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.sign,
			},
		},
		HelpSynopsis: "Sign a provided transaction object.",
		HelpDescription: `

    Sign a transaction object with properties conforming to the Ethereum JSON-RPC documentation.

    `,
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
			"hash": {
				Type:        framework.TypeString,
				Description: "Hex string of the hash that should be signed.",
				Default:     "",
			},
			"address": {
				Type:        framework.TypeString,
				Description: "The address that belongs to a private key in the key-manager.",
			},
		},
	}
}

func (b *Backend) sign(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	serviceNameInput, err := getStringField(data, "name")
	if err != nil {
		return nil, err
	}

	hashInput, err := getStringField(data, "hash")
	if err != nil {
		return nil, err
	}

	if hashInput == "" {
		return nil, fmt.Errorf("hash is required")
	}

	hashBytes, err := hexutil.Decode(hashInput)
	if err != nil {
		return nil, fmt.Errorf("invalid hash hex encoding: %w", err)
	}
	if len(hashBytes) != 32 {
		return nil, fmt.Errorf("hash must be exactly 32 bytes, got %d", len(hashBytes))
	}

	address, err := getStringField(data, "address")
	if err != nil {
		return nil, err
	}

	if address == "" {
		return nil, fmt.Errorf("address is required")
	}

	if !common.IsHexAddress(address) {
		return nil, fmt.Errorf("invalid Ethereum address: %s", address)
	}
	address = common.HexToAddress(address).Hex()

	keyManager, err := b.retrieveKeyManager(ctx, req, serviceNameInput)
	if err != nil {
		b.Logger().Error("Failed to retrieve the signing keyManager",
			"service_name", serviceNameInput, "error", err)
		return nil, fmt.Errorf("error retrieving signing keyManager %s", serviceNameInput)
	}

	if keyManager == nil {
		return nil, fmt.Errorf("signing keyManager %s does not exist", serviceNameInput)
	}

	if len(keyManager.KeyPairs) == 0 {
		return nil, fmt.Errorf("signing keyManager %s does not have a key pair", serviceNameInput)
	}

	var privateKeyStr string
	for _, keyPairs := range keyManager.KeyPairs {
		if strings.EqualFold(keyPairs.Address, address) {
			privateKeyStr = keyPairs.PrivateKey
			break
		}
	}

	if privateKeyStr == "" {
		return nil, errors.New("no private key for the input address")
	}

	privateKey, err := crypto.HexToECDSA(privateKeyStr)
	if err != nil {
		b.Logger().Error("Error reconstructing private key from retrieved hex", "error", err)
		return nil, fmt.Errorf("error reconstructing private key from retrieved hex")
	}
	defer zeroKey(privateKey)

	sig, err := crypto.Sign(hashBytes, privateKey)
	if err != nil {
		b.Logger().Error("Error signing input hash", "error", err)
		return nil, fmt.Errorf("error signing hash: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": common.Bytes2Hex(sig),
		},
	}, nil
}
