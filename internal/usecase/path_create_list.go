package usecase

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCreateAndList(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "key-managers/?",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.createKeyManager,
			},
			logical.ListOperation: &framework.PathOperation{
				Callback: b.listKeyManagers,
			},
		},
		HelpSynopsis: "Create new key-manager with input private-key or random private-key & list all the key-managers maintained by the plugin backend.",
		HelpDescription: `

    POST - create a new keyManager
    LIST - list all keyManagers

    `,
		Fields: map[string]*framework.FieldSchema{
			"serviceName": {
				Type:        framework.TypeString,
				Description: "The service that is the owner of the private-key",
				Default:     "",
			},
			"privateKey": {
				Type:        framework.TypeString,
				Description: "(Optional, default random key) Hex string for the private key (32-byte or 64-char long). If present, the request will import the given key instead of generating a new key.",
				Default:     "",
			},
			"allowRawSigning": {
				Type:        framework.TypeBool,
				Description: "Unsafe capability flag. If true, this key manager can sign arbitrary 32-byte digests via /sign.",
				Default:     false,
			},
		},
	}
}

func (b *Backend) listKeyManagers(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, "key-managers/")
	if err != nil {
		b.Logger().Error("Failed to retrieve the list of keyManagers", "error", err)
		return nil, err
	}

	return logical.ListResponse(vals), nil
}

func (b *Backend) createKeyManager(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	serviceInput, err := getStringField(data, "serviceName")
	if err != nil {
		return nil, err
	}

	if err := validateServiceName(serviceInput); err != nil {
		return nil, err
	}

	keyInput, err := getStringField(data, "privateKey")
	if err != nil {
		return nil, err
	}

	allowRawSigning, err := getBoolField(data, "allowRawSigning")
	if err != nil {
		return nil, err
	}
	_, allowRawSigningProvided := data.GetOk("allowRawSigning")

	keyManager, err := b.retrieveKeyManager(ctx, req, serviceInput)
	if err != nil {
		return nil, err
	}

	if keyManager == nil {
		keyManager = &KeyManager{
			ServiceName:     serviceInput,
			AllowRawSigning: allowRawSigning,
		}
	} else if allowRawSigningProvided {
		keyManager.AllowRawSigning = allowRawSigning
	}

	var privateKey *ecdsa.PrivateKey
	var privateKeyBytes []byte

	if keyInput != "" {
		re := regexp.MustCompile(`^(0x)?[0-9a-fA-F]{64}$`)

		if !re.MatchString(keyInput) {
			b.Logger().Error("Input private key did not parse successfully")
			return nil, fmt.Errorf("privateKey must be a 32-byte hexadecimal string")
		}

		key := keyInput
		if len(key) > 64 {
			key = key[len(key)-64:]
		}

		privateKey, err = crypto.HexToECDSA(key)
		if err != nil {
			b.Logger().Error("Error reconstructing private key from input hex", "error", err)
			return nil, fmt.Errorf("error reconstructing private key from input hex, %w", err)
		}
	} else {
		privateKey, err = crypto.GenerateKey()
		if err != nil {
			b.Logger().Error("Failed to generate private key", "error", err)
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
	}

	privateKeyBytes = crypto.FromECDSA(privateKey)
	defer zeroKey(privateKey)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	keyPair := &KeyPair{
		PrivateKey: common.Bytes2Hex(privateKeyBytes),
		PublicKey:  common.Bytes2Hex(publicKeyBytes),
		Address:    crypto.PubkeyToAddress(*publicKeyECDSA).Hex(),
	}

	for _, existingKeyPair := range keyManager.KeyPairs {
		if strings.EqualFold(existingKeyPair.Address, keyPair.Address) {
			if allowRawSigningProvided {
				policyPath := fmt.Sprintf("key-managers/%s", serviceInput)
				entry, err := logical.StorageEntryJSON(policyPath, keyManager)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal keyManager: %w", err)
				}
				if err := req.Storage.Put(ctx, entry); err != nil {
					return nil, fmt.Errorf("failed to persist allowRawSigning update: %w", err)
				}
			}
			return &logical.Response{
				Data: map[string]interface{}{
					"service_name":      keyManager.ServiceName,
					"address":           existingKeyPair.Address,
					"public_key":        existingKeyPair.PublicKey,
					"allow_raw_signing": keyManager.AllowRawSigning,
				},
			}, nil
		}
	}

	keyManager.KeyPairs = append(keyManager.KeyPairs, keyPair)

	policyPath := fmt.Sprintf("key-managers/%s", serviceInput)
	entry, err := logical.StorageEntryJSON(policyPath, keyManager)
	if err != nil {
		b.Logger().Error("Failed to marshal keyManager to JSON", "error", err)
		return nil, fmt.Errorf("failed to marshal keyManager: %w", err)
	}
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		b.Logger().Error("Failed to save the new keyManager to storage", "error", err)
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": keyManager.ServiceName,
			"address":      keyPair.Address,
			"public_key":   keyPair.PublicKey,
		},
	}, nil
}
