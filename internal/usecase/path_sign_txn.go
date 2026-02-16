package usecase

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type RequestFieldsTransaction struct {
	tx      *types.Transaction
	chainID *big.Int
	from    string
	address string
}

func pathSignTx(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern:        "key-managers/" + framework.GenericNameRegex("name") + "/txn/sign",
		ExistenceCheck: b.keyManagerExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.signTx,
			},
		},
		HelpSynopsis: "Sign a provided transaction object.",
		HelpDescription: `

    Sign a transaction object with properties conforming to the Ethereum JSON-RPC documentation.

    `,
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
			"address": {
				Type:        framework.TypeString,
				Description: "The address that belongs to a private key in the key-manager.",
			},
			"to": {
				Type:        framework.TypeString,
				Description: "(optional when creating new contract) The contract address the transaction is directed to.",
				Default:     "",
			},
			"data": {
				Type:        framework.TypeString,
				Description: "The compiled code of a contract OR the hash of the invoked method signature and encoded parameters.",
			},
			"input": {
				Type:        framework.TypeString,
				Description: "The compiled code of a contract OR the hash of the invoked method signature and encoded parameters.",
			},
			"value": {
				Type:        framework.TypeString,
				Description: "(optional) Integer of the value sent with this transaction (in wei).",
			},
			"nonce": {
				Type:        framework.TypeString,
				Description: "The transaction nonce.",
			},
			"gas": {
				Type:        framework.TypeString,
				Description: "(optional, default: 90000) Integer of the gas provided for the transaction execution. It will return unused gas",
				Default:     "90000",
			},
			"gasPrice": {
				Type:        framework.TypeString,
				Description: "(optional, default: 0) The gas price for the transaction in wei.",
				Default:     "0",
			},
			"gasFeeCap": {
				Type:        framework.TypeString,
				Description: "(optional) Integer of the gasFeeCap  provided for the transaction execution. It will return unused gas",
			},
			"gasTipCap": {
				Type:        framework.TypeString,
				Description: "(optional) Integer of the gasTipCap provided for the transaction execution. It will return unused gas",
			},
			"chainId": {
				Type:        framework.TypeString,
				Description: "(required) Non-zero chain ID of the target blockchain network.",
			},
			"accessList": {
				Type:        framework.TypeString,
				Description: "(optional) JSON-encoded access list for EIP-2930/EIP-1559 transactions. Format: [{\"address\":\"0x...\",\"storageKeys\":[\"0x...\"]}]",
				Default:     "",
			},
		},
	}
}

func (b *Backend) signTx(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	fieldsAndTx, err := b.validateAndGetTx(data)
	if err != nil {
		return nil, err
	}

	keyManager, err := b.retrieveKeyManager(ctx, req, fieldsAndTx.from)
	if err != nil {
		b.Logger().Error("Failed to retrieve the signing keyManager",
			"address", fieldsAndTx.from, "error", err)
		return nil, fmt.Errorf("error retrieving signing keyManager %s", fieldsAndTx.from)
	}

	if keyManager == nil {
		return nil, fmt.Errorf("signing keyManager %s does not exist", fieldsAndTx.from)
	}

	if len(keyManager.KeyPairs) == 0 {
		return nil, fmt.Errorf("signing keyManager %s does not have a key pair", fieldsAndTx.from)
	}

	var privateKeyStr string
	for _, keyPairs := range keyManager.KeyPairs {
		if strings.EqualFold(keyPairs.Address, fieldsAndTx.address) {
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

	signer := types.LatestSignerForChainID(fieldsAndTx.chainID)

	signedTx, err := types.SignTx(fieldsAndTx.tx, signer, privateKey)
	if err != nil {
		b.Logger().Error("Failed to sign the transaction object", "error", err)
		return nil, err
	}

	var signedTxBuff bytes.Buffer
	err = signedTx.EncodeRLP(&signedTxBuff)
	if err != nil {
		b.Logger().Error("Failed to encode signedTx RLP", "error", err)
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"txHash":             signedTx.Hash().Hex(),
			"signedTx":           hexutil.Encode(signedTxBuff.Bytes()),
			"transaction_hash":   signedTx.Hash().Hex(),
			"signed_transaction": hexutil.Encode(signedTxBuff.Bytes()),
		},
	}, nil
}

func (b *Backend) validateAndGetTx(data *framework.FieldData) (*RequestFieldsTransaction, error) {
	from, err := getStringField(data, "name")
	if err != nil {
		return nil, err
	}

	dataInput, err := getStringField(data, "data")
	if err != nil {
		return nil, err
	}

	if dataInput == "" {
		dataInput, err = getStringField(data, "input")
		if err != nil {
			return nil, err
		}
	}

	if dataInput == "" {
		dataInput = "0x"
	}

	if len(dataInput) > 2 && dataInput[0:2] != "0x" {
		dataInput = "0x" + dataInput
	}

	if len(dataInput) > 2+(maxTxDataBytes*2) {
		return nil, fmt.Errorf("transaction data too large")
	}

	txDataToSign, err := hexutil.Decode(dataInput)
	if err != nil {
		b.Logger().Error("Failed to decode payload for the 'data' field", "error", err)
		return nil, err
	}
	if len(txDataToSign) > maxTxDataBytes {
		return nil, fmt.Errorf("transaction data too large")
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

	valueStr, err := getStringField(data, "value")
	if err != nil {
		return nil, err
	}
	amount := validNumber(valueStr)
	if amount == nil {
		b.Logger().Error("Invalid amount for the 'value' field", "value", valueStr)
		return nil, fmt.Errorf("invalid amount for the 'value' field")
	}

	rawAddressTo, err := getStringField(data, "to")
	if err != nil {
		return nil, err
	}

	chainIDStr, err := getStringField(data, "chainId")
	if err != nil {
		return nil, err
	}
	if chainIDStr == "" {
		return nil, fmt.Errorf("chainId is required")
	}
	chainID := validNumber(chainIDStr)
	if chainID == nil || chainID.Sign() == 0 {
		b.Logger().Error("Invalid chainId", "chainId", chainIDStr)
		return nil, fmt.Errorf("invalid chainId value; must be non-zero")
	}

	gasStr, err := getStringField(data, "gas")
	if err != nil {
		return nil, err
	}
	gasLimitIn := validNumber(gasStr)
	if gasLimitIn == nil {
		b.Logger().Error("Invalid gas limit", "gas", gasStr)
		return nil, fmt.Errorf("invalid gas limit")
	}
	gasLimit, err := uint64FromBig(gasLimitIn)
	if err != nil {
		return nil, fmt.Errorf("gas value exceeds uint64")
	}

	gasPriceStr, err := getStringField(data, "gasPrice")
	if err != nil {
		return nil, err
	}
	gasPrice := validNumber(gasPriceStr)

	gasFeeCapStr, err := getStringField(data, "gasFeeCap")
	if err != nil {
		return nil, err
	}
	gasTipCapStr, err := getStringField(data, "gasTipCap")
	if err != nil {
		return nil, err
	}

	nonceStr, err := getStringField(data, "nonce")
	if err != nil {
		return nil, err
	}
	if nonceStr == "" {
		return nil, fmt.Errorf("nonce is required")
	}
	nonceIn := validNumber(nonceStr)
	if nonceIn == nil {
		b.Logger().Error("Invalid nonce", "nonce", nonceStr)
		return nil, fmt.Errorf("invalid nonce")
	}
	nonce, err := uint64FromBig(nonceIn)
	if err != nil {
		return nil, fmt.Errorf("nonce value exceeds uint64")
	}

	var addressTo *common.Address
	if rawAddressTo != "" {
		if !common.IsHexAddress(rawAddressTo) {
			return nil, fmt.Errorf("invalid 'to' address: %s", rawAddressTo)
		}
		addressToTemp := common.HexToAddress(rawAddressTo)
		addressTo = &addressToTemp
	}

	out := &RequestFieldsTransaction{
		address: address,
		from:    from,
		chainID: chainID,
	}

	hasGasFeeCap := gasFeeCapStr != ""
	hasGasTipCap := gasTipCapStr != ""
	if hasGasFeeCap != hasGasTipCap {
		return nil, fmt.Errorf("gasFeeCap and gasTipCap must be provided together")
	}

	if hasGasFeeCap && hasGasTipCap {
		gasFeeCap := validNumber(gasFeeCapStr)
		if gasFeeCap == nil {
			return nil, fmt.Errorf("invalid gasFeeCap value")
		}
		gasTipCap := validNumber(gasTipCapStr)
		if gasTipCap == nil {
			return nil, fmt.Errorf("invalid gasTipCap value")
		}
		if gasFeeCap.Cmp(gasTipCap) < 0 {
			return nil, fmt.Errorf("gasFeeCap must be greater than or equal to gasTipCap")
		}

		accessListStr, err := getStringField(data, "accessList")
		if err != nil {
			return nil, err
		}
		var accessList types.AccessList
		if accessListStr != "" {
			if len(accessListStr) > maxAccessListJSONBytes {
				return nil, fmt.Errorf("accessList exceeds size limit")
			}
			if err := json.Unmarshal([]byte(accessListStr), &accessList); err != nil {
				b.Logger().Error("Failed to parse accessList", "error", err)
				return nil, fmt.Errorf("invalid accessList JSON: %w", err)
			}
			if len(accessList) > maxAccessListEntries {
				return nil, fmt.Errorf("accessList has too many entries")
			}
			storageKeysCount := 0
			for _, tuple := range accessList {
				storageKeysCount += len(tuple.StorageKeys)
			}
			if storageKeysCount > maxAccessListStorageKeys {
				return nil, fmt.Errorf("accessList has too many storage keys")
			}
		}

		out.tx = newTransactionWithDynamicFee(addressTo, nonce, gasFeeCap, gasTipCap, gasLimit, txDataToSign, amount, chainID, accessList)
	} else {
		if gasPrice == nil {
			return nil, fmt.Errorf("invalid gas price")
		}
		out.tx = newLegacyTransaction(addressTo, nonce, gasPrice, gasLimit, txDataToSign, amount)
	}

	return out, nil
}
