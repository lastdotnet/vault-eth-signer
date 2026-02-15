# vault-eth-signer Knowledge Base

**Module**: `github.com/lastdotnet/vault-eth-signer`
**Branch**: `chore/rebrand-and-security-updates`
**Go**: 1.25.0
**Version**: v0.0.3

## OVERVIEW

HashiCorp Vault secrets engine plugin for Ethereum key management and transaction signing. Runs as a Vault plugin binary — Vault loads it as a backend, exposing HTTP paths for key creation, import, listing, reading, deletion, and signing.

**This is a Vault plugin, not a standalone service.** It has no HTTP server of its own. Vault proxies all requests through its plugin system.

## STRUCTURE

```
vault-eth-signer/
├── cmd/
│   └── plugin/
│       └── main.go             # Entry point: plugin.Serve() → usecase.Factory
├── internal/
│   └── usecase/
│       ├── backend.go           # Backend struct, Factory(), path registration
│       ├── key_managers.go      # KeyPair, KeyManager types, paths(), retrieveKeyManager
│       ├── path_create_list.go  # POST /key-managers/ (create/import), LIST /key-managers/
│       ├── path_read_delete.go  # GET/DELETE /key-managers/:name
│       ├── path_sign.go         # POST /key-managers/:name/sign (raw 32-byte hash)
│       ├── path_sign_txn.go     # POST /key-managers/:name/txn/sign (Ethereum transactions)
│       └── utils.go             # Helpers: validateServiceName, newTransactionWithDynamicFee, zeroKey
├── .github/                     # CI workflows
├── .scripts/                    # Build/release scripts
├── docker-compose.yml           # Vault dev server for local development
├── Makefile                     # Build, test, start-vault commands
├── go.mod                       # Module definition
└── README.md                    # Documentation
```

## KEY TYPES

### `KeyManager` — A named service with key pairs

```go
type KeyManager struct {
    ServiceName string    `json:"service_name"`
    KeyPairs    []KeyPair `json:"key_pairs"`
}
```

A KeyManager is a named container (identified by `ServiceName`) that holds one or more Ethereum key pairs. It maps to a Vault storage path.

### `KeyPair` — An Ethereum key pair

```go
type KeyPair struct {
    PrivateKey string `json:"private_key"`
    PublicKey  string `json:"public_key"`
    Address    string `json:"address"`
}
```

Private keys are hex-encoded (no `0x` prefix in storage). Addresses are checksummed.

## VAULT PATHS

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/key-managers/` | Create key manager — generate new key or import existing |
| `LIST` | `/key-managers/` | List all key manager names |
| `GET` | `/key-managers/:name` | Read key manager (returns addresses only, NOT private keys) |
| `DELETE` | `/key-managers/:name` | Delete key manager from Vault storage |
| `POST` | `/key-managers/:name/sign` | Sign a raw 32-byte hash (requires `allowRawSigning=true`) |
| `POST` | `/key-managers/:name/txn/sign` | Sign an Ethereum transaction (legacy or EIP-1559) |

### Create Key Manager

```
POST /key-managers/
{
  "service_name": "my-service",       // Required, alphanumeric + hyphens only
  "private_key": "abcdef1234...",     // Optional — omit to generate new key
  "allowRawSigning": true             // Optional — enables raw hash signing
}
```

Returns: `{ "address": "0x...", "service_name": "my-service" }`

### Sign Transaction

```
POST /key-managers/:name/txn/sign
{
  "address_index": 0,        // Which key pair to use
  "chain_id": "999",         // Target chain
  "to": "0x...",             // Recipient
  "data": "0x...",           // Calldata (hex)
  "value": "0",              // Wei value
  "nonce": "42",             // Account nonce
  "gas_limit": "21000",      // Gas limit
  "max_fee_per_gas": "...",  // EIP-1559 (or gas_price for legacy)
  "max_priority_fee": "..."  // EIP-1559 only
}
```

Returns: `{ "signed_transaction": "0x...", "transaction_hash": "0x..." }`

### Sign Raw Hash

```
POST /key-managers/:name/sign
{
  "address_index": 0,
  "hash": "0xabcdef..."     // Exactly 32 bytes
}
```

Requires `allowRawSigning=true` on the key manager. Returns: `{ "signature": "0x..." }`

## SECURITY DESIGN

### Private Key Handling
- `zeroKey(k *ecdsa.PrivateKey)` — Zeroes private key bytes in memory after every signing operation
- Private keys are NEVER returned by read endpoints — only addresses and public keys
- All signing paths retrieve the key, sign, then immediately zero the key

### Input Validation
- `validateServiceName(name)` — Prevents path traversal attacks (alphanumeric + hyphens only)
- `maxTxDataBytes = 131072` — Limits transaction data size to 128KB
- Raw signing requires explicit opt-in (`allowRawSigning` flag set at creation time)

### Transaction Signing
- Supports both legacy (Type 0) and EIP-1559 (Type 2) transactions
- `newTransactionWithDynamicFee()` — Creates EIP-1559 transaction when `max_fee_per_gas` is provided
- Falls back to legacy transaction when only `gas_price` is provided

## KEY DEPENDENCIES

- `github.com/hashicorp/vault/api` — Vault API client
- `github.com/hashicorp/vault/sdk` — Vault plugin SDK (framework, logical, plugin)
- `github.com/ethereum/go-ethereum` — Ethereum crypto, types, RLP encoding
- `github.com/hashicorp/go-hclog` — Structured logging

## COMMANDS

```bash
# Build
make build                  # Debug build with race detector (macOS)
make build-linux-release    # Static ARM64 Linux binary for production

# Test
make test                   # go test -v -cover ./...
go test -v -cover ./...     # Direct — ~96% coverage

# Local Development
make start-vault            # Start Vault dev server via docker-compose
docker-compose up -d        # Same thing, manually

# Enable plugin in Vault
vault secrets enable -path=ethereum vault-eth-signer
```

## LOCAL DEVELOPMENT

1. `docker-compose up -d` — Start Vault dev server (root token: `root`)
2. `make build` — Build plugin binary
3. Copy binary to Vault plugin directory
4. Register and enable the plugin in Vault
5. Use Vault CLI or API to interact with `/ethereum/key-managers/`

## CONVENTIONS

- All Vault paths are registered in `paths()` in `key_managers.go`
- Storage keys follow pattern: `key-managers/{service_name}`
- Factory function in `backend.go` is the plugin entrypoint — Vault calls this
- Every signing operation MUST zero the private key after use (call `zeroKey`)
- Service names are validated before any storage operation

## ANTI-PATTERNS

- Do NOT return private keys from any read/list endpoint
- Do NOT skip `zeroKey()` after signing — this is a security invariant
- Do NOT allow raw signing without explicit `allowRawSigning` flag
- Do NOT accept service names with special characters (path traversal risk)
- Do NOT increase `maxTxDataBytes` without security review
- Do NOT import this plugin into other services — it runs as a Vault plugin process only
