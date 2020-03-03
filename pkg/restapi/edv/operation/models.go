/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import "encoding/json"

// DataVaultConfiguration represents a Data Vault Configuration.
type DataVaultConfiguration struct {
	Sequence    int        `json:"sequence"`
	Controller  string     `json:"controller"`
	Invoker     string     `json:"invoker"`
	Delegator   string     `json:"delegator"`
	ReferenceID string     `json:"referenceId"`
	KEK         IDTypePair `json:"kek"`
	HMAC        IDTypePair `json:"hmac"`
}

// IDTypePair represents an ID+type pair. Used in the DataVaultConfiguration struct.
type IDTypePair struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// StructuredDocument represents a Structured Document.
type StructuredDocument struct {
	ID      string                 `json:"id"`
	Meta    map[string]interface{} `json:"meta"`
	Content map[string]interface{} `json:"content"`
}

// EncryptedDocument represents an Encrypted Document.
type EncryptedDocument struct {
	ID       string          `json:"id"`
	Sequence int             `json:"sequence"`
	JWE      json.RawMessage `json:"jwe"`
}
