/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

// DataVaultConfiguration represents a Data Vault Configuration. For use with an EDV.
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

// StructuredDocument represents a Structured Document. For use with an EDV.
type StructuredDocument struct {
	ID      string                 `json:"id"`
	Meta    map[string]interface{} `json:"meta"`
	Content map[string]interface{} `json:"content"`
}
