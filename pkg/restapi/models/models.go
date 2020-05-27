/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

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

// StructuredDocument represents a Structured Document.
type StructuredDocument struct {
	ID      string                 `json:"id"`
	Meta    map[string]interface{} `json:"meta"`
	Content map[string]interface{} `json:"content"`
}

// EncryptedDocument represents an Encrypted Document.
type EncryptedDocument struct {
	ID                          string                       `json:"id"`
	Sequence                    int                          `json:"sequence"`
	IndexedAttributeCollections []IndexedAttributeCollection `json:"indexed"`
	JWE                         json.RawMessage              `json:"jwe"`
}

// IndexedAttributeCollection represents a collection of indexed attributes,
// all of which share a common MAC algorithm and key.
type IndexedAttributeCollection struct {
	Sequence          int                `json:"sequence"`
	HMAC              IDTypePair         `json:"hmac"`
	IndexedAttributes []IndexedAttribute `json:"attributes"`
}

// IndexedAttribute represents a single indexed attribute.
type IndexedAttribute struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Unique bool   `json:"unique"`
}

// IDTypePair represents an ID+type pair.
type IDTypePair struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// Query represents a name+value pair that can be used to query the encrypted indices for specific data.
type Query struct {
	Name  string `json:"index"`
	Value string `json:"equals"`
}
