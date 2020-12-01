/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import "encoding/json"

// DataVaultConfiguration represents a Data Vault Configuration.
type DataVaultConfiguration struct {
	Sequence    uint64     `json:"sequence"`
	Controller  string     `json:"controller"`
	Invoker     []string   `json:"invoker"`
	Delegator   []string   `json:"delegator"`
	ReferenceID string     `json:"referenceId"`
	KEK         IDTypePair `json:"kek"`
	HMAC        IDTypePair `json:"hmac"`
}

// DataVaultConfigurationMapping represents an entry in the data vault config store that maps a DataVaultConfiguration
// to a vaultID
type DataVaultConfigurationMapping struct {
	DataVaultConfiguration DataVaultConfiguration `json:"dataVaultConfiguration"`
	VaultID                string                 `json:"vaultId"`
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
	Sequence                    uint64                       `json:"sequence"`
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
// ReturnFullDocuments is optional and can only be used if the "ReturnFullDocumentsOnQuery" extension is enabled.
type Query struct {
	ReturnFullDocuments bool   `json:"returnFullDocuments"`
	Name                string `json:"index"`
	Value               string `json:"equals"`
}

// Batch represents a batch of operations to be performed in a vault.
type Batch []VaultOperation

const (
	// UpsertDocumentVaultOperation represents an upsert operation to be performed in a batch.
	UpsertDocumentVaultOperation = "upsert"
	// DeleteDocumentVaultOperation represents a delete operation to be performed in a batch.
	DeleteDocumentVaultOperation = "delete"
)

// VaultOperation represents an upsert or delete operation to be performed in a vault.
type VaultOperation struct {
	Operation         string            `json:"operation"`          // Valid values: upsert,delete
	DocumentID        string            `json:"id,omitempty"`       // Only used if Operation=delete
	EncryptedDocument EncryptedDocument `json:"document,omitempty"` // Only used if Operation=createOrUpdate
}

// JSONWebEncryption represents a JWE
type JSONWebEncryption struct {
	B64ProtectedHeaders      string                 `json:"protected,omitempty"`
	UnprotectedHeaders       map[string]interface{} `json:"unprotected,omitempty"`
	Recipients               []Recipient            `json:"recipients,omitempty"`
	B64SingleRecipientEncKey string                 `json:"encrypted_key,omitempty"`
	SingleRecipientHeader    *RecipientHeaders      `json:"header,omitempty"`
	B64AAD                   string                 `json:"aad,omitempty"`
	B64IV                    string                 `json:"iv,omitempty"`
	B64Ciphertext            string                 `json:"ciphertext,omitempty"`
	B64Tag                   string                 `json:"tag,omitempty"`
}

// Recipient is a recipient of a JWE including the shared encryption key.
type Recipient struct {
	Header       *RecipientHeaders `json:"header,omitempty"`
	EncryptedKey string            `json:"encrypted_key,omitempty"`
}

// RecipientHeaders are the recipient headers.
type RecipientHeaders struct {
	Alg string          `json:"alg,omitempty"`
	APU string          `json:"apu,omitempty"`
	IV  string          `json:"iv,omitempty"`
	Tag string          `json:"tag,omitempty"`
	KID string          `json:"kid,omitempty"`
	EPK json.RawMessage `json:"epk,omitempty"`
	SPK json.RawMessage `json:"spk,omitempty"`
}
