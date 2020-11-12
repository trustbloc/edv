/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edvprovider

import (
	"errors"

	"github.com/trustbloc/edv/pkg/restapi/models"
)

// ErrIndexingNotSupported is returned when an attempt is made to create an index in a provider that doesn't support it.
var ErrIndexingNotSupported = errors.New("indexing is not supported by this provider")

// ErrIndexNameAndValueAlreadyDeclaredUnique is returned when an attempt is made to store a document with an
// index name and value that are defined as unique in another document already. Note that depending
// on the provider implementation, it may not be guaranteed that uniqueness can always be maintained.
var ErrIndexNameAndValueAlreadyDeclaredUnique = errors.New("unable to store document since it contains an " +
	"index name and value that are already declared as unique in an existing document")

// ErrIndexNameAndValueCannotBeUnique is returned when an attempt is made to store a document with an
// index name and value that are defined as unique in the new would-be document, but another document already has
// an identical index name + value pair defined so uniqueness cannot be achieved. Note that depending
// on the provider implementation, it may not be guaranteed that uniqueness can always be maintained.
var ErrIndexNameAndValueCannotBeUnique = errors.New("unable to store document since it contains an " +
	"index name and value that are declared as unique, but another document already has an " +
	"identical index name + value pair")

// EDVProvider represents a provider with functionality needed for EDV data storage.
type EDVProvider interface {
	// CreateStore creates a new store with the given name.
	CreateStore(name string) error

	// OpenStore opens an existing store and returns it.
	OpenStore(name string) (EDVStore, error)
}

// EDVStore represents a store with functionality needed for EDV data storage.
type EDVStore interface {
	// Put stores the given document.
	Put(document models.EncryptedDocument) error

	// GetAll fetches all the documents within this store.
	GetAll() ([][]byte, error)

	// Get fetches the document associated with the given key.
	Get(k string) ([]byte, error)

	// Update updates the given document
	Update(document models.EncryptedDocument) error

	// CreateEDVIndex creates the index which will allow for encrypted indices to work.
	CreateEDVIndex() error

	// CreateEncryptedDocIDIndex creates index for the MatchingEncryptedDocID field in mapping documents.
	CreateEncryptedDocIDIndex() error

	// Query does an EDV encrypted index query.
	Query(query *models.Query) ([]string, error)

	// CreateReferenceIDIndex creates index for the referenceId field in config documents
	CreateReferenceIDIndex() error

	// StoreDataVaultConfiguration stores the given DataVaultConfiguration and vaultID
	StoreDataVaultConfiguration(config *models.DataVaultConfiguration, vaultID string) error
}
