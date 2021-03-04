/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edvprovider

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/edv/pkg/restapi/models"
)

const (
	// VaultConfigurationStoreName is the name for the store that holds data vault configurations.
	VaultConfigurationStoreName = "data_vault_configurations"
	// VaultConfigReferenceIDTagName is the tag name used for querying vault configs based on their reference IDs.
	VaultConfigReferenceIDTagName = "ReferenceID"

	// MappingDocumentTagName is the tag name used for querying mapping documents
	// based on what attribute name they're for.
	MappingDocumentTagName = "AttributeName"
	// MappingDocumentMatchingEncryptedDocIDTagName is the tag name used for querying mapping documents
	// based on what encrypted document they're for.
	MappingDocumentMatchingEncryptedDocIDTagName = "MatchingEncryptedDocumentID"
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
	// StoreExists determines if a given store exists.
	StoreExists(name string) (bool, error)

	// OpenStore opens a store (creating it if it doesn't exist) and returns it.
	OpenStore(name string) (EDVStore, error)

	// SetStoreConfig sets the configuration on a store.
	// The store must be created prior to calling this method.
	// If the store cannot be found, then an error wrapping ErrStoreNotFound will be returned.
	// If name is blank, then an error will be returned.
	SetStoreConfig(name string, config storage.StoreConfiguration) error
}

// EDVStore represents a store with functionality needed for EDV data storage.
type EDVStore interface {
	// Put stores the given document.
	Put(document models.EncryptedDocument) error

	// UpsertBulk stores the given documents, creating or updating them as needed.
	UpsertBulk(documents []models.EncryptedDocument) error

	// Get fetches the document associated with the given key.
	Get(k string) ([]byte, error)

	// Update updates the given document
	Update(document models.EncryptedDocument) error

	// Delete deletes the given document
	Delete(docID string) error

	// Query does an EDV encrypted index query.
	// If query.Value is blank, then any documents tagged with query.Name will be returned regardless of value.
	Query(query *models.Query) ([]models.EncryptedDocument, error)

	// StoreDataVaultConfiguration stores the given DataVaultConfiguration and vaultID
	StoreDataVaultConfiguration(config *models.DataVaultConfiguration, vaultID string) error
}
