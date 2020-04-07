/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edvprovider

import (
	"errors"

	"github.com/trustbloc/edv/pkg/restapi/edv/models"
)

// ErrIndexingNotSupported is returned when an attempt is made to create an index in a provider that doesn't support it.
var ErrIndexingNotSupported = errors.New("indexing is not supported by this provider")

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

	// Get fetches the document associated with the given key.
	Get(k string) ([]byte, error)

	// CreateEDVIndex creates the index which will allow for encrypted indices to work.
	CreateEDVIndex() error

	// Query does an EDV encrypted index query.
	Query(query *models.Query) ([]string, error)
}
