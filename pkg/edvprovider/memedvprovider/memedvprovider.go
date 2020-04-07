/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memedvprovider

import (
	"encoding/json"
	"errors"

	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/restapi/edv/models"
)

// ErrQueryingNotSupported is used when an attempt is made to query a vault backed by a memstore.
var ErrQueryingNotSupported = errors.New("querying is not supported by memstore")

// MemEDVProvider represents an in-memory provider with functionality needed for EDV data storage.
// It wraps an edge-core memstore provider with additional functionality that's needed for EDV operations,
// however this additional functionality is not supported in memstore.
type MemEDVProvider struct {
	coreProvider storage.Provider
}

// NewProvider instantiates Provider
func NewProvider() *MemEDVProvider {
	return &MemEDVProvider{coreProvider: memstore.NewProvider()}
}

// CreateStore creates a new store with the given name.
func (m MemEDVProvider) CreateStore(name string) error {
	return m.coreProvider.CreateStore(name)
}

// OpenStore opens an existing store and returns it.
func (m MemEDVProvider) OpenStore(name string) (edvprovider.EDVStore, error) {
	coreStore, err := m.coreProvider.OpenStore(name)
	if err != nil {
		return nil, err
	}

	return &MemEDVStore{coreStore: coreStore}, nil
}

// MemEDVStore represents an in-memory store with functionality needed for EDV data storage.
// It wraps an edge-core in-memory store with additional functionality that's needed for EDV operations.
type MemEDVStore struct {
	coreStore storage.Store
}

// Put stores the given document.
func (m MemEDVStore) Put(document models.EncryptedDocument) error {
	documentBytes, err := json.Marshal(document)
	if err != nil {
		return err
	}

	return m.coreStore.Put(document.ID, documentBytes)
}

// Get fetches the document associated with the given key.
func (m MemEDVStore) Get(k string) ([]byte, error) {
	return m.coreStore.Get(k)
}

// CreateEDVIndex is not supported in memstore, and calling it will always return an error.
func (m MemEDVStore) CreateEDVIndex() error {
	return edvprovider.ErrIndexingNotSupported
}

// Query is not supported in memstore, and calling it will always return an error.
func (m MemEDVStore) Query(query *models.Query) ([]string, error) {
	return nil, ErrQueryingNotSupported
}
