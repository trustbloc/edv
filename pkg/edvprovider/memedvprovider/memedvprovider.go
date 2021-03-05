/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memedvprovider

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/spi/storage"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

// ErrQueryingNotSupported is used when an attempt is made to query a vault backed by a memstore.
var ErrQueryingNotSupported = errors.New("querying is not supported by memstore")

// MemEDVProvider represents an in-memory provider with functionality needed for EDV data storage.
// It wraps an edge-core memstore provider with additional functionality that's needed for EDV operations.
type MemEDVProvider struct {
	coreProvider storage.Provider
}

// NewProvider instantiates Provider
func NewProvider() *MemEDVProvider {
	return &MemEDVProvider{coreProvider: mem.NewProvider()}
}

// StoreExists returns a boolean indicating whether a given store already exists.
func (m *MemEDVProvider) StoreExists(name string) (bool, error) {
	_, err := m.coreProvider.GetStoreConfig(name)
	if err != nil {
		if errors.Is(err, storage.ErrStoreNotFound) {
			return false, nil
		}

		return false, fmt.Errorf("unexpected error while getting store config: %w", err)
	}

	return true, nil
}

// OpenStore opens an existing store and returns it.
func (m *MemEDVProvider) OpenStore(name string) (edvprovider.EDVStore, error) {
	coreStore, err := m.coreProvider.OpenStore(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open store in core provider: %w", err)
	}

	return &MemEDVStore{coreStore: coreStore}, nil
}

// SetStoreConfig sets the store configuration in the underlying core provider.
func (m *MemEDVProvider) SetStoreConfig(name string, config storage.StoreConfiguration) error {
	err := m.coreProvider.SetStoreConfig(name, config)
	if err != nil {
		return fmt.Errorf("failed to set store config in core provider: %w", err)
	}

	return nil
}

// MemEDVStore represents an in-memory store with functionality needed for EDV data storage.
// It wraps an Aries in-memory store with additional functionality that's needed for EDV operations.
type MemEDVStore struct {
	coreStore storage.Store
}

// Put stores the given document.
func (m *MemEDVStore) Put(document models.EncryptedDocument) error {
	documentBytes, err := json.Marshal(document)
	if err != nil {
		return err
	}

	return m.coreStore.Put(document.ID, documentBytes)
}

// UpsertBulk stores the given documents, creating or updating them as needed.
func (m *MemEDVStore) UpsertBulk(documents []models.EncryptedDocument) error {
	for _, document := range documents {
		err := m.Put(document)
		if err != nil {
			return fmt.Errorf("failed to store document: %w", err)
		}
	}

	return nil
}

// Get fetches the document associated with the given key.
func (m *MemEDVStore) Get(k string) ([]byte, error) {
	return m.coreStore.Get(k)
}

// Update updates the given document
func (m *MemEDVStore) Update(newDoc models.EncryptedDocument) error {
	return m.Put(newDoc)
}

// Delete deletes the given document
func (m *MemEDVStore) Delete(docID string) error {
	return m.coreStore.Delete(docID)
}

// Query is not supported in memstore, and calling it will always return an error.
func (m *MemEDVStore) Query(*models.Query) ([]models.EncryptedDocument, error) {
	return nil, ErrQueryingNotSupported
}

// StoreDataVaultConfiguration stores the given dataVaultConfiguration and vaultID
func (m *MemEDVStore) StoreDataVaultConfiguration(config *models.DataVaultConfiguration, vaultID string) error {
	err := m.checkDuplicateReferenceID(config.ReferenceID)
	if err != nil {
		return fmt.Errorf(messages.CheckDuplicateRefIDFailure, err)
	}

	configEntry := models.DataVaultConfigurationMapping{
		DataVaultConfiguration: *config,
		VaultID:                vaultID,
	}

	configBytes, err := json.Marshal(configEntry)
	if err != nil {
		return fmt.Errorf(messages.FailToMarshalConfig, err)
	}

	return m.coreStore.Put(config.ReferenceID, configBytes)
}

func (m *MemEDVStore) checkDuplicateReferenceID(referenceID string) error {
	_, err := m.coreStore.Get(referenceID)
	if err == nil {
		return messages.ErrDuplicateVault
	}

	if !errors.Is(err, storage.ErrDataNotFound) {
		return fmt.Errorf("unexpected error while trying to get existing data vault configuration: %w", err)
	}

	return nil
}
