/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edvprovider

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edv/pkg/edvutils"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const logModuleName = "edv-provider"

var logger = log.New(logModuleName)

type (
	checkIfBase58Encoded128BitValueFunc func(id string) error
	base58Encoded128BitToUUIDFunc       func(name string) (string, error)
)

// Provider represents an EDV storage provider.
// It wraps an Aries storage provider with additional functionality that's needed for EDV operations.
type Provider struct {
	coreProvider                    storage.Provider
	retrievalPageSize               uint
	checkIfBase58Encoded128BitValue checkIfBase58Encoded128BitValueFunc
	base58Encoded128BitToUUID       base58Encoded128BitToUUIDFunc
}

// NewProvider instantiates a new Provider. retrievalPageSize is used by ariesProvider for query paging.
// It may be ignored if ariesProvider doesn't support paging.
func NewProvider(ariesProvider storage.Provider, retrievalPageSize uint) *Provider {
	return &Provider{
		coreProvider:                    ariesProvider,
		retrievalPageSize:               retrievalPageSize,
		checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
		base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
	}
}

// StoreExists returns a boolean indicating whether a given store has ever been created.
// It checks to see if the underlying database exists via the GetStoreConfig method.
func (c *Provider) StoreExists(name string) (bool, error) {
	storeName, err := c.getUnderlyingStoreName(name)
	if err != nil {
		return false, fmt.Errorf("failed to determine store name to use: %w", err)
	}

	_, err = c.coreProvider.GetStoreConfig(storeName)
	if err != nil {
		if errors.Is(err, storage.ErrStoreNotFound) {
			return false, nil
		}

		return false, fmt.Errorf("unexpected error while getting store config: %w", err)
	}

	return true, nil
}

// OpenStore opens a store for the given vaultID and returns it.
// The name is converted to a UUID if it is a base58-encoded 128-bit value.
func (c *Provider) OpenStore(vaultID string) (*Store, error) {
	coreStore, _, err := c.openUnderlyingStore(vaultID)
	if err != nil {
		return nil, err
	}

	return &Store{coreStore: coreStore, name: vaultID, retrievalPageSize: c.retrievalPageSize}, nil
}

// AddIndexes creates attributes for the given attributeKeys.
func (c *Provider) AddIndexes(vaultID string, attributeKeys []string) error {
	// Need to make sure the store is open in-memory first before calling GetStoreConfig and SetStoreConfig.
	_, underlyingStoreName, err := c.openUnderlyingStore(vaultID)
	if err != nil {
		return fmt.Errorf("failed to open underlying store: %w", err)
	}

	storeConfiguration, err := c.coreProvider.GetStoreConfig(underlyingStoreName)
	if err != nil {
		return fmt.Errorf("failed to get existing store configuration: %w", err)
	}

	storeConfiguration.TagNames = mergeTagNames(storeConfiguration.TagNames, attributeKeys)

	return c.coreProvider.SetStoreConfig(underlyingStoreName, storeConfiguration)
}

func (c *Provider) openUnderlyingStore(vaultID string) (underlyingStore storage.Store,
	underlyingStoreName string, err error) {
	storeName, err := c.getUnderlyingStoreName(vaultID)
	if err != nil {
		return nil, "",
			fmt.Errorf("failed to determine underlying store name: %w", err)
	}

	coreStore, err := c.coreProvider.OpenStore(storeName)
	if err != nil {
		return nil, "", err
	}

	return coreStore, storeName, nil
}

// Store represents an EDV store.
// It wraps an Aries store with additional functionality that's needed for EDV operations.
type Store struct {
	coreStore         storage.Store
	name              string
	retrievalPageSize uint
}

// Put stores the given document.
func (c *Store) Put(document models.EncryptedDocument) error {
	return c.UpsertBulk([]models.EncryptedDocument{document})
}

// UpsertBulk stores the given documents, creating or updating them as needed.
// TODO (#236): Support "unique" option on attribute pair.
func (c *Store) UpsertBulk(documents []models.EncryptedDocument) error {
	operations := make([]storage.Operation, len(documents))

	for i := 0; i < len(documents); i++ {
		documentBytes, errMarshal := json.Marshal(documents[i])
		if errMarshal != nil {
			return fmt.Errorf("failed to marshal encrypted document %s: %w",
				documents[i].ID, errMarshal)
		}

		operations[i].Key = documents[i].ID
		operations[i].Value = documentBytes
		operations[i].Tags = createTags(documents[i])
	}

	err := c.coreStore.Batch(operations)
	if err != nil {
		return fmt.Errorf("failed to store encrypted document(s): %w", err)
	}

	return nil
}

func createTags(document models.EncryptedDocument) []storage.Tag {
	var tags []storage.Tag

	for _, indexedAttributeCollection := range document.IndexedAttributeCollections {
		for _, indexedAttribute := range indexedAttributeCollection.IndexedAttributes {
			tags = append(tags, storage.Tag{
				Name:  indexedAttribute.Name,
				Value: indexedAttribute.Value,
			})
		}
	}

	return tags
}

// Get fetches the document associated with the given key.
func (c *Store) Get(k string) ([]byte, error) {
	return c.coreStore.Get(k)
}

// Update updates the given document.
func (c *Store) Update(newDoc models.EncryptedDocument) error {
	newDocBytes, err := json.Marshal(newDoc)
	if err != nil {
		return err
	}

	return c.coreStore.Put(newDoc.ID, newDocBytes)
}

// Delete deletes the given document.
func (c *Store) Delete(docID string) error {
	return c.coreStore.Delete(docID)
}

// Query queries for data based on Encrypted Document attributes..
// If query.Has is not blank, then we assume it's a "has" query, and so any documents with an attribute name matching
// query.Has will be returned regardless of value.
// TODO (#168): Add support for pagination (not currently in the spec).
//  The c.retrievalPageSize parameter is passed in from the startup args and could be used with pagination.
func (c *Store) Query(query *models.Query) ([]models.EncryptedDocument, error) {
	// TODO (#169): Use c.retrievalPageSize to do pagination within this method to help control the maximum amount of
	//  memory used here. Without official pagination support it won't be possible to truly cap memory usage, however.
	var queryStringForUnderlyingStorage string
	if query.Has != "" {
		queryStringForUnderlyingStorage = query.Has
	} else {
		queryStringForUnderlyingStorage = fmt.Sprintf("%s:%s", query.Name, query.Value)
	}

	documents, err := c.queryUnderlyingStore(queryStringForUnderlyingStorage)
	if err != nil {
		return nil, err
	}

	return documents, nil
}

func (c *Store) queryUnderlyingStore(query string) ([]models.EncryptedDocument, error) {
	iterator, err := c.coreStore.Query(query, storage.WithPageSize(int(c.retrievalPageSize)))
	if err != nil {
		return nil, fmt.Errorf("failed to query underlying store: %w", err)
	}

	moreEntries, err := iterator.Next()
	if err != nil {
		return nil, err
	}

	defer storage.Close(iterator, logger)

	var encryptedDocuments []models.EncryptedDocument

	for moreEntries {
		encryptedDocumentBytes, valueErr := iterator.Value()
		if valueErr != nil {
			return nil, valueErr
		}

		var encryptedDocument models.EncryptedDocument

		err = json.Unmarshal(encryptedDocumentBytes, &encryptedDocument)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal encrypted document bytes: %w", err)
		}

		encryptedDocuments = append(encryptedDocuments, encryptedDocument)

		moreEntries, err = iterator.Next()
		if err != nil {
			return nil, err
		}
	}

	return encryptedDocuments, nil
}

// StoreDataVaultConfiguration stores the given DataVaultConfiguration.
func (c *Store) StoreDataVaultConfiguration(config *models.DataVaultConfiguration) error {
	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf(messages.FailToMarshalConfig, err)
	}

	return c.coreStore.Put("DataVaultConfiguration", configBytes)
}

func (c *Provider) getUnderlyingStoreName(name string) (string, error) {
	storeName := name

	if c.checkIfBase58Encoded128BitValue(name) == nil {
		storeNameString, err := c.base58Encoded128BitToUUID(name)
		if err != nil {
			return "", fmt.Errorf("failed to generate UUID from base 58 encoded 128 bit name: %w", err)
		}

		storeName = storeNameString
	}

	return storeName, nil
}

// Adds tag names from tagNames2 that aren't in tagNames1 to tagNames1.
// Duplicate tag names in tagNames2 are discarded.
func mergeTagNames(tagNames1, tagNames2 []string) []string {
	if len(tagNames1) == 0 {
		return tagNames2
	}

	for i := 0; i < len(tagNames2); i++ {
		var found bool

		for j := 0; j < len(tagNames1); j++ {
			if tagNames2[i] == tagNames1[j] {
				found = true
				break
			}
		}

		if !found {
			tagNames1 = append(tagNames1, tagNames2[i])
		}
	}

	return tagNames1
}
