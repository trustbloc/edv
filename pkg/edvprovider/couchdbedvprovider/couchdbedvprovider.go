/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package couchdbedvprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"
	couchdbstore "github.com/trustbloc/edge-core/pkg/storage/couchdb"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/edvutils"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const (
	mapDocumentIndexedField = "IndexName"

	mapConfigReferenceIDField = "dataVaultConfiguration.referenceId"

	failGetKeyValuePairsFromCoreStoreErrMsg = "failure while getting all key value pairs from core storage: %w"

	mappingDocumentFilteredOutLogMsg = `Getting all documents from vault %s. The following ` +
		`document will be filtered out since it is a mapping document: 
CouchDB document ID: %s
Document content: %s`
)

var logger = log.New("edv-couchdbprovider")

// ErrMissingDatabaseURL is returned when an attempt is made to instantiate a new CouchDBEDVProvider with a blank URL.
var ErrMissingDatabaseURL = errors.New("couchDB database URL not set")

type couchDBIndexMappingDocument struct {
	IndexName              string `json:"IndexName"`
	MatchingEncryptedDocID string `json:"MatchingEncryptedDocID"`
}

// CouchDBEDVProvider represents a CouchDB provider with functionality needed for EDV data storage.
// It wraps an edge-core CouchDB provider with additional functionality that's needed for EDV operations.
type CouchDBEDVProvider struct {
	coreProvider storage.Provider
}

// NewProvider instantiates Provider
func NewProvider(databaseURL, dbPrefix string) (*CouchDBEDVProvider, error) {
	couchDBProvider, err := couchdbstore.NewProvider(databaseURL, couchdbstore.WithDBPrefix(dbPrefix))
	if err != nil {
		if err.Error() == "hostURL for new CouchDB provider can't be blank" {
			return nil, ErrMissingDatabaseURL
		}

		return nil, err
	}

	return &CouchDBEDVProvider{coreProvider: couchDBProvider}, nil
}

// CreateStore creates a new store. If the given name is a base58-encoded 128-bit value, we decode and creates a uuid
// from the bytes array since couchDB does not allow using uppercase characters in database names.
func (c *CouchDBEDVProvider) CreateStore(name string) error {
	err := edvutils.CheckIfBase58Encoded128BitValue(name)
	if err == nil {
		storeName, err := edvutils.Base58Encoded128BitToUUID(name)
		if err != nil {
			return err
		}

		return c.coreProvider.CreateStore(storeName)
	}

	return c.coreProvider.CreateStore(name)
}

// OpenStore opens an existing store and returns it. The name is converted to a uuid if it is a base58-encoded
// 128-bit value.
func (c *CouchDBEDVProvider) OpenStore(name string) (edvprovider.EDVStore, error) {
	storeName := name

	if edvutils.CheckIfBase58Encoded128BitValue(name) == nil {
		storeNameString, err := edvutils.Base58Encoded128BitToUUID(name)
		if err != nil {
			return nil, err
		}

		storeName = storeNameString
	}

	coreStore, err := c.coreProvider.OpenStore(storeName)

	if err != nil {
		return nil, err
	}

	return &CouchDBEDVStore{coreStore: coreStore, name: name}, nil
}

// CouchDBEDVStore represents a CouchDB store with functionality needed for EDV data storage.
// It wraps an edge-core CouchDB store with additional functionality that's needed for EDV operations.
type CouchDBEDVStore struct {
	coreStore storage.Store
	name      string
}

// Put stores the given document.
// A mapping document is also created and stored in order to allow for encrypted indices to work.
func (c *CouchDBEDVStore) Put(document models.EncryptedDocument) error {
	err := c.validateNewDoc(document)
	if err != nil {
		return err
	}

	documentBytes, err := json.Marshal(document)
	if err != nil {
		return err
	}

	// TODO: The encrypted document and mapping document should both be stored at the same time (all-or-nothing).
	// If either of these requests fails, then the database will be left in a weird state.
	// https://github.com/trustbloc/edge-core/issues/27 and https://github.com/trustbloc/edv/issues/49

	for _, indexedAttributeCollection := range document.IndexedAttributeCollections {
		for _, indexedAttribute := range indexedAttributeCollection.IndexedAttributes {
			err := c.createMappingDocument(indexedAttribute.Name, document.ID)
			if err != nil {
				return err
			}
		}
	}

	return c.coreStore.Put(document.ID, documentBytes)
}

// GetAll fetches all the documents within this store.
// TODO: Support pagination #106
func (c *CouchDBEDVStore) GetAll() ([][]byte, error) {
	allKeyValuePairs, err := c.coreStore.GetAll()
	if err != nil {
		return nil, fmt.Errorf(failGetKeyValuePairsFromCoreStoreErrMsg, err)
	}

	var allDocuments [][]byte

	for key, value := range allKeyValuePairs {
		if strings.Contains(key, "_mapping_") {
			logger.Debugf(mappingDocumentFilteredOutLogMsg, c.name, key, value)
		} else {
			allDocuments = append(allDocuments, value)
		}
	}

	return allDocuments, nil
}

// Get fetches the document associated with the given key.
func (c *CouchDBEDVStore) Get(k string) ([]byte, error) {
	return c.coreStore.Get(k)
}

// CreateEDVIndex creates the index which will allow for encrypted indices to work.
func (c *CouchDBEDVStore) CreateEDVIndex() error {
	createIndexRequest := storage.CreateIndexRequest{
		IndexStorageLocation: "EDV_EncryptedIndexesDesignDoc",
		IndexName:            "EDV_IndexName",
		WhatToIndex:          `{"fields": ["` + mapDocumentIndexedField + `"]}`,
	}

	return c.coreStore.CreateIndex(createIndexRequest)
}

// CreateReferenceIDIndex creates index for the referenceId field in config documents
func (c *CouchDBEDVStore) CreateReferenceIDIndex() error {
	createIndexRequest := storage.CreateIndexRequest{
		IndexStorageLocation: "EDV_ConfigStoreDesignDoc",
		IndexName:            "EDV_ReferenceId",
		WhatToIndex:          `{"fields": ["` + mapConfigReferenceIDField + `"]}`,
	}

	return c.coreStore.CreateIndex(createIndexRequest)
}

// Query does an EDV encrypted index query.
// We first get the "mapping document" and then use the ID we get from that to lookup the associated encrypted document.
// Then we check that encrypted document to see if the value matches what was specified in the query.
func (c *CouchDBEDVStore) Query(query *models.Query) ([]string, error) {
	idsOfDocsWithMatchingQueryIndexName, err := c.findDocsMatchingQueryIndexName(query.Name)
	if err != nil {
		return nil, err
	}

	return c.filterDocsByQuery(idsOfDocsWithMatchingQueryIndexName, query)
}

// StoreDataVaultConfiguration stores the given DataVaultConfiguration and vaultID
func (c *CouchDBEDVStore) StoreDataVaultConfiguration(config *models.DataVaultConfiguration, vaultID string) error {
	err := c.checkDuplicateReferenceID(config.ReferenceID)
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

	return c.coreStore.Put(vaultID, configBytes)
}

func (c *CouchDBEDVStore) checkDuplicateReferenceID(referenceID string) error {
	query := `{"selector":{"` + mapConfigReferenceIDField + `":"` + referenceID +
		`"},"use_index": ["EDV_ConfigStoreDesignDoc", "EDV_ReferenceId"]}`

	itr, err := c.coreStore.Query(query)
	if err != nil {
		return err
	}

	ok, err := itr.Next()
	if err != nil {
		return err
	}

	if ok {
		return messages.ErrDuplicateVault
	}

	return nil
}

// validateNewDoc tries to ensure that index name+pairs declared unique are maintained as such. Note that
// this cannot be guaranteed due to the nature of concurrent requests and CouchDB's eventual consistency model.
func (c *CouchDBEDVStore) validateNewDoc(newDoc models.EncryptedDocument) error {
	for _, newAttributeCollection := range newDoc.IndexedAttributeCollections {
		err := c.validateNewAttributeCollection(newAttributeCollection)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *CouchDBEDVStore) validateNewAttributeCollection(
	newAttributeCollection models.IndexedAttributeCollection) error {
	for _, newAttribute := range newAttributeCollection.IndexedAttributes {
		err := c.validateNewAttribute(newAttribute)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *CouchDBEDVStore) validateNewAttribute(newAttribute models.IndexedAttribute) error {
	query := models.Query{
		Name:  newAttribute.Name,
		Value: newAttribute.Value,
	}

	existingDocIDs, err := c.Query(&query)
	if err != nil {
		return err
	}

	err = c.validateNewAttributeAgainstDocs(existingDocIDs, newAttribute)
	if err != nil {
		return err
	}

	return nil
}

func (c *CouchDBEDVStore) validateNewAttributeAgainstDocs(docIDs []string, newAttribute models.IndexedAttribute) error {
	for _, docID := range docIDs {
		err := c.validateNewAttributeAgainstDoc(newAttribute, docID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *CouchDBEDVStore) validateNewAttributeAgainstDoc(newAttribute models.IndexedAttribute, docID string) error {
	docBytes, err := c.coreStore.Get(docID)
	if err != nil {
		if errors.Is(err, storage.ErrValueNotFound) {
			return messages.ErrDocumentNotFound
		}

		return err
	}

	encryptedDoc := models.EncryptedDocument{}

	err = json.Unmarshal(docBytes, &encryptedDoc)
	if err != nil {
		return err
	}

	err = validateNewAttributeAgainstAttributeCollections(newAttribute, encryptedDoc.IndexedAttributeCollections)
	if err != nil {
		return err
	}

	return nil
}

func validateNewAttributeAgainstAttributeCollections(newAttribute models.IndexedAttribute,
	attributeCollections []models.IndexedAttributeCollection) error {
	for _, attributeCollection := range attributeCollections {
		err := validateNewAttributeAgainstAttributeCollection(newAttribute, attributeCollection)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateNewAttributeAgainstAttributeCollection(newAttribute models.IndexedAttribute,
	attributeCollection models.IndexedAttributeCollection) error {
	for _, attribute := range attributeCollection.IndexedAttributes {
		err := validateNewAttributeAgainstAttribute(newAttribute, attribute)
		if err != nil {
			return err
		}
	}

	return nil
}

func validateNewAttributeAgainstAttribute(newAttribute, attribute models.IndexedAttribute) error {
	if newAttribute.Name == attribute.Name && newAttribute.Value == attribute.Value {
		if attribute.Unique {
			return edvprovider.ErrIndexNameAndValueAlreadyDeclaredUnique
		}

		if newAttribute.Unique {
			return edvprovider.ErrIndexNameAndValueCannotBeUnique
		}
	}

	return nil
}

// createMappingDocument creates a document with a mapping of the encrypted index to the document that has it.
func (c *CouchDBEDVStore) createMappingDocument(indexedAttributeName, encryptedDocID string) error {
	mapDocument := couchDBIndexMappingDocument{
		IndexName:              indexedAttributeName,
		MatchingEncryptedDocID: encryptedDocID,
	}

	documentBytes, err := json.Marshal(mapDocument)
	if err != nil {
		return err
	}

	mappingDocumentName := encryptedDocID + "_mapping_" + uuid.New().String()

	logger.Debugf(`Creating mapping document in EDV "%s":
Name: %s,
Contents: %s`, c.name, mappingDocumentName, documentBytes)

	return c.coreStore.Put(mappingDocumentName, documentBytes)
}

func (c *CouchDBEDVStore) findDocsMatchingQueryIndexName(queryIndexName string) (map[string]struct{}, error) {
	query := `{"selector":{"` + mapDocumentIndexedField + `":"` + queryIndexName +
		`"},"use_index": ["EDV_EncryptedIndexesDesignDoc", "EDV_IndexName"]}`

	logger.Debugf(`Querying config store with the following query: %s`, query)

	itr, err := c.coreStore.Query(query)
	if err != nil {
		return nil, err
	}

	ok, err := itr.Next()
	if err != nil {
		return nil, err
	}

	idsOfDocsWithAMatchingIndex := make(map[string]struct{})

	for ok {
		value, valueErr := itr.Value()
		if valueErr != nil {
			return nil, valueErr
		}

		receivedCouchDBIndexMappingDocument := couchDBIndexMappingDocument{}

		err = json.Unmarshal(value, &receivedCouchDBIndexMappingDocument)
		if err != nil {
			return nil, err
		}

		idsOfDocsWithAMatchingIndex[receivedCouchDBIndexMappingDocument.MatchingEncryptedDocID] = struct{}{}

		ok, err = itr.Next()
		if err != nil {
			return nil, err
		}
	}

	err = itr.Release()
	if err != nil {
		return nil, err
	}

	return idsOfDocsWithAMatchingIndex, nil
}

// Given a set of documents, returns the document IDs that satisfy the query.
func (c *CouchDBEDVStore) filterDocsByQuery(docIDs map[string]struct{}, query *models.Query) ([]string, error) {
	matchingDocIDs := make([]string, 0)

	for docID := range docIDs {
		documentBytes, err := c.coreStore.Get(docID)
		if err != nil {
			if errors.Is(err, storage.ErrValueNotFound) {
				return nil, messages.ErrDocumentNotFound
			}

			return nil, err
		}

		foundEncryptedDoc := models.EncryptedDocument{}

		err = json.Unmarshal(documentBytes, &foundEncryptedDoc)
		if err != nil {
			return nil, err
		}

		if documentMatchesQuery(foundEncryptedDoc, query) {
			matchingDocIDs = append(matchingDocIDs, foundEncryptedDoc.ID)
		}
	}

	return matchingDocIDs, nil
}

func documentMatchesQuery(document models.EncryptedDocument, query *models.Query) bool {
	for _, indexedAttributeCollection := range document.IndexedAttributeCollections {
		if attributeCollectionSatisfiesQuery(indexedAttributeCollection, query) {
			return true
		}
	}

	return false
}

func attributeCollectionSatisfiesQuery(attrCollection models.IndexedAttributeCollection, query *models.Query) bool {
	for _, indexedAttribute := range attrCollection.IndexedAttributes {
		if indexedAttribute.Name == query.Name {
			if indexedAttribute.Value == query.Value {
				return true
			}
		}
	}

	return false
}
