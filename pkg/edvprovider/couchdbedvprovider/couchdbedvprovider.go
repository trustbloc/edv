/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package couchdbedvprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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
	mapDocumentIndexedField  = "IndexName"
	mapDocumentDocIDField    = "MatchingEncryptedDocID"
	mappingDocumentNameField = "MappingDocumentName"

	mapConfigReferenceIDField = "dataVaultConfiguration.referenceId"

	failGetKeyValuePairsFromCoreStoreErrMsg = "failure while getting all key value pairs from core storage: %w"

	mappingDocumentFilteredOutLogMsg = `Getting all documents from vault %s. The following ` +
		`document will be filtered out since it is a mapping document: 
CouchDB document ID: %s
Document content: %s`

	queryResultsLimit = 25

	queryTemplate = `{"selector":{"%s":"%s"},"use_index":["EDV_EncryptedIndexesDesignDoc"` +
		`,"EDV_IndexName"],"limit":%s}`
	queryTemplateWithBookmark = `{"selector":{"%s":"%s"},"use_index":["EDV_EncryptedIndexesDesignDoc` +
		`","EDV_IndexName"],"limit":%s,"bookmark":"%s"}`
)

var logger = log.New("edv-couchdbprovider")

// ErrMissingDatabaseURL is returned when an attempt is made to instantiate a new CouchDBEDVProvider with a blank URL.
var ErrMissingDatabaseURL = errors.New("couchDB database URL not set")

type couchDBIndexMappingDocument struct {
	IndexName              string `json:"IndexName"`
	MatchingEncryptedDocID string `json:"MatchingEncryptedDocID"`
	MappingDocumentName    string `json:"MappingDocumentName"`
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

// Update updates the given document.
func (c *CouchDBEDVStore) Update(newDoc models.EncryptedDocument) error {
	err := c.validateNewDoc(newDoc)
	if err != nil {
		return err
	}

	err = c.updateMappingDocuments(newDoc.ID, newDoc.IndexedAttributeCollections)
	if err != nil {
		return fmt.Errorf(messages.UpdateMappingDocumentFailure, newDoc.ID, err)
	}

	newDocBytes, err := json.Marshal(newDoc)
	if err != nil {
		return err
	}

	return c.coreStore.Put(newDoc.ID, newDocBytes)
}

// Delete deletes the given document and its mapping document(s).
func (c *CouchDBEDVStore) Delete(docID string) error {
	mappingDocNamesAndIndexNames, err := c.findDocMatchingQueryEncryptedDocID(docID)
	if err != nil {
		return err
	}

	for mappingDocName := range mappingDocNamesAndIndexNames {
		err := c.deleteMappingDocument(mappingDocName)
		if err != nil {
			return fmt.Errorf(messages.DeleteMappingDocumentFailure, err)
		}
	}

	return c.coreStore.Delete(docID)
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

// CreateEncryptedDocIDIndex creates index for the MatchingEncryptedDocID field in mapping documents.
func (c *CouchDBEDVStore) CreateEncryptedDocIDIndex() error {
	createIndexRequest := storage.CreateIndexRequest{
		IndexStorageLocation: "EDV_EncryptedIndexesDesignDoc",
		IndexName:            "EDV_MatchingEncryptedDocID",
		WhatToIndex:          `{"fields": ["` + mapDocumentDocIDField + `"]}`,
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
		err := c.validateNewAttributeCollection(newAttributeCollection, newDoc.ID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *CouchDBEDVStore) validateNewAttributeCollection(
	newAttributeCollection models.IndexedAttributeCollection, docID string) error {
	for _, newAttribute := range newAttributeCollection.IndexedAttributes {
		err := c.validateNewAttribute(newAttribute, docID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *CouchDBEDVStore) validateNewAttribute(
	newAttribute models.IndexedAttribute, newDocID string) error {
	query := models.Query{
		Name:  newAttribute.Name,
		Value: newAttribute.Value,
	}

	existingDocIDs, err := c.Query(&query)
	if err != nil {
		return err
	}

	err = c.validateNewAttributeAgainstDocs(existingDocIDs, newDocID, newAttribute)
	if err != nil {
		return err
	}

	return nil
}

func (c *CouchDBEDVStore) validateNewAttributeAgainstDocs(docIDs []string, newDocID string,
	newAttribute models.IndexedAttribute) error {
	for _, docID := range docIDs {
		err := c.validateNewAttributeAgainstDoc(newAttribute, docID, newDocID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *CouchDBEDVStore) validateNewAttributeAgainstDoc(newAttribute models.IndexedAttribute,
	docID, newDocID string) error {
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

	// Skip validating new attribute against attribute collections of the same document while updating.
	if encryptedDoc.ID == newDocID {
		return nil
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
	mappingDocumentName := encryptedDocID + "_mapping_" + uuid.New().String()

	mapDocument := couchDBIndexMappingDocument{
		IndexName:              indexedAttributeName,
		MatchingEncryptedDocID: encryptedDocID,
		MappingDocumentName:    mappingDocumentName,
	}

	documentBytes, err := json.Marshal(mapDocument)
	if err != nil {
		return err
	}

	logger.Debugf(`Creating mapping document in EDV "%s":
Name: %s,
Contents: %s`, c.name, mappingDocumentName, documentBytes)

	return c.coreStore.Put(mappingDocumentName, documentBytes)
}

// updateMappingDocuments first queries mapping document names and indexNames with matching encrypted document ID.
// Then we delete the mapping documents belonging to indexNames that are removed from the update
// and create the mapping documents belonging to indexNames that are newly added.
func (c *CouchDBEDVStore) updateMappingDocuments(encryptedDocID string,
	newIndexedAttributeCollections []models.IndexedAttributeCollection) error {
	mappingDocNamesAndIndexNames, err := c.findDocMatchingQueryEncryptedDocID(encryptedDocID)
	if err != nil {
		return err
	}

	if err := c.checkAndCleanUpOldMappingDocuments(newIndexedAttributeCollections,
		mappingDocNamesAndIndexNames); err != nil {
		return err
	}

	if err := c.checkAndCreateNewMappingDocuments(encryptedDocID, newIndexedAttributeCollections,
		mappingDocNamesAndIndexNames); err != nil {
		return err
	}

	return nil
}

// checkAndCreateNewMappingDocuments checks if an indexName from the new indexedAttributeCollections already exists
// before the update, if not, create a mapping document for it.
func (c *CouchDBEDVStore) checkAndCreateNewMappingDocuments(encryptedDocID string,
	newIndexedAttributeCollections []models.IndexedAttributeCollection,
	mappingDocNamesAndIndexNames map[string]string) error {
	for _, newIndexedAttributeCollection := range newIndexedAttributeCollections {
		for _, newIndexAttribute := range newIndexedAttributeCollection.IndexedAttributes {
			indexNameFound := false

			for _, oldIndexName := range mappingDocNamesAndIndexNames {
				if oldIndexName == newIndexAttribute.Name {
					indexNameFound = true
					break
				}
			}

			if !indexNameFound {
				if err := c.createMappingDocument(newIndexAttribute.Name, encryptedDocID); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// checkAndCleanUpOldMappingDocuments checks if the existing indexNames still exist after the update and
// deletes mapping documents of those that should no longer exist.
func (c *CouchDBEDVStore) checkAndCleanUpOldMappingDocuments(
	newIndexedAttributeCollections []models.IndexedAttributeCollection,
	mappingDocNamesAndIndexNames map[string]string) error {
	for mappingDocName, oldIndexName := range mappingDocNamesAndIndexNames {
		indexNameFound := false

		for _, newIndexedAttributeCollection := range newIndexedAttributeCollections {
			for _, newIndexedAttribute := range newIndexedAttributeCollection.IndexedAttributes {
				if oldIndexName == newIndexedAttribute.Name {
					indexNameFound = true
					break
				}
			}
		}

		if !indexNameFound {
			err := c.deleteMappingDocument(mappingDocName)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *CouchDBEDVStore) deleteMappingDocument(mappingDocName string) error {
	return c.coreStore.Delete(mappingDocName)
}

// findDocMatchingQueryEncryptedDocID does an encrypted document ID query to obtain mapping document names and
// indexNames. It returns a map that uses the mapping document name as key and the indexName as value.
func (c *CouchDBEDVStore) findDocMatchingQueryEncryptedDocID(encryptedDocID string) (map[string]string, error) {
	query := `{"selector":{"` + mapDocumentDocIDField + `":"` + encryptedDocID +
		`"},"use_index": ["EDV_EncryptedIndexesDesignDoc", "EDV_MatchingEncryptedDocID"]}`

	logger.Debugf(`Querying config store with the following query: %s`, query)

	itr, err := c.coreStore.Query(query)
	if err != nil {
		return nil, err
	}

	ok, err := itr.Next()
	if err != nil {
		return nil, err
	}

	mappingDocNamesAndIndexNames := make(map[string]string)

	for ok {
		value, valueErr := itr.Value()
		if valueErr != nil {
			return nil, valueErr
		}

		rawDoc := make(map[string]string)

		err = json.Unmarshal(value, &rawDoc)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling rawDoc: %s", err)
		}

		mappingDocNamesAndIndexNames[rawDoc[mappingDocumentNameField]] = rawDoc[mapDocumentIndexedField]

		ok, err = itr.Next()
		if err != nil {
			return nil, err
		}
	}

	err = itr.Release()
	if err != nil {
		return nil, err
	}

	return mappingDocNamesAndIndexNames, nil
}

func (c *CouchDBEDVStore) findDocsMatchingQueryIndexName(queryIndexName string) (map[string]struct{}, error) {
	query := generateStringForMappingDocumentQuery(queryIndexName, "")

	idsOfDocsWithAMatchingIndex := make(map[string]struct{})

	doneWithQuery := false

	for !doneWithQuery {
		logger.Debugf(`Querying store %s with the following query: %s`, c.name, query)

		itr, err := c.coreStore.Query(query)
		if err != nil {
			return nil, err
		}

		ok, err := itr.Next()
		if err != nil {
			return nil, err
		}

		numDocumentsReturned := 0

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

			numDocumentsReturned++
		}

		// This means that there are (potentially) more pages of documents to get. Need to do another query.
		if numDocumentsReturned >= queryResultsLimit {
			query = generateStringForMappingDocumentQuery(queryIndexName, itr.Bookmark())
		} else {
			doneWithQuery = true
		}

		err = itr.Release()
		if err != nil {
			return nil, err
		}
	}

	return idsOfDocsWithAMatchingIndex, nil
}

func generateStringForMappingDocumentQuery(queryIndexName, bookmark string) string {
	if bookmark == "" {
		return fmt.Sprintf(queryTemplate, mapDocumentIndexedField, queryIndexName, strconv.Itoa(queryResultsLimit))
	}

	return fmt.Sprintf(queryTemplateWithBookmark, mapDocumentIndexedField, queryIndexName,
		strconv.Itoa(queryResultsLimit), bookmark)
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
