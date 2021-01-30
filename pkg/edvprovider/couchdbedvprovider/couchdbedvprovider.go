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
	logModuleName = "edv-couchdbprovider"

	mapDocumentIndexedField  = "IndexName"
	mapDocumentDocIDField    = "MatchingEncryptedDocID"
	mappingDocumentNameField = "MappingDocumentName"

	mapConfigReferenceIDField = "dataVaultConfiguration.referenceId"

	failGetKeyValuePairsFromCoreStoreErrMsg = "failure while getting all key value pairs from core storage: %w"
	failFilterDocsByQueryErrMsg             = "failed to filter docs by query: %w"

	mappingDocumentFilteredOutLogMsg = `Getting all documents from vault %s. The following ` +
		`document will be filtered out since it is a mapping document: 
CouchDB document ID: %s
Document content: %s`

	queryTemplate = `{"selector":{"%s":"%s"},"use_index":["EDV_EncryptedIndexesDesignDoc"` +
		`,"EDV_IndexName"],"limit":%s}`
	queryTemplateWithBookmark = `{"selector":{"%s":"%s"},"use_index":["EDV_EncryptedIndexesDesignDoc` +
		`","EDV_IndexName"],"limit":%s,"bookmark":"%s"}`
)

var logger = log.New(logModuleName)

// ErrMissingDatabaseURL is returned when an attempt is made to instantiate a new CouchDBEDVProvider with a blank URL.
var ErrMissingDatabaseURL = errors.New("couchDB database URL not set")

type indexMappingDocument struct {
	IndexName              string `json:"IndexName"`
	MatchingEncryptedDocID string `json:"MatchingEncryptedDocID"`
	MappingDocumentName    string `json:"MappingDocumentName"`
}

// CouchDBEDVProvider represents a CouchDB provider with functionality needed for EDV data storage.
// It wraps an edge-core CouchDB provider with additional functionality that's needed for EDV operations.
type CouchDBEDVProvider struct {
	coreProvider      storage.Provider
	retrievalPageSize uint
}

// NewProvider instantiates Provider
func NewProvider(databaseURL, dbPrefix string, retrievalPageSize uint) (*CouchDBEDVProvider, error) {
	couchDBProvider, err := couchdbstore.NewProvider(databaseURL, couchdbstore.WithDBPrefix(dbPrefix))
	if err != nil {
		if err.Error() == "hostURL for new CouchDB provider can't be blank" {
			return nil, ErrMissingDatabaseURL
		}

		return nil, err
	}

	return &CouchDBEDVProvider{coreProvider: couchDBProvider, retrievalPageSize: retrievalPageSize}, nil
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

	return &CouchDBEDVStore{coreStore: coreStore, name: name, retrievalPageSize: c.retrievalPageSize}, nil
}

// CouchDBEDVStore represents a CouchDB store with functionality needed for EDV data storage.
// It wraps an edge-core CouchDB store with additional functionality that's needed for EDV operations.
type CouchDBEDVStore struct {
	coreStore         storage.Store
	name              string
	retrievalPageSize uint
}

// Put stores the given document.
// Mapping documents are also created and stored in order to allow for encrypted indices to work.
func (c *CouchDBEDVStore) Put(document models.EncryptedDocument) error {
	err := c.validateNewDoc(document)
	if err != nil {
		return fmt.Errorf("failure during encrypted document validation: %w", err)
	}

	return c.UpsertBulk([]models.EncryptedDocument{document})
}

// UpsertBulk stores the given documents, creating or updating them as needed.
// TODO (#171): Address encrypted index limitations of this method.
func (c *CouchDBEDVStore) UpsertBulk(documents []models.EncryptedDocument) error {
	mappingDocuments := c.createMappingDocuments(documents)

	keysToStore := make([]string, len(mappingDocuments)+len(documents))
	valuesToStore := make([][]byte, len(mappingDocuments)+len(documents))

	for i := 0; i < len(mappingDocuments); i++ {
		keysToStore[i] = mappingDocuments[i].MappingDocumentName

		mappingDocumentBytes, errMarshal := json.Marshal(mappingDocuments[i])
		if errMarshal != nil {
			return fmt.Errorf("failed to marshal mapping document into bytes: %w", errMarshal)
		}

		logger.Debugf(`Creating mapping document in vault %s: Mapping document contents: %s`,
			c.name, mappingDocumentBytes)

		valuesToStore[i] = mappingDocumentBytes
	}

	for i := len(mappingDocuments); i < len(mappingDocuments)+len(documents); i++ {
		keysToStore[i] = documents[i-len(mappingDocuments)].ID

		documentBytes, errMarshal := json.Marshal(documents[i-len(mappingDocuments)])
		if errMarshal != nil {
			return fmt.Errorf("failed to marshal encrypted document %s: %w",
				documents[i-len(mappingDocuments)].ID, errMarshal)
		}

		valuesToStore[i] = documentBytes
	}

	err := c.coreStore.PutBulk(keysToStore, valuesToStore)
	if err != nil {
		return fmt.Errorf("failed to put encrypted document(s) and their associated mapping document(s) into "+
			"CouchDB: %w", err)
	}

	return nil
}

// createMappingDocuments creates documents with mappings of the encrypted index to the document that has it.
func (c *CouchDBEDVStore) createMappingDocuments(documents []models.EncryptedDocument) []indexMappingDocument {
	var mappingDocuments []indexMappingDocument

	for _, document := range documents {
		for _, indexedAttributeCollection := range document.IndexedAttributeCollections {
			for _, indexedAttribute := range indexedAttributeCollection.IndexedAttributes {
				mappingDocument := c.createMappingDocument(indexedAttribute, document.ID)
				mappingDocuments = append(mappingDocuments, *mappingDocument)
			}
		}
	}

	return mappingDocuments
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
	mappingDocNamesAndIndexNames, err := c.findDocsMatchingQueryEncryptedDocID(docID)
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
// If query.Has is not blank, then we assume it's a "has" query,
// and so any documents with an index name matching query.Has will be returned regardless of value.
// TODO (#168): Add support for pagination (not currently in the spec).
//  The c.retrievalPageSize parameter is passed in from the startup args and could be used with pagination.
func (c *CouchDBEDVStore) Query(query *models.Query) ([]models.EncryptedDocument, error) {
	// TODO (#169): Use c.retrievalPageSize to do pagination within this method to help control the maximum amount of
	//  memory used here. Without official pagination support it won't be possible to truly cap memory usage, however.
	var indexName string
	if query.Has != "" {
		indexName = query.Has
	} else {
		indexName = query.Name
	}

	docIDsSetMatchingQueryIndexName, err := c.findDocsMatchingQueryIndexName(indexName)
	if err != nil {
		return nil, fmt.Errorf("failed to get doc IDs matching query index name: %w", err)
	}

	if len(docIDsSetMatchingQueryIndexName) == 0 { // No documents have the encrypted index name tag
		return nil, nil
	}

	docIDsSliceMatchingQueryIndexName := convertSetToSlice(docIDsSetMatchingQueryIndexName)

	idsOfFullyMatchingDocs := docIDsSliceMatchingQueryIndexName

	if query.Value != "" {
		idsOfFullyMatchingDocs, err = c.filterDocsByQuery(docIDsSliceMatchingQueryIndexName, query)
		if err != nil {
			return nil, fmt.Errorf(failFilterDocsByQueryErrMsg, err)
		}
	}

	if len(idsOfFullyMatchingDocs) == 0 { // No documents match the query
		return nil, nil
	}

	matchingEncryptedDocs := make([]models.EncryptedDocument, len(idsOfFullyMatchingDocs))

	encryptedDocsBytes, err := c.coreStore.GetBulk(idsOfFullyMatchingDocs...)
	if err != nil {
		return nil, fmt.Errorf("failed to get all documents with matching IDs: %w", err)
	}

	for i, encryptedDocBytes := range encryptedDocsBytes {
		var matchingEncryptedDoc models.EncryptedDocument

		err = json.Unmarshal(encryptedDocBytes, &matchingEncryptedDoc)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal matching encrypted document with ID %s: %w",
				idsOfFullyMatchingDocs[i], err)
		}

		matchingEncryptedDocs[i] = matchingEncryptedDoc
	}

	return matchingEncryptedDocs, nil
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

	existingDocs, err := c.Query(&query)
	if err != nil {
		return err
	}

	err = c.validateNewAttributeAgainstDocs(existingDocs, newDocID, newAttribute)
	if err != nil {
		return err
	}

	return nil
}

func (c *CouchDBEDVStore) validateNewAttributeAgainstDocs(docs []models.EncryptedDocument, newDocID string,
	newAttribute models.IndexedAttribute) error {
	for _, doc := range docs {
		err := c.validateNewAttributeAgainstDoc(newAttribute, doc, newDocID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *CouchDBEDVStore) validateNewAttributeAgainstDoc(newAttribute models.IndexedAttribute,
	doc models.EncryptedDocument, newDocID string) error {
	// Skip validating new attribute against attribute collections of the same document while updating.
	if doc.ID == newDocID {
		return nil
	}

	err := validateNewAttributeAgainstAttributeCollections(newAttribute, doc.IndexedAttributeCollections)
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
func (c *CouchDBEDVStore) createMappingDocument(indexedAttribute models.IndexedAttribute,
	encryptedDocID string) *indexMappingDocument {
	mappingDocumentName := encryptedDocID + "_mapping_" + indexedAttribute.Name + "-" + indexedAttribute.Value

	mapDocument := indexMappingDocument{
		IndexName:              indexedAttribute.Name,
		MatchingEncryptedDocID: encryptedDocID,
		MappingDocumentName:    mappingDocumentName,
	}

	return &mapDocument
}

// createMappingDocument creates a document with a mapping of the encrypted index to the document that has it.
func (c *CouchDBEDVStore) createAndStoreMappingDocument(indexedAttributeName, encryptedDocID string) error {
	mappingDocumentName := encryptedDocID + "_mapping_" + uuid.New().String()

	mapDocument := indexMappingDocument{
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
	mappingDocNamesAndIndexNames, err := c.findDocsMatchingQueryEncryptedDocID(encryptedDocID)
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
				if err := c.createAndStoreMappingDocument(newIndexAttribute.Name, encryptedDocID); err != nil {
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

// findDocsMatchingQueryEncryptedDocID does an encrypted document ID query to obtain mapping document names and
// indexNames. It returns a map that uses the mapping document name as key and the indexName as value.
func (c *CouchDBEDVStore) findDocsMatchingQueryEncryptedDocID(encryptedDocID string) (map[string]string, error) {
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
	query := c.generateStringForMappingDocumentQuery(queryIndexName, "")

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

		var numDocumentsReturned uint

		for ok {
			value, valueErr := itr.Value()
			if valueErr != nil {
				return nil, valueErr
			}

			receivedCouchDBIndexMappingDocument := indexMappingDocument{}

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
		if numDocumentsReturned >= c.retrievalPageSize {
			query = c.generateStringForMappingDocumentQuery(queryIndexName, itr.Bookmark())
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

func (c *CouchDBEDVStore) generateStringForMappingDocumentQuery(queryIndexName, bookmark string) string {
	if bookmark == "" {
		return fmt.Sprintf(queryTemplate, mapDocumentIndexedField, queryIndexName,
			strconv.FormatUint(uint64(c.retrievalPageSize), 10))
	}

	return fmt.Sprintf(queryTemplateWithBookmark, mapDocumentIndexedField, queryIndexName,
		strconv.FormatUint(uint64(c.retrievalPageSize), 10), bookmark)
}

func (c *CouchDBEDVStore) filterDocsByQuery(docIDs []string, query *models.Query) ([]string, error) {
	var docIDsMatchingNameAndValue []string

	documentsBytes, err := c.coreStore.GetBulk(docIDs...)
	if err != nil {
		if errors.Is(err, storage.ErrValueNotFound) {
			return nil, messages.ErrDocumentNotFound
		}

		return nil, err
	}

	for _, documentBytes := range documentsBytes {
		foundEncryptedDoc := models.EncryptedDocument{}

		err = json.Unmarshal(documentBytes, &foundEncryptedDoc)
		if err != nil {
			return nil, err
		}

		if documentMatchesQuery(foundEncryptedDoc, query) {
			docIDsMatchingNameAndValue = append(docIDsMatchingNameAndValue, foundEncryptedDoc.ID)
		}
	}

	return docIDsMatchingNameAndValue, nil
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

func convertSetToSlice(docIDsSetMatchingQueryIndexName map[string]struct{}) []string {
	docIDsSliceMatchingQueryIndexName := make([]string, len(docIDsSetMatchingQueryIndexName))

	var counter int

	for docIDMatchingQueryIndexName := range docIDsSetMatchingQueryIndexName {
		docIDsSliceMatchingQueryIndexName[counter] = docIDMatchingQueryIndexName
		counter++
	}

	return docIDsSliceMatchingQueryIndexName
}
