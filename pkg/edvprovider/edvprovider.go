/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edvprovider

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"
	"go.mongodb.org/mongo-driver/bson"
	mongodriver "go.mongodb.org/mongo-driver/mongo"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"

	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const (
	logModuleName       = "edv-provider"
	vaultIDTagName      = "vaultID"
	documentIDFieldName = "id"
)

var logger = log.New(logModuleName)

// Provider represents an EDV storage provider. It's used for performing operations involving creation/instantiation
// of Vaults.
// It wraps an Aries storage provider with additional functionality that's needed for EDV operations.
type Provider struct {
	coreProvider      storage.Provider
	configStore       storage.Store
	documentsStore    storage.Store
	retrievalPageSize uint
}

// NewProvider instantiates a new EDV storage Provider. retrievalPageSize is used by ariesProvider for query paging.
// It may be ignored if ariesProvider doesn't support paging.
func NewProvider(coreProvider storage.Provider,
	configDatabaseName, documentDatabaseName string, retrievalPageSize uint) (*Provider, error) {
	configStore, err := coreProvider.OpenStore(configDatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open configuration store: %w", err)
	}

	documentsStore, err := coreProvider.OpenStore(documentDatabaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to open document store: %w", err)
	}

	mongoDBProvider, ok := coreProvider.(*mongodb.Provider)
	if ok {
		logger.Debugf("Creating indexes for documents database...")

		err = createMongoDBIndex(mongoDBProvider, documentDatabaseName)
		if err != nil {
			return nil, fmt.Errorf("failed to create indexes in MongoDB: %w", err)
		}

		logger.Debugf("Successfully created indexes for documents database.")
	}

	return &Provider{
		coreProvider:      coreProvider,
		configStore:       configStore,
		documentsStore:    documentsStore,
		retrievalPageSize: retrievalPageSize,
	}, nil
}

// CreateNewVault instantiates a new vault with the given dataVaultConfiguration
func (p *Provider) CreateNewVault(vaultID string, dataVaultConfiguration *models.DataVaultConfiguration) error {
	mongoDBStore, ok := p.configStore.(*mongodb.Store)
	if ok {
		err := mongoDBStore.PutAsJSON(vaultID, dataVaultConfiguration)
		if err != nil {
			return fmt.Errorf(messages.StoreVaultConfigFailure, err)
		}

		return nil
	}

	configBytes, err := json.Marshal(dataVaultConfiguration)
	if err != nil {
		return fmt.Errorf(messages.FailToMarshalConfig, err)
	}

	err = p.configStore.Put(vaultID, configBytes)
	if err != nil {
		return fmt.Errorf(messages.StoreVaultConfigFailure, err)
	}

	return nil
}

// VaultExists tells you whether the given vault already exists.
func (p *Provider) VaultExists(vaultID string) (bool, error) {
	_, err := p.configStore.Get(vaultID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return false, nil
		}

		return false, fmt.Errorf("unexpected error while checking for vault configuration: %w", err)
	}

	return true, nil
}

// Put stores the given documents into a vault, creating or updating them as needed.
// TODO (#236): Support "unique" option on attribute pair.
func (p *Provider) Put(vaultID string, documents ...models.EncryptedDocument) error {
	mongoDBStore, ok := p.documentsStore.(*mongodb.Store)
	if ok {
		return storeDocumentsForMongoDB(vaultID, documents, mongoDBStore)
	}

	operations := make([]storage.Operation, len(documents))

	for i := 0; i < len(documents); i++ {
		documentBytes, errMarshal := json.Marshal(documents[i])
		if errMarshal != nil {
			return fmt.Errorf("failed to marshal encrypted document %s: %w",
				documents[i].ID, errMarshal)
		}

		operations[i].Key = generateAriesDocumentEntryKey(vaultID, documents[i].ID)
		operations[i].Value = documentBytes
		operations[i].Tags = createTags(vaultID, &documents[i])
	}

	err := p.documentsStore.Batch(operations)
	if err != nil {
		return fmt.Errorf("failed to store encrypted document(s): %w", err)
	}

	return nil
}

// Get fetches a document from a vault.
func (p *Provider) Get(vaultID, documentID string) ([]byte, error) {
	mongoDBStore, ok := p.documentsStore.(*mongodb.Store)
	if ok {
		return p.getFromMongoDB(mongoDBStore, vaultID, documentID)
	}

	return p.documentsStore.Get(generateAriesDocumentEntryKey(vaultID, documentID))
}

// Delete deletes a document from a vault.
func (p *Provider) Delete(vaultID, documentID string) error {
	mongoDBStore, ok := p.documentsStore.(*mongodb.Store)
	if ok {
		filter := bson.M{documentIDFieldName: documentID, vaultIDTagName: vaultID}

		writeModel := mongodriver.NewDeleteOneModel().SetFilter(filter)

		return mongoDBStore.BulkWrite([]mongodriver.WriteModel{writeModel})
	}

	return p.documentsStore.Delete(generateAriesDocumentEntryKey(vaultID, documentID))
}

// Query queries for data based on Encrypted Document attributes.
// TODO (#168): Add support for pagination (not currently in the spec).
//  The c.retrievalPageSize parameter is passed in from the startup args and could be used with pagination.
func (p *Provider) Query(vaultID string, query models.Query) ([]models.EncryptedDocument, error) {
	mongoDBStore, ok := p.documentsStore.(*mongodb.Store)
	if ok {
		return p.queryFromMongoDB(mongoDBStore, vaultID, query)
	}

	ariesQuery, err := convertEDVQueryToAriesQuery(query)
	if err != nil {
		return nil, err
	}

	return p.queryForEncryptedDocumentsFromAries(vaultID, ariesQuery)
}

func (p *Provider) queryForEncryptedDocumentsFromAries(vaultID, ariesQuery string) ([]models.EncryptedDocument, error) {
	iterator, err := p.documentsStore.Query(ariesQuery, storage.WithPageSize(int(p.retrievalPageSize)))
	if err != nil {
		return nil, fmt.Errorf("failed to query underlying store: %w", err)
	}

	defer storage.Close(iterator, logger)

	moreEntries, err := iterator.Next()
	if err != nil {
		return nil, err
	}

	var encryptedDocuments []models.EncryptedDocument

	for moreEntries {
		isForCorrectVault, err := vaultIDTagMatches(vaultID, iterator)
		if err != nil {
			return nil, err
		}

		if isForCorrectVault {
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
		}

		moreEntries, err = iterator.Next()
		if err != nil {
			return nil, err
		}
	}

	return encryptedDocuments, nil
}

func (p *Provider) queryFromMongoDB(store *mongodb.Store, vaultID string,
	query models.Query) ([]models.EncryptedDocument, error) {
	mongoDBQuery := convertEDVQueryToMongoDBQuery(vaultID, query)

	return p.queryForEncryptedDocumentsFromMongoDB(store, mongoDBQuery)
}

func (p *Provider) queryForEncryptedDocumentsFromMongoDB(store *mongodb.Store,
	filter interface{}) ([]models.EncryptedDocument, error) {
	iterator, err := store.QueryCustom(filter, mongooptions.Find().SetBatchSize(int32(p.retrievalPageSize)))
	if err != nil {
		return nil, fmt.Errorf("failed to query underlying store: %w", err)
	}

	defer storage.Close(iterator, logger)

	moreEntries, err := iterator.Next()
	if err != nil {
		return nil, err
	}

	var encryptedDocuments []models.EncryptedDocument

	for moreEntries {
		mongoDBDocument, valueErr := iterator.ValueAsRawMap()
		if valueErr != nil {
			return nil, valueErr
		}

		encryptedDocumentBytes, err := json.Marshal(mongoDBDocument)
		if err != nil {
			return nil, err
		}

		var encryptedDocument models.EncryptedDocument

		err = json.Unmarshal(encryptedDocumentBytes, &encryptedDocument)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal encrypted document bytes: %w", err)
		}

		// This field is just for internal use - remove it before sending to client since it's not a proper field
		// in an Encrypted Document.
		encryptedDocument.VaultID = ""

		encryptedDocuments = append(encryptedDocuments, encryptedDocument)

		moreEntries, err = iterator.Next()
		if err != nil {
			return nil, err
		}
	}

	return encryptedDocuments, nil
}

func createMongoDBIndex(mongoDBProvider *mongodb.Provider, documentDatabaseName string) error {
	indexModels := generateMongoDBIndexModels()

	return mongoDBProvider.CreateCustomIndexes(documentDatabaseName, indexModels...)
}

func convertEDVQueryToAriesQuery(query models.Query) (string, error) {
	if query.Has != "" {
		return query.Has, nil
	}

	if len(query.Equals) > 1 || len(query.Equals[0]) > 1 {
		return "", errors.New("support for multiple attribute queries not implemented for " +
			"CouchDB or in-memory storage")
	}

	// Note: The case where query.Equals has no elements is handled in operations.go.
	for attributeName, attributeValue := range query.Equals[0] {
		return fmt.Sprintf("%s:%s", attributeName, attributeValue), nil
	}

	return "", nil
}

func generateMongoDBIndexModels() []mongodriver.IndexModel {
	model := []mongodriver.IndexModel{
		{
			Keys: bson.D{
				{Key: documentIDFieldName, Value: 1},
				{Key: vaultIDTagName, Value: 1},
			},
			Options: mongooptions.Index().SetName("DocumentIDAndVaultID").SetUnique(true),
		},
		{
			Keys: bson.D{
				{Key: "indexed.attributes.name", Value: 1},
				{Key: "indexed.attributes.value", Value: 1},
				{Key: vaultIDTagName, Value: 1},
			},
			Options: mongooptions.Index().SetName("AttributesAndVaultID"),
		},
	}

	return model
}

func storeDocumentsForMongoDB(vaultID string, documents []models.EncryptedDocument, mongoDBStore *mongodb.Store) error {
	writeModels := make([]mongodriver.WriteModel, len(documents))

	for i := 0; i < len(documents); i++ {
		documents[i].VaultID = vaultID

		mongoDBDocument, err := mongodb.PrepareDataForBSONStorage(documents[i])
		if err != nil {
			return err
		}

		filter := bson.M{documentIDFieldName: documents[i].ID, vaultIDTagName: vaultID}

		writeModels[i] = mongodriver.NewReplaceOneModel().SetFilter(filter).
			SetReplacement(mongoDBDocument).SetUpsert(true)
	}

	return mongoDBStore.BulkWrite(writeModels)
}

func (p *Provider) getFromMongoDB(store *mongodb.Store, vaultID, documentID string) ([]byte, error) {
	filter := bson.D{
		{Key: documentIDFieldName, Value: documentID},
		{Key: vaultIDTagName, Value: vaultID},
	}

	documents, err := p.queryForEncryptedDocumentsFromMongoDB(store, filter)
	if err != nil {
		return nil, err
	}

	if len(documents) == 0 {
		return nil, storage.ErrDataNotFound
	}

	documentBytes, err := json.Marshal(documents[0])
	if err != nil {
		return nil, err
	}

	return documentBytes, nil
}

func convertEDVQueryToMongoDBQuery(vaultID string, edvQuery models.Query) bson.D {
	if edvQuery.Has != "" {
		return bson.D{
			{
				Key:   "indexed.attributes.name",
				Value: edvQuery.Has,
			},
			{
				Key:   vaultIDTagName,
				Value: vaultID,
			},
		}
	}

	mongoDBORQuery := make(bson.A, len(edvQuery.Equals))

	mongoDBQuery := bson.D{
		{
			Key:   "$or",
			Value: mongoDBORQuery,
		},
		{
			Key:   vaultIDTagName,
			Value: vaultID,
		},
	}

	for i, subfilter := range edvQuery.Equals {
		var mongoDBANDQuery bson.D

		for attributeName, attributeValue := range subfilter {
			mongoDBANDQuery = append(mongoDBANDQuery,
				bson.E{
					Key:   "indexed.attributes.name",
					Value: attributeName,
				})

			if attributeValue != "" {
				mongoDBANDQuery = append(mongoDBANDQuery,
					bson.E{
						Key:   "indexed.attributes.value",
						Value: attributeValue,
					})
			}
		}

		mongoDBORQuery[i] = mongoDBANDQuery
	}

	return mongoDBQuery
}

func generateAriesDocumentEntryKey(vaultID, documentID string) string {
	return fmt.Sprintf("%s-%s", vaultID, documentID)
}

func createTags(vaultID string, document *models.EncryptedDocument) []storage.Tag {
	tags := []storage.Tag{
		{Name: vaultIDTagName, Value: vaultID},
	}

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

func vaultIDTagMatches(targetVaultID string, queryResultsIterator storage.Iterator) (bool, error) {
	tags, err := queryResultsIterator.Tags()
	if err != nil {
		return false, err
	}

	for _, tag := range tags {
		if tag.Name == vaultIDTagName && tag.Value == targetVaultID {
			return true, nil
		}
	}

	return false, nil
}
