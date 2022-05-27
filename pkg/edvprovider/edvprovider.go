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
	"go.mongodb.org/mongo-driver/mongo"
	mongooptions "go.mongodb.org/mongo-driver/mongo/options"

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

// Provider represents an EDV storage provider. It's used for performing operations involving creation/instantiation
// of Vaults.
// It wraps an Aries storage provider with additional functionality that's needed for EDV operations.
type Provider struct {
	CoreProvider                    storage.Provider
	retrievalPageSize               uint
	checkIfBase58Encoded128BitValue checkIfBase58Encoded128BitValueFunc
	base58Encoded128BitToUUID       base58Encoded128BitToUUIDFunc
}

// NewProvider instantiates a new Provider. retrievalPageSize is used by ariesProvider for query paging.
// It may be ignored if ariesProvider doesn't support paging.
func NewProvider(ariesProvider storage.Provider, retrievalPageSize uint) *Provider {
	return &Provider{
		CoreProvider:                    ariesProvider,
		retrievalPageSize:               retrievalPageSize,
		checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
		base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
	}
}

// CreateNewVault instantiates a new vault with the given dataVaultConfiguration
func (c *Provider) CreateNewVault(vaultID string, dataVaultConfiguration *models.DataVaultConfiguration) error {
	store, err := c.OpenVault(vaultID)
	if err != nil {
		return fmt.Errorf("failed to open store for vault: %w", err)
	}

	mongoDBProvider, ok := c.CoreProvider.(*mongodb.Provider)
	if ok {
		err = createMongoDBAttributeIndex(mongoDBProvider, store.underlyingStoreName)
		if err != nil {
			return err
		}
	}

	err = store.StoreDataVaultConfiguration(dataVaultConfiguration)
	if err != nil {
		return fmt.Errorf("failed to store data vault configuration: %w", err)
	}

	return nil
}

// VaultExists tells you whether the given vault already exists.
func (c *Provider) VaultExists(vaultID string) (bool, error) {
	storeName, err := c.getUnderlyingStoreName(vaultID)
	if err != nil {
		return false, fmt.Errorf("failed to determine store name to use: %w", err)
	}

	_, err = c.CoreProvider.GetStoreConfig(storeName)
	if err != nil {
		if errors.Is(err, storage.ErrStoreNotFound) {
			return false, nil
		}

		return false, fmt.Errorf("unexpected error while getting store config: %w", err)
	}

	return true, nil
}

// OpenVault opens a Vault for the given vaultID and returns it.
func (c *Provider) OpenVault(vaultID string) (*Vault, error) {
	coreStore, underlyingStoreName, err := c.openUnderlyingStore(vaultID)
	if err != nil {
		return nil, err
	}

	return &Vault{
		CoreStore:           coreStore,
		underlyingStoreName: underlyingStoreName,
		retrievalPageSize:   c.retrievalPageSize,
	}, nil
}

// AddIndexes creates indexes for the given attributeNames.
func (c *Provider) AddIndexes(vaultID string, attributeNames []string) error {
	// Need to make sure the store is open in-memory first before calling GetStoreConfig and SetStoreConfig.
	_, underlyingStoreName, err := c.openUnderlyingStore(vaultID)
	if err != nil {
		return fmt.Errorf("failed to open underlying store: %w", err)
	}

	storeConfiguration, err := c.CoreProvider.GetStoreConfig(underlyingStoreName)
	if err != nil {
		return fmt.Errorf("failed to get existing store configuration: %w", err)
	}

	storeConfiguration.TagNames = mergeTagNames(storeConfiguration.TagNames, attributeNames)

	return c.CoreProvider.SetStoreConfig(underlyingStoreName, storeConfiguration)
}

func (c *Provider) openUnderlyingStore(vaultID string) (underlyingStore storage.Store,
	underlyingStoreName string, err error) {
	storeName, err := c.getUnderlyingStoreName(vaultID)
	if err != nil {
		return nil, "",
			fmt.Errorf("failed to determine underlying store name: %w", err)
	}

	coreStore, err := c.CoreProvider.OpenStore(storeName)
	if err != nil {
		return nil, "", err
	}

	return coreStore, storeName, nil
}

// Vault represents a single vault store.
type Vault struct {
	CoreStore           storage.Store
	underlyingStoreName string
	retrievalPageSize   uint
}

// Put stores the given documents, creating or updating them as needed.
// TODO (#236): Support "unique" option on attribute pair.
func (v *Vault) Put(documents ...models.EncryptedDocument) error {
	mongoDBStore, ok := v.CoreStore.(*mongodb.Store)
	if ok {
		return storeDocumentsForMongoDB(documents, mongoDBStore)
	}

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

	err := v.CoreStore.Batch(operations)
	if err != nil {
		return fmt.Errorf("failed to store encrypted document(s): %w", err)
	}

	return nil
}

// Get fetches the document associated with the given id.
func (v *Vault) Get(id string) ([]byte, error) {
	mongoDBStore, ok := v.CoreStore.(*mongodb.Store)
	if ok {
		return getFromMongoDB(mongoDBStore, id)
	}

	return v.CoreStore.Get(id)
}

// Delete deletes the given document.
func (v *Vault) Delete(docID string) error {
	return v.CoreStore.Delete(docID)
}

// Query queries for data based on Encrypted Document attributes.
// TODO (#168): Add support for pagination (not currently in the spec).
//  The c.retrievalPageSize parameter is passed in from the startup args and could be used with pagination.
func (v *Vault) Query(query models.Query) ([]models.EncryptedDocument, error) {
	mongoDBStore, ok := v.CoreStore.(*mongodb.Store)
	if ok {
		return v.queryFromMongoDB(mongoDBStore, query)
	}

	ariesQuery, err := convertEDVQueryToAriesQuery(query)
	if err != nil {
		return nil, err
	}

	iterator, err := v.CoreStore.Query(ariesQuery, storage.WithPageSize(int(v.retrievalPageSize)))
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
func (v *Vault) StoreDataVaultConfiguration(config *models.DataVaultConfiguration) error {
	mongoDBStore, ok := v.CoreStore.(*mongodb.Store)
	if ok {
		return mongoDBStore.PutAsJSON("DataVaultConfiguration", config)
	}

	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf(messages.FailToMarshalConfig, err)
	}

	return v.CoreStore.Put("DataVaultConfiguration", configBytes)
}

// UUIDs based off vault IDs are used as store names since with the current implementation in the aries-framework-go
// storage providers, stores are case-insensitive. There could be two vault IDs (in theory) that are identical except
// for the case, so the UUID conversion should help avoid a conflict.
// With some rework, this workaround could be removed.
func (c *Provider) getUnderlyingStoreName(vaultID string) (string, error) {
	err := c.checkIfBase58Encoded128BitValue(vaultID)
	if err != nil {
		return "", fmt.Errorf("invalid vault ID: %w", err)
	}

	convertedStoreName, err := c.base58Encoded128BitToUUID(vaultID)
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID from base 58 encoded 128 bit name: %w", err)
	}

	return convertedStoreName, nil
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

func createMongoDBAttributeIndex(mongoDBProvider *mongodb.Provider, underlyingStoreName string) error {
	model := generateMongoDBIndexModel()

	err := mongoDBProvider.CreateCustomIndex(underlyingStoreName, model)
	if err != nil {
		return fmt.Errorf("failed to create index for indexed attributes: %w", err)
	}

	return nil
}

func generateMongoDBIndexModel() mongo.IndexModel {
	model := mongo.IndexModel{
		Keys: bson.D{
			{Key: "indexed.attributes.name", Value: 1},
			{Key: "indexed.attributes.value", Value: 1},
		},
		Options: mongooptions.Index().SetName("Indexed Attributes"),
	}

	return model
}

func storeDocumentsForMongoDB(documents []models.EncryptedDocument, mongoDBStore *mongodb.Store) error {
	operations := make([]mongodb.BatchAsJSONOperation, len(documents))

	for i := 0; i < len(documents); i++ {
		operations[i].Key = documents[i].ID
		// The document's ID will be used as the MongoDB document id (_id field).

		// To avoid having that data stored twice in the sample MongoDB document, we remove it from the
		// Encrypted Document object. When everything gets marshalled and stored in MongoDB, the MongoDB document will
		// look like an Encrypted Document but with the id field named _id instead.

		documents[i].ID = "" // The model uses the omitempty JSON tag to ensure this field will disappear.

		operations[i].Value = documents[i]
	}

	return mongoDBStore.BatchAsJSON(operations)
}

func getFromMongoDB(mongoDBStore *mongodb.Store, id string) ([]byte, error) {
	mongoDBDocument, err := mongoDBStore.GetAsRawMap(id)
	if err != nil {
		return nil, err
	}

	mongoDBDocument["id"] = mongoDBDocument["_id"]

	delete(mongoDBDocument, "_id")

	encryptedDocumentBytes, err := json.Marshal(mongoDBDocument)
	if err != nil {
		return nil, err
	}

	return encryptedDocumentBytes, nil
}

func (v *Vault) queryFromMongoDB(store *mongodb.Store, query models.Query) ([]models.EncryptedDocument, error) {
	mongoDBQuery := convertEDVQueryToMongoDBQuery(query)

	iterator, err := store.QueryCustom(mongoDBQuery, mongooptions.Find().SetBatchSize(int32(v.retrievalPageSize)))
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
		encryptedDocumentAsMongoDBDocument, valueErr := iterator.ValueAsRawMap()
		if valueErr != nil {
			return nil, valueErr
		}

		encryptedDocumentAsMongoDBDocument["id"] = encryptedDocumentAsMongoDBDocument["_id"]

		delete(encryptedDocumentAsMongoDBDocument, "_id")

		encryptedDocumentBytes, err := json.Marshal(encryptedDocumentAsMongoDBDocument)
		if err != nil {
			return nil, err
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

func convertEDVQueryToMongoDBQuery(edvQuery models.Query) bson.D {
	if edvQuery.Has != "" {
		return bson.D{
			{
				Key:   "indexed.attributes.name",
				Value: edvQuery.Has,
			},
		}
	}

	mongoDBORQuery := make(bson.A, len(edvQuery.Equals))

	mongoDBQuery := bson.D{
		{Key: "$or", Value: mongoDBORQuery},
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
