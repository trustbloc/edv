/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdhes"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/keyio"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"

	"github.com/trustbloc/edv/pkg/restapi/models"
	"github.com/trustbloc/edv/test/bdd/pkg/common"
	"github.com/trustbloc/edv/test/bdd/pkg/context"
)

const (
	jweProtectedFieldName  = "protected"
	jweIVFieldName         = "iv"
	jweCiphertextFieldName = "ciphertext"
	jweTagFieldName        = "tag"

	contentMessageFieldName = "message"
	metaCreatedFieldName    = "created"

	documentTypeExpectedStructuredDoc  = "expected Structured Document"
	documentTypeDecryptedStructuredDoc = "decrypted Structured Document"

	testReferenceID = "testReferenceID"
)

// Steps is steps for EDV BDD tests
type Steps struct {
	bddContext *context.BDDContext
}

// NewSteps returns BDD test steps for EDV server
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

// RegisterSteps registers EDV server test steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^Client sends request to create a new data vault and receives the vault location$`, e.createDataVault)
	s.Step(`^Client constructs a Structured Document with id "([^"]*)"$`, e.clientConstructsAStructuredDocument)
	s.Step(`^Client encrypts the Structured Document and uses it to construct an Encrypted Document$`,
		e.clientEncryptsTheStructuredDocument)
	s.Step(`^Client stores the Encrypted Document in the data vault`, e.storeDocumentInVault)
	s.Step(`^Client sends request to retrieve the previously stored Encrypted Document with id "([^"]*)"`+
		` in the data vault and receives the previously stored Encrypted Document in response$`,
		e.retrieveDocument)
	s.Step(`^Client decrypts the Encrypted Document it received`+
		` in order to reconstruct the original Structured Document$`, e.decryptDocument)
	s.Step(`^Client queries the vault to find the previously created document `+
		`with an encrypted index named "([^"]*)" with associated value "([^"]*)"$`,
		e.queryVault)
}

func (e *Steps) createDataVault() error {
	config := models.DataVaultConfiguration{
		Sequence:    0,
		Controller:  "did:example:123456789",
		Invoker:     []string{},
		Delegator:   []string{},
		ReferenceID: testReferenceID,
		KEK:         models.IDTypePair{ID: "https://example.com/kms/12345", Type: "AesKeyWrappingKey2019"},
		HMAC:        models.IDTypePair{ID: "https://example.com/kms/67891", Type: "Sha256HmacKey2019"},
	}

	vaultLocation, err := e.bddContext.EDVClient.CreateDataVault(&config)

	s := strings.Split(vaultLocation, "/")
	vaultID := s[len(s)-1]
	e.bddContext.VaultID = vaultID

	return err
}

func (e *Steps) clientConstructsAStructuredDocument(docID string) error {
	meta := make(map[string]interface{})
	meta["created"] = "2020-01-10"

	content := make(map[string]interface{})
	content["message"] = "In Bloc we trust"

	e.bddContext.StructuredDocToBeEncrypted = &models.StructuredDocument{
		ID:      docID,
		Meta:    meta,
		Content: content,
	}

	return nil
}

func (e *Steps) clientEncryptsTheStructuredDocument() error {
	marshalledStructuredDoc, err := json.Marshal(e.bddContext.StructuredDocToBeEncrypted)
	if err != nil {
		return err
	}

	keyHandle, err := keyset.NewHandle(ecdhes.ECDHES256KWAES256GCMKeyTemplate())
	if err != nil {
		return err
	}

	pubKH, err := keyHandle.Public()
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	pubKeyWriter := keyio.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	if err != nil {
		return err
	}

	ecPubKey := new(composite.PublicKey)

	err = json.Unmarshal(buf.Bytes(), ecPubKey)
	if err != nil {
		return err
	}

	jweEncrypter, err := jose.NewJWEEncrypt(jose.A256GCM, composite.DIDCommEncType, "", nil,
		[]*composite.PublicKey{ecPubKey})
	if err != nil {
		return err
	}

	encryptedDocToStore, err := e.buildEncryptedDoc(jweEncrypter, marshalledStructuredDoc)
	if err != nil {
		return err
	}

	e.bddContext.EncryptedDocToStore = encryptedDocToStore

	e.bddContext.JWEDecrypter = jose.NewJWEDecrypt(nil, keyHandle)

	return nil
}

func (e *Steps) storeDocumentInVault() error {
	_, err := e.bddContext.EDVClient.CreateDocument(e.bddContext.VaultID, e.bddContext.EncryptedDocToStore)

	return err
}

func (e *Steps) retrieveDocument(docID string) error {
	retrievedDocument, err := e.bddContext.EDVClient.ReadDocument(e.bddContext.VaultID, docID)
	if err != nil {
		return err
	}

	err = verifyEncryptedDocsAreEqual(retrievedDocument, e.bddContext.EncryptedDocToStore)
	if err != nil {
		return err
	}

	e.bddContext.ReceivedEncryptedDoc = retrievedDocument

	return nil
}

func (e *Steps) decryptDocument() error {
	encryptedJWE, err := jose.Deserialize(string(e.bddContext.ReceivedEncryptedDoc.JWE))
	if err != nil {
		return err
	}

	decryptedDocBytes, err := e.bddContext.JWEDecrypter.Decrypt(encryptedJWE)
	if err != nil {
		return err
	}

	decryptedDoc := models.StructuredDocument{}

	err = json.Unmarshal(decryptedDocBytes, &decryptedDoc)
	if err != nil {
		return err
	}

	err = verifyStructuredDocsAreEqual(&decryptedDoc, e.bddContext.StructuredDocToBeEncrypted)
	if err != nil {
		return err
	}

	return nil
}

func (e *Steps) queryVault(queryIndexName, queryIndexValue string) error {
	query := models.Query{
		Name:  queryIndexName,
		Value: queryIndexValue,
	}

	docURLs, err := e.bddContext.EDVClient.QueryVault(e.bddContext.VaultID, &query)
	if err != nil {
		return err
	}

	numDocumentsFound := len(docURLs)
	expectedDocumentsFound := 1

	if numDocumentsFound != expectedDocumentsFound {
		return errors.New("expected query to find " + strconv.Itoa(expectedDocumentsFound) +
			" document(s), but " + strconv.Itoa(numDocumentsFound) + " were found instead")
	}

	expectedDocURL := "localhost:8080/encrypted-data-vaults/" + e.bddContext.VaultID +
		"/documents/VJYHHJx4C8J9Fsgz7rZqSp"

	if docURLs[0] != expectedDocURL {
		return common.UnexpectedValueError(expectedDocURL, docURLs[0])
	}

	return nil
}

func (e *Steps) buildEncryptedDoc(jweEncrypter jose.Encrypter,
	marshalledStructuredDoc []byte) (*models.EncryptedDocument, error) {
	jwe, err := jweEncrypter.Encrypt(marshalledStructuredDoc)
	if err != nil {
		return nil, err
	}

	encryptedStructuredDoc, err := jwe.FullSerialize(json.Marshal)
	if err != nil {
		return nil, err
	}

	// TODO: Update this to demonstrate a full example of how to create an indexed attribute using HMAC-SHA256.
	// https://github.com/trustbloc/edv/issues/53
	indexedAttribute := models.IndexedAttribute{
		Name:   "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
		Value:  "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
		Unique: false,
	}

	indexedAttributeCollection := models.IndexedAttributeCollection{
		Sequence:          0,
		HMAC:              models.IDTypePair{},
		IndexedAttributes: []models.IndexedAttribute{indexedAttribute},
	}

	indexedAttributeCollections := []models.IndexedAttributeCollection{indexedAttributeCollection}

	encryptedDocToStore := &models.EncryptedDocument{
		ID:                          e.bddContext.StructuredDocToBeEncrypted.ID,
		Sequence:                    0,
		JWE:                         []byte(encryptedStructuredDoc),
		IndexedAttributeCollections: indexedAttributeCollections,
	}

	return encryptedDocToStore, nil
}

func verifyEncryptedDocsAreEqual(retrievedDocument, expectedDocument *models.EncryptedDocument) error {
	if retrievedDocument.ID != expectedDocument.ID {
		return common.UnexpectedValueError(expectedDocument.ID, retrievedDocument.ID)
	}

	if retrievedDocument.Sequence != expectedDocument.Sequence {
		return common.UnexpectedValueError(string(expectedDocument.Sequence), string(retrievedDocument.Sequence))
	}

	err := verifyJWEFieldsAreEqual(expectedDocument, retrievedDocument)
	if err != nil {
		return err
	}

	return nil
}

func verifyJWEFieldsAreEqual(expectedDocument, retrievedDocument *models.EncryptedDocument) error {
	// CouchDB likes to switch around the order of the fields in the JSON.
	// This means that we can't do a direct string comparison of the JWE (json.rawmessage) fields
	// in the EncryptedDocument structs. Instead we need to check each field manually.
	var expectedJWEFields map[string]json.RawMessage

	err := json.Unmarshal(expectedDocument.JWE, &expectedJWEFields)
	if err != nil {
		return err
	}

	expectedProtectedFieldValue, expectedIVFieldValue, expectedCiphertextFieldValue, expectedTagFieldValue,
		err := getJWEFieldValues(expectedJWEFields, "expected JWE")
	if err != nil {
		return err
	}

	var retrievedJWEFields map[string]json.RawMessage

	err = json.Unmarshal(retrievedDocument.JWE, &retrievedJWEFields)
	if err != nil {
		return err
	}

	retrievedProtectedFieldValue, retrievedIVFieldValue, retrievedCiphertextFieldValue, retrievedTagFieldValue,
		err := getJWEFieldValues(retrievedJWEFields, "retrieved JWE")
	if err != nil {
		return err
	}

	err = verifyFieldsAreEqual(
		retrievedProtectedFieldValue, expectedProtectedFieldValue,
		retrievedIVFieldValue, expectedIVFieldValue,
		retrievedCiphertextFieldValue, expectedCiphertextFieldValue,
		retrievedTagFieldValue, expectedTagFieldValue)
	if err != nil {
		return err
	}

	return nil
}

func getJWEFieldValues(jweFields map[string]json.RawMessage,
	jweDocType string) (string, string, string, string, error) {
	protectedFieldValue, found := jweFields[jweProtectedFieldName]
	if !found {
		return "", "", "", "", fieldNotFoundError(jweProtectedFieldName, jweDocType)
	}

	ivFieldValue, found := jweFields[jweIVFieldName]
	if !found {
		return "", "", "", "", fieldNotFoundError(jweIVFieldName, jweDocType)
	}

	ciphertextFieldValue, found := jweFields[jweCiphertextFieldName]
	if !found {
		return "", "", "", "", fieldNotFoundError(jweCiphertextFieldName, jweDocType)
	}

	tagFieldValue, found := jweFields[jweTagFieldName]
	if !found {
		return "", "", "", "", fieldNotFoundError(jweTagFieldName, jweDocType)
	}

	return string(protectedFieldValue), string(ivFieldValue), string(ciphertextFieldValue), string(tagFieldValue), nil
}

func verifyFieldsAreEqual(retrievedProtectedFieldValue, expectedProtectedFieldValue, retrievedIVFieldValue,
	expectedIVFieldValue, retrievedCiphertextFieldValue, expectedCiphertextFieldValue, retrievedTagFieldValue,
	expectedTagFieldValue string) error {
	if retrievedProtectedFieldValue != expectedProtectedFieldValue {
		return common.UnexpectedValueError(expectedProtectedFieldValue, retrievedProtectedFieldValue)
	}

	if retrievedIVFieldValue != expectedIVFieldValue {
		return common.UnexpectedValueError(expectedIVFieldValue, retrievedIVFieldValue)
	}

	if retrievedCiphertextFieldValue != expectedCiphertextFieldValue {
		return common.UnexpectedValueError(expectedCiphertextFieldValue, retrievedCiphertextFieldValue)
	}

	if retrievedTagFieldValue != expectedTagFieldValue {
		return common.UnexpectedValueError(expectedTagFieldValue, retrievedTagFieldValue)
	}

	return nil
}

func verifyStructuredDocsAreEqual(decryptedDoc, expectedDoc *models.StructuredDocument) error {
	if decryptedDoc.ID != expectedDoc.ID {
		return common.UnexpectedValueError(expectedDoc.ID, decryptedDoc.ID)
	}

	expectedCreatedValue, decryptedCreatedValue, err := getMetaFieldValues(expectedDoc, decryptedDoc)
	if err != nil {
		return err
	}

	expectedMessageValue, decryptedMessageValue, err := getContentFieldValues(expectedDoc, decryptedDoc)
	if err != nil {
		return err
	}

	if decryptedCreatedValue != expectedCreatedValue {
		return common.UnexpectedValueError(expectedCreatedValue, decryptedCreatedValue)
	}

	if decryptedMessageValue != expectedMessageValue {
		return common.UnexpectedValueError(expectedMessageValue, decryptedMessageValue)
	}

	return nil
}

func getContentFieldValues(expectedDoc, decryptedDoc *models.StructuredDocument) (string, string, error) {
	expectedMessageFieldInContent, found := expectedDoc.Content[contentMessageFieldName]
	if !found {
		return "", "", fieldNotFoundError(contentMessageFieldName, documentTypeExpectedStructuredDoc)
	}

	expectedMessageFieldInContentString, ok := expectedMessageFieldInContent.(string)
	if !ok {
		return "", "", unableToAssertAsStringError(contentMessageFieldName)
	}

	decryptedMessageFieldInContent, found := decryptedDoc.Content[contentMessageFieldName]
	if !found {
		return "", "", fieldNotFoundError(contentMessageFieldName, documentTypeDecryptedStructuredDoc)
	}

	decryptedMessageFieldInContentString, ok := decryptedMessageFieldInContent.(string)
	if !ok {
		return "", "", unableToAssertAsStringError(contentMessageFieldName)
	}

	return expectedMessageFieldInContentString, decryptedMessageFieldInContentString, nil
}

func getMetaFieldValues(expectedDoc, decryptedDoc *models.StructuredDocument) (string, string, error) {
	expectedCreatedFieldInMeta, found := expectedDoc.Meta[metaCreatedFieldName]
	if !found {
		return "", "", fieldNotFoundError(metaCreatedFieldName, documentTypeExpectedStructuredDoc)
	}

	expectedCreatedFieldInMetaString, ok := expectedCreatedFieldInMeta.(string)
	if !ok {
		return "", "", unableToAssertAsStringError(metaCreatedFieldName)
	}

	decryptedCreatedFieldInMeta, found := decryptedDoc.Meta[metaCreatedFieldName]
	if !found {
		return "", "", fieldNotFoundError(metaCreatedFieldName, documentTypeDecryptedStructuredDoc)
	}

	decryptedCreatedFieldInMetaString, ok := decryptedCreatedFieldInMeta.(string)
	if !ok {
		return "", "", unableToAssertAsStringError(metaCreatedFieldName)
	}

	return expectedCreatedFieldInMetaString, decryptedCreatedFieldInMetaString, nil
}

func fieldNotFoundError(fieldName, documentType string) error {
	return fmt.Errorf("unable to find the '" + fieldName + "' field in the " + documentType)
}

func unableToAssertAsStringError(fieldName string) error {
	return fmt.Errorf("unable to assert `" + fieldName + "` field value type as string")
}
