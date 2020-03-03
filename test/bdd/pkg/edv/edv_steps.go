/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/legacy/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"

	"github.com/trustbloc/edv/pkg/client/edv"
	"github.com/trustbloc/edv/pkg/restapi/edv/operation"
	"github.com/trustbloc/edv/test/bdd/pkg/context"

	"github.com/DATA-DOG/godog"
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
	s.Step(`^Client sends request to create a new data vault with id "([^"]*)"`+
		` and receives the vault location "([^"]*)" in response$`, e.createDataVault)
	s.Step(`^Client constructs a Structured Document with id "([^"]*)"$`, e.clientConstructsAStructuredDocument)
	s.Step(`^Client encrypts the Structured Document and uses it to construct an Encrypted Document$`,
		e.clientEncryptsTheStructuredDocument)
	s.Step(`^Client stores the Encrypted Document in the data vault with id "([^"]*)" and receives the document`+
		` location "([^"]*)" in response$`, e.storeDocumentInVault)
	s.Step(`^Client sends request to retrieve the previously stored Encrypted Document with id "([^"]*)"`+
		` in the data vault with id "([^"]*)" and receives the previously stored Encrypted Document in response$`,
		e.retrieveDocument)
	s.Step(`^Client decrypts the Encrypted Document it received`+
		` in order to reconstruct the original Structured Document$`, e.decryptDocument)
}

type provider struct {
	storeProvider storage.Provider
	crypto        legacykms.KeyManager
}

func (p provider) LegacyKMS() legacykms.KeyManager {
	return p.crypto
}

func (p provider) StorageProvider() storage.Provider {
	return p.storeProvider
}

func (e *Steps) createDataVault(vaultID, expectedVaultLocation string) error {
	client := edv.New(e.bddContext.EDVHostURL)

	config := operation.DataVaultConfiguration{ReferenceID: vaultID}

	vaultLocation, err := client.CreateDataVault(&config)
	if err != nil {
		return err
	}

	if vaultLocation != expectedVaultLocation {
		return unexpectedValueError(expectedVaultLocation, vaultLocation)
	}

	return nil
}

func (e *Steps) clientConstructsAStructuredDocument(docID string) error {
	meta := make(map[string]interface{})
	meta["created"] = "2020-01-10"

	content := make(map[string]interface{})
	content["message"] = "In Bloc we trust"

	e.bddContext.StructuredDocToBeEncrypted = operation.StructuredDocument{
		ID:      docID,
		Meta:    meta,
		Content: content,
	}

	return nil
}

func (e *Steps) clientEncryptsTheStructuredDocument() error {
	memProvider := mem.NewProvider()
	p := provider{storeProvider: memProvider}

	_, err := p.StorageProvider().OpenStore("bdd-test-storage")
	if err != nil {
		return err
	}

	testingKMS, err := legacykms.New(p)
	if err != nil {
		return err
	}

	cryptProvider := provider{
		storeProvider: nil,
		crypto:        testingKMS,
	}

	packer := authcrypt.New(cryptProvider)

	marshalledStructuredDoc, err := json.Marshal(e.bddContext.StructuredDocToBeEncrypted)
	if err != nil {
		return err
	}

	_, senderKey, err := testingKMS.CreateKeySet()
	if err != nil {
		return err
	}

	// No recipients in this case, so we pass in the sender key as the recipient key as well
	encryptedStructuredDoc, err := packer.Pack(marshalledStructuredDoc,
		base58.Decode(senderKey), [][]byte{base58.Decode(senderKey)})
	if err != nil {
		return err
	}

	e.bddContext.EncryptedDocToStore = operation.EncryptedDocument{
		ID:       e.bddContext.StructuredDocToBeEncrypted.ID,
		Sequence: 0,
		JWE:      encryptedStructuredDoc,
	}

	e.bddContext.Packer = packer

	return nil
}

func (e *Steps) storeDocumentInVault(vaultID, expectedDocLocation string) error {
	client := edv.New(e.bddContext.EDVHostURL)

	docLocation, err := client.CreateDocument(vaultID, &e.bddContext.EncryptedDocToStore)
	if err != nil {
		return err
	}

	if docLocation != expectedDocLocation {
		return unexpectedValueError(expectedDocLocation, docLocation)
	}

	return nil
}

func (e *Steps) retrieveDocument(docID, vaultID string) error {
	client := edv.New(e.bddContext.EDVHostURL)

	retrievedDocumentBytes, err := client.ReadDocument(vaultID, docID)
	if err != nil {
		return err
	}

	retrievedDocument := operation.EncryptedDocument{}

	err = json.Unmarshal(retrievedDocumentBytes, &retrievedDocument)
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
	decryptedEnvelope, err := e.bddContext.Packer.Unpack(e.bddContext.ReceivedEncryptedDoc.JWE)
	if err != nil {
		return err
	}

	decryptedDoc := operation.StructuredDocument{}

	err = json.Unmarshal(decryptedEnvelope.Message, &decryptedDoc)
	if err != nil {
		return err
	}

	err = verifyStructuredDocsAreEqual(decryptedDoc, e.bddContext.StructuredDocToBeEncrypted)
	if err != nil {
		return err
	}

	return nil
}

func verifyEncryptedDocsAreEqual(retrievedDocument, expectedDocument operation.EncryptedDocument) error {
	if retrievedDocument.ID != expectedDocument.ID {
		return unexpectedValueError(expectedDocument.ID, retrievedDocument.ID)
	}

	if retrievedDocument.Sequence != expectedDocument.Sequence {
		return unexpectedValueError(string(expectedDocument.Sequence), string(retrievedDocument.Sequence))
	}

	err := verifyJWEFieldsAreEqual(expectedDocument, retrievedDocument)
	if err != nil {
		return err
	}

	return nil
}

func verifyJWEFieldsAreEqual(expectedDocument, retrievedDocument operation.EncryptedDocument) error {
	// CouchDB likes to switch around the order of the fields in the JSON.
	// This means that we can't do a direct string comparison of the JWE (json.rawmessage) fields
	// in the EncryptedDocument structs. Instead we need to check each field manually.
	var expectedJWEFields map[string]string

	err := json.Unmarshal(expectedDocument.JWE, &expectedJWEFields)
	if err != nil {
		return err
	}

	expectedProtectedFieldValue, expectedIVFieldValue, expectedCiphertextFieldValue, expectedTagFieldValue,
		err := getJWEFieldValues(expectedJWEFields, "expected JWE")
	if err != nil {
		return err
	}

	var retrievedJWEFields map[string]string

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

func getJWEFieldValues(jweFields map[string]string, jweDocType string) (string, string, string, string, error) {
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

	return protectedFieldValue, ivFieldValue, ciphertextFieldValue, tagFieldValue, nil
}

func verifyFieldsAreEqual(retrievedProtectedFieldValue, expectedProtectedFieldValue, retrievedIVFieldValue,
	expectedIVFieldValue, retrievedCiphertextFieldValue, expectedCiphertextFieldValue, retrievedTagFieldValue,
	expectedTagFieldValue string) error {
	if retrievedProtectedFieldValue != expectedProtectedFieldValue {
		return unexpectedValueError(expectedProtectedFieldValue, retrievedProtectedFieldValue)
	}

	if retrievedIVFieldValue != expectedIVFieldValue {
		return unexpectedValueError(expectedIVFieldValue, retrievedIVFieldValue)
	}

	if retrievedCiphertextFieldValue != expectedCiphertextFieldValue {
		return unexpectedValueError(expectedCiphertextFieldValue, retrievedCiphertextFieldValue)
	}

	if retrievedTagFieldValue != expectedTagFieldValue {
		return unexpectedValueError(expectedTagFieldValue, retrievedTagFieldValue)
	}

	return nil
}

func verifyStructuredDocsAreEqual(decryptedDoc, expectedDoc operation.StructuredDocument) error {
	if decryptedDoc.ID != expectedDoc.ID {
		return unexpectedValueError(expectedDoc.ID, decryptedDoc.ID)
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
		return unexpectedValueError(expectedCreatedValue, decryptedCreatedValue)
	}

	if decryptedMessageValue != expectedMessageValue {
		return unexpectedValueError(expectedMessageValue, decryptedMessageValue)
	}

	return nil
}

func getContentFieldValues(expectedDoc, decryptedDoc operation.StructuredDocument) (string, string, error) {
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

func getMetaFieldValues(expectedDoc, decryptedDoc operation.StructuredDocument) (string, string, error) {
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

func unexpectedValueError(expected, actual string) error {
	return fmt.Errorf("expected %s but got %s instead", expected, actual)
}

func fieldNotFoundError(fieldName, documentType string) error {
	return fmt.Errorf("unable to find the '" + fieldName + "' field in the " + documentType)
}

func unableToAssertAsStringError(fieldName string) error {
	return fmt.Errorf("unable to assert `" + fieldName + "` field value type as string")
}
