/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	jld "github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/edvutils"
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

	edvResource = "urn:edv:vault"

	numDocumentsForParallelTest = 100
	numThreadsForParallelTest   = 10
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
	s.Step(`^Client stores the Encrypted Document in the data vault with empty signature header`,
		e.storeDocumentInVaultWithoutSignature)
	s.Step(`^Client stores the Encrypted Document in the data vault`, e.storeDocumentInVault)
	s.Step(`^Client sends request to retrieve the previously stored Encrypted Document with id "([^"]*)"`+
		` in the data vault and receives the previously stored Encrypted Document in response$`,
		e.retrieveDocument)
	s.Step(`^Client decrypts the Encrypted Document it received`+
		` in order to reconstruct the original Structured Document$`, e.decryptDocument)
	s.Step(`^Client queries the vault to find the previously created document `+
		`with an encrypted index named "([^"]*)" with associated value "([^"]*)"$`,
		e.queryVault)
	s.Step(`^Client changes the Structured Document with id "([^"]*)" in order to update the`+
		` Encrypted Document in the data vault$`, e.clientReconstructsAStructuredDocument)
	s.Step(`^Client encrypts the new Structured Document and uses it to construct an `+
		`Encrypted Document$`, e.clientEncryptsTheStructuredDocument)
	s.Step(`^Client updates Structured Document with id "([^"]*)" in the data vault$`, e.updateDocumentInVault)
	s.Step(`^Client sends request to retrieve the updated Encrypted Document with id "([^"]*)" in the data `+
		`vault and receives the updated Encrypted Document in response$`, e.retrieveDocument)
	s.Step(`^Client decrypts the Encrypted Document it received`+
		` in order to reconstruct the original Structured Document$`, e.decryptDocument)
	s.Step(`^Client deletes the Encrypted Document with id "([^"]*)" from the vault$`, e.deleteDocument)
	s.Step(`^Client stores the Encrypted Document again$`, e.storeDocumentInVault)
	s.Step(`^Client stores (\d+) documents using (\d+) threads$`, e.clientStoresDocumentsInParallel)
}

func (e *Steps) createDataVault() error {
	signer, err := signature.NewCryptoSigner(e.bddContext.Crypto, e.bddContext.KeyManager, kms.ED25519)
	if err != nil {
		return fmt.Errorf("failed to create crypto signer: %w", err)
	}

	_, didKeyURL := fingerprint.CreateDIDKey(signer.PublicKeyBytes())

	config := models.DataVaultConfiguration{
		Sequence:    0,
		Controller:  didKeyURL,
		ReferenceID: uuid.New().String(),
		KEK:         models.IDTypePair{ID: "https://example.com/kms/12345", Type: "AesKeyWrappingKey2019"},
		HMAC:        models.IDTypePair{ID: "https://example.com/kms/67891", Type: "Sha256HmacKey2019"},
	}

	vaultLocation, resp, err := e.bddContext.EDVClient.CreateDataVault(&config,
		client.WithRequestHeader(func(req *http.Request) (*http.Header, error) {
			return nil, nil
		}))
	if err != nil {
		return err
	}

	s := strings.Split(vaultLocation, "/")
	vaultID := s[len(s)-1]
	e.bddContext.VaultID = vaultID

	capability, err := zcapld.ParseCapability(resp)
	if err != nil {
		return err
	}

	if capability.Context != zcapld.SecurityContextV2 {
		return fmt.Errorf("wrong ctx return for zcapld")
	}

	// create chain capability
	c, err := e.createChainCapability(capability, signer, vaultID)
	if err != nil {
		return err
	}

	e.bddContext.Capability = c

	return nil
}

func (e *Steps) createChainCapability(capability *zcapld.Capability, capabilitySigner verifiable.Signer,
	vaultID string) (*zcapld.Capability, error) {
	signer, err := signature.NewCryptoSigner(e.bddContext.Crypto, e.bddContext.KeyManager, kms.ED25519)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto signer: %w", err)
	}

	_, didKeyURL := fingerprint.CreateDIDKey(signer.PublicKeyBytes())

	loader, err := jld.NewDocumentLoader(mem.NewProvider())
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	return zcapld.NewCapability(&zcapld.Signer{
		SignatureSuite:     ed25519signature2018.New(suite.WithSigner(capabilitySigner)),
		SuiteType:          ed25519signature2018.SignatureType,
		VerificationMethod: capability.Invoker,
		ProcessorOpts:      []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(loader)},
	}, zcapld.WithParent(capability.ID), zcapld.WithInvoker(didKeyURL), zcapld.WithAllowedActions("read", "write"),
		zcapld.WithInvocationTarget(vaultID, edvResource), zcapld.WithCapabilityChain(capability.Parent, capability.ID))
}

func (e *Steps) clientConstructsAStructuredDocument(docID string) error {
	e.bddContext.StructuredDocToBeEncrypted = constructStructuredDocument(docID)

	return nil
}

func constructStructuredDocument(docID string) *models.StructuredDocument {
	meta := make(map[string]interface{})
	meta["created"] = "2020-01-10"

	content := make(map[string]interface{})
	content["message"] = "In Bloc we trust"

	return &models.StructuredDocument{
		ID:      docID,
		Meta:    meta,
		Content: content,
	}
}

func (e *Steps) clientEncryptsTheStructuredDocument() error {
	marshalledStructuredDoc, err := json.Marshal(e.bddContext.StructuredDocToBeEncrypted)
	if err != nil {
		return err
	}

	_, ecPubKeyBytes, err := e.bddContext.KeyManager.CreateAndExportPubKeyBytes(kms.NISTP256ECDHKWType)
	if err != nil {
		return err
	}

	ecPubKey := new(cryptoapi.PublicKey)

	err = json.Unmarshal(ecPubKeyBytes, ecPubKey)
	if err != nil {
		return err
	}

	jweEncrypter, err := jose.NewJWEEncrypt(jose.A256GCM, packer.ContentEncodingTypeV2, "", "", nil,
		[]*cryptoapi.PublicKey{ecPubKey}, e.bddContext.Crypto)
	if err != nil {
		return err
	}

	encryptedDocToStore, err := e.buildEncryptedDoc(jweEncrypter, marshalledStructuredDoc)
	if err != nil {
		return err
	}

	e.bddContext.EncryptedDocToStore = encryptedDocToStore
	e.bddContext.JWEDecrypter = jose.NewJWEDecrypt(nil, e.bddContext.Crypto, e.bddContext.KeyManager)

	return nil
}

func (e *Steps) storeDocumentInVaultWithoutSignature() error {
	_, err := e.bddContext.EDVClient.CreateDocument(e.bddContext.VaultID, e.bddContext.EncryptedDocToStore)

	if err == nil {
		return fmt.Errorf("create docment didn't failed with empty signature header")
	}

	errMsg := "signature header not found"
	if !strings.Contains(err.Error(), errMsg) {
		return fmt.Errorf("error msg %s didn't contains %s", err.Error(), errMsg) //nolint:errorlint
	}

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
	docURLs, err := e.bddContext.EDVClient.QueryVault(e.bddContext.VaultID, queryIndexName, queryIndexValue)
	if err != nil {
		return err
	}

	numDocumentsFound := len(docURLs)

	if expectedDocumentsFound := 1; numDocumentsFound != expectedDocumentsFound {
		return errors.New("expected query to find " + strconv.Itoa(expectedDocumentsFound) +
			" document(s), but " + strconv.Itoa(numDocumentsFound) + " were found instead")
	}

	expectedDocURL := "edv/encrypted-data-vaults/" + e.bddContext.VaultID +
		"/documents/VJYHHJx4C8J9Fsgz7rZqSp"

	if docURLs[0] != expectedDocURL {
		return common.UnexpectedValueError(expectedDocURL, docURLs[0])
	}

	return nil
}

func (e *Steps) clientReconstructsAStructuredDocument(docID string) error {
	meta := make(map[string]interface{})
	meta["created"] = "2020-01-10"

	content := make(map[string]interface{})
	content["message"] = "Message updated"

	e.bddContext.StructuredDocToBeEncrypted = &models.StructuredDocument{
		ID:      docID,
		Meta:    meta,
		Content: content,
	}

	return nil
}

func (e *Steps) updateDocumentInVault(docID string) error {
	err := e.bddContext.EDVClient.UpdateDocument(e.bddContext.VaultID, docID, e.bddContext.EncryptedDocToStore)

	return err
}

func (e *Steps) deleteDocument(docID string) error {
	err := e.bddContext.EDVClient.DeleteDocument(e.bddContext.VaultID, docID)
	if err != nil {
		return err
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

// Currently hardcoded to use 100 documents and 10 threads (10 documents per thread).
func (e *Steps) clientStoresDocumentsInParallel(_, _ int) error {
	println("Creating key to encrypt documents with.")

	_, ecPubKeyBytes, err := e.bddContext.KeyManager.CreateAndExportPubKeyBytes(kms.NISTP256ECDHKWType)
	if err != nil {
		return err
	}

	ecPubKey := new(cryptoapi.PublicKey)

	err = json.Unmarshal(ecPubKeyBytes, ecPubKey)
	if err != nil {
		return err
	}

	jweEncrypter, err := jose.NewJWEEncrypt(jose.A256GCM, packer.ContentEncodingTypeV2, "", "", nil,
		[]*cryptoapi.PublicKey{ecPubKey}, e.bddContext.Crypto)
	if err != nil {
		return err
	}

	encryptedDocuments, err := generateEncryptedDocuments(jweEncrypter)
	if err != nil {
		return fmt.Errorf("failed to generate encrypted documents: %w", err)
	}

	encryptedDocumentLocations := e.storeDocumentsInParallel(encryptedDocuments)

	for i := 0; i < numDocumentsForParallelTest; i++ {
		expectedDocumentLocation := fmt.Sprintf("edv/encrypted-data-vaults/%s/documents/%s",
			e.bddContext.VaultID, encryptedDocuments[i].ID)

		if encryptedDocumentLocations[i] != expectedDocumentLocation {
			return fmt.Errorf("document %d's location was expected to be %s but got %s instead",
				i, expectedDocumentLocation, encryptedDocumentLocations[i])
		}
	}

	return nil
}

func (e *Steps) storeDocumentsInParallel(encryptedDocuments []models.EncryptedDocument) []string {
	encryptedDocumentLocations := make([]string, numDocumentsForParallelTest)

	var waitGroup sync.WaitGroup

	for i := 0; i < numThreadsForParallelTest; i++ {
		i := i

		waitGroup.Add(1)

		store10Documents := func() {
			defer waitGroup.Done()

			firstDocumentIndexToSend := i * numThreadsForParallelTest
			lastDocumentIndexToSend := firstDocumentIndexToSend + (numThreadsForParallelTest - 1)

			println(fmt.Sprintf("Thread %d will store documents %d through %d.",
				i, firstDocumentIndexToSend, lastDocumentIndexToSend))

			for j := firstDocumentIndexToSend; j <= lastDocumentIndexToSend; j++ {
				location, err := e.bddContext.EDVClient.CreateDocument(e.bddContext.VaultID, &encryptedDocuments[j])
				if err != nil {
					println("Failed to create document in EDV: " + err.Error())
				}

				encryptedDocumentLocations[j] = location
			}

			println(fmt.Sprintf("Thread %d has finished storing documents %d through %d.",
				i, firstDocumentIndexToSend, lastDocumentIndexToSend))
		}
		go store10Documents()
	}

	waitGroup.Wait()

	println("All documents done storing.")

	return encryptedDocumentLocations
}

func verifyEncryptedDocsAreEqual(retrievedDocument, expectedDocument *models.EncryptedDocument) error {
	if retrievedDocument.ID != expectedDocument.ID {
		return common.UnexpectedValueError(expectedDocument.ID, retrievedDocument.ID)
	}

	if retrievedDocument.Sequence != expectedDocument.Sequence {
		return common.UnexpectedValueError(fmt.Sprint(expectedDocument.Sequence),
			fmt.Sprint(retrievedDocument.Sequence))
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

func generateEncryptedDocuments(jweEncrypter *jose.JWEEncrypt) ([]models.EncryptedDocument, error) {
	println("Generating encrypted documents.")

	encryptedDocuments := make([]models.EncryptedDocument, numDocumentsForParallelTest)

	for i := 0; i < numDocumentsForParallelTest; i++ {
		docID, err := edvutils.GenerateEDVCompatibleID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate an EDV document ID: %w", err)
		}

		structuredDocument := constructStructuredDocument(docID)

		marshalledStructuredDoc, err := json.Marshal(structuredDocument)
		if err != nil {
			return nil, err
		}

		jwe, err := jweEncrypter.Encrypt(marshalledStructuredDoc)
		if err != nil {
			return nil, err
		}

		encryptedStructuredDoc, err := jwe.FullSerialize(json.Marshal)
		if err != nil {
			return nil, err
		}

		encryptedDoc := models.EncryptedDocument{
			ID:  docID,
			JWE: []byte(encryptedStructuredDoc),
		}

		encryptedDocuments[i] = encryptedDoc
	}

	println("Done generating encrypted documents.")

	return encryptedDocuments, nil
}
