/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edvutils

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edv/pkg/restapi/messages"
)

const (
	testBase58encoded128bitString = "Sr7yHjomhn1aeaFnxREfRN"
	testConvertedUUIDString       = "d15034fa-9525-4ebf-3352-d19c8b02cf05"

	not128BitString = "testString"

	validURI   = "did:example:123456789"
	invalidURI = "invalidURI"

	testValidRawJWEWithMultipleRecipients = `{"protected":"eyJlbmMiOiJDMjBQIn0","recipients":[{"header":` +
		`{"alg":"A256KW","kid":"https://example.com/kms/z7BgF536GaR"},"encrypted_key":"OR1vdCNvf_B68mfUxFQVT-vy` +
		`XVrBembuiM40mAAjDC1-Qu5iArDbug"}],"iv":"i8Nins2vTI3PlrYW","ciphertext":"Cb-963UCXblINT8F6MDHzMJN9EAhK3` +
		`I","tag":"pfZO0JulJcrc3trOZy8rjA"}`

	testValidRawJWEFlattenedWithOneRecipient = `{"protected":"eyJlbmMiOiJDMjBQIn0","header":{"alg":"A256KW","kid":` +
		`"https://example.com/kms/z7BgF536GaR"},"encrypted_key":"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJR` +
		`gckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14` +
		`B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8186` +
		`0ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg","iv":"48V1_ALb6US04U` +
		`3b","ciphertext":"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A","` +
		`tag": "XFBoMYUZodetZdvTiFvSkQ"}`

	testValidRawJWEWithHeaderEncodedInProtectedHeader = `{"protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ0` +
		`0ifQ","encrypted_key":"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWS` +
		`rFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76` +
		`FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr` +
		`66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg","iv":"48V1_ALb6US04U3b","ciphertext":"5eym8TW_c8S` +
		`uK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A","tag":"XFBoMYUZodetZdvTiFvSkQ` +
		`"}`

	testRawJWEWithMissingHeaderWithMultipleRecipients = `{"protected":"eyJlbmMiOiJDMjBQIn0","recipients":[{"header":` +
		`{"kid":"https://example.com/kms/z7BgF536GaR"},"encrypted_key":"OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-` +
		`Qu5iArDbug"}],"iv":"i8Nins2vTI3PlrYW","ciphertext":"Cb-963UCXblINT8F6MDHzMJN9EAhK3I","tag":"pfZO0JulJcrc3tr` +
		`OZy8rjA"}`

	testRawJWEWithMissingHeaderAlgFlatten = `{"protected":"eyJlbmMiOiJDMjBQIn0","encrypted_key":"OKOawDo13gRp2ojaHV` +
		`7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImG` +
		`yFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzf` +
		`iwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iG` +
		`dXKHzg","iv":"48V1_ALb6US04U3b","ciphertext":"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7` +
		`j6jiSdiwkIr3ajwQzaBtQD_A","tag":"XFBoMYUZodetZdvTiFvSkQ"}`

	testRawJWEWithBadTypeForUnmarshal = `{"recipients": 0}`
	testRawJWEWithBadProtectedHeaders = `{"protected":"notBase64EncodedString"}`
)

func Test_GenerateEDVCompatibleID(t *testing.T) {
	id, err := GenerateEDVCompatibleID()
	require.NoError(t, err)
	require.NotEmpty(t, id)
}

func Test_generateEDVCompatibleID_Failure(t *testing.T) {
	t.Run("Failure while generating random bytes", func(t *testing.T) {
		id, err := generateEDVCompatibleID(failingGenerateRandomBytesFunc)
		require.EqualError(t, err, errRandomByteGeneration.Error())
		require.Empty(t, id)
	})
}

func TestCheckIfBase58Encoded128BitValue(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		err := CheckIfBase58Encoded128BitValue(testBase58encoded128bitString)
		require.NoError(t, err)
	})
	t.Run("Failure - not base58 encoded", func(t *testing.T) {
		err := CheckIfBase58Encoded128BitValue("")
		require.Equal(t, messages.ErrNotBase58Encoded, err)
	})
	t.Run("Failure - not 128 bit", func(t *testing.T) {
		err := CheckIfBase58Encoded128BitValue(not128BitString)
		require.Equal(t, messages.ErrNot128BitValue, err)
	})
}

func TestBase58Encoded128BitToUUID(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		uuidString, err := Base58Encoded128BitToUUID(testBase58encoded128bitString)
		require.NoError(t, err)
		require.Equal(t, testConvertedUUIDString, uuidString)
	})
}

func TestCheckIfURI(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		err := CheckIfURI(validURI)
		require.NoError(t, err)
	})
	t.Run("Failure - invalid URI", func(t *testing.T) {
		err := CheckIfURI(invalidURI)
		require.NotNil(t, err)
		require.Equal(t, fmt.Sprintf(messages.InvalidURI, invalidURI), err.Error())
	})
}

func TestCheckIfArrayIsURI(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		err := CheckIfArrayIsURI([]string{validURI})
		require.NoError(t, err)
	})
	t.Run("Failure - invalid URI", func(t *testing.T) {
		err := CheckIfArrayIsURI([]string{invalidURI})
		require.NotNil(t, err)
		require.Equal(t, fmt.Sprintf(messages.InvalidURI, invalidURI), err.Error())
	})
}

func TestValidateRawJWE(t *testing.T) {
	t.Run("Success - general JWE JSON serialization syntax with multiple recipients", func(t *testing.T) {
		err := ValidateRawJWE(json.RawMessage(testValidRawJWEWithMultipleRecipients))
		require.NoError(t, err)
	})
	t.Run("Success - flattened JWE JSON serialization syntax with one recipient", func(t *testing.T) {
		err := ValidateRawJWE(json.RawMessage(testValidRawJWEFlattenedWithOneRecipient))
		require.NoError(t, err)
	})
	t.Run("Success - alg encoded in protected headers", func(t *testing.T) {
		err := ValidateRawJWE(json.RawMessage(testValidRawJWEWithHeaderEncodedInProtectedHeader))
		require.NoError(t, err)
	})
	t.Run("Failure - missing alg in header with multiple recipients", func(t *testing.T) {
		err := ValidateRawJWE(json.RawMessage(testRawJWEWithMissingHeaderWithMultipleRecipients))
		require.NotNil(t, err)
		require.Equal(t, messages.BlankJWEAlg, err.Error())
	})
	t.Run("Failure - missing alg in header flattened JWE JSON serialization syntax", func(t *testing.T) {
		err := ValidateRawJWE(json.RawMessage(testRawJWEWithMissingHeaderAlgFlatten))
		require.NotNil(t, err)
		require.Equal(t, messages.BlankJWEAlg, err.Error())
	})
	t.Run("Failure - empty JWE", func(t *testing.T) {
		err := ValidateRawJWE(json.RawMessage(""))
		require.NotNil(t, err)
		require.Equal(t, messages.BlankJWE, err.Error())
	})
	t.Run("Failure - unmarshal JWE error", func(t *testing.T) {
		err := ValidateRawJWE(json.RawMessage(testRawJWEWithBadTypeForUnmarshal))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "json: cannot unmarshal")
	})
	t.Run("Failure - base64 decode protected headers error", func(t *testing.T) {
		err := ValidateRawJWE(json.RawMessage(testRawJWEWithBadProtectedHeaders))
		require.NotNil(t, err)
		require.Equal(t, messages.BadJWEProtectedHeaders, err.Error())
	})
}

var errRandomByteGeneration = errors.New("failingGenerateRandomBytesFunc always fails")

func failingGenerateRandomBytesFunc(_ []byte) (int, error) {
	return -1, errRandomByteGeneration
}
