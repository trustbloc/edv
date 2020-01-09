/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

type dataVaultConfiguration struct {
	Sequence    int        `json:"sequence"`
	Controller  string     `json:"controller"`
	Invoker     string     `json:"invoker"`
	Delegator   string     `json:"delegator"`
	ReferenceID string     `json:"referenceId"`
	KEK         idTypePair `json:"kek"`
	HMAC        idTypePair `json:"hmac"`
}

type idTypePair struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type structuredDocument struct {
	ID      string                 `json:"id"`
	Meta    map[string]interface{} `json:"meta"`
	Content map[string]interface{} `json:"content"`
}
