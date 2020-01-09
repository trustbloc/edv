/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package storage

import "errors"

// ErrStoreNotFound is used when a given store was not found in a provider.
var ErrStoreNotFound = errors.New("store not found")

// ErrValueNotFound is used when an attempt is made to retrieve a value from key
var ErrValueNotFound = errors.New("store does not have a value associated with this key")

// Provider represents a storage provider.
type Provider interface {
	// OpenStore opens a store with the given name and returns it.
	OpenStore(name string) (Store, error)

	// CloseStore closes the store with the given name.
	CloseStore(name string) error

	// Close closes all stores created under this store provider.
	Close() error
}

// Store represents a storage database.
type Store interface {
	// Put stores the key-record pair.
	Put(k string, v []byte) error

	// Get fetches the record associated with the given key.
	Get(k string) ([]byte, error)
}
