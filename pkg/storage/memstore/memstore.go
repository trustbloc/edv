/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memstore

import (
	"github.com/trustbloc/edv/pkg/storage"
)

// Provider represents an MemStore implementation of the storage.Provider interface
type Provider struct {
	dbs map[string]*MemStore
}

// NewProvider instantiates Provider
func NewProvider() *Provider {
	return &Provider{dbs: make(map[string]*MemStore)}
}

// OpenStore opens and returns a store for the given name.
func (p *Provider) OpenStore(name string) (storage.Store, error) {
	store, exists := p.dbs[name]
	if !exists {
		return p.newMemStore(name), nil
	}

	return store, nil
}

func (p *Provider) newMemStore(name string) *MemStore {
	store := MemStore{db: make(map[string][]byte)}

	p.dbs[name] = &store

	return &store
}

// CloseStore closes a previously opened store.
func (p *Provider) CloseStore(name string) error {
	store, exists := p.dbs[name]
	if !exists {
		return storage.ErrStoreNotFound
	}

	delete(p.dbs, name)

	store.close()

	return nil
}

// Close closes the provider.
func (p *Provider) Close() error {
	for _, memStore := range p.dbs {
		memStore.db = make(map[string][]byte)
	}

	p.dbs = make(map[string]*MemStore)

	return nil
}

// MemStore is a simple DB that's stored in memory. Useful for demos or testing. Not designed to be performant.
type MemStore struct {
	db map[string][]byte
}

// Put stores the given key-value pair in the store.
func (store *MemStore) Put(k string, v []byte) error {
	store.db[k] = v

	return nil
}

// Get retrieves the value in the store associated with the given key.
func (store *MemStore) Get(k string) ([]byte, error) {
	v, exists := store.db[k]
	if !exists {
		return nil, storage.ErrValueNotFound
	}

	return v, nil
}

func (store *MemStore) close() {
	store.db = make(map[string][]byte)
}
