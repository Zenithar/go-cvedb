/*
 * Copyright 2019 Thibault NORMAND
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package badger

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/blevesearch/bleve"
	"github.com/blevesearch/bleve/analysis/analyzer/keyword"
	badger "github.com/dgraph-io/badger"
	"github.com/imdario/mergo"

	"go.zenithar.org/cvedb/internal/models"
	"go.zenithar.org/cvedb/internal/repositories"
	"go.zenithar.org/pkg/db"
)

type badgerAdvisoryRepository struct {
	db    *badger.DB
	index bleve.Index
}

// Advisories returns an advisory management repository instance
func Advisories(db *badger.DB, indexPath string) (repositories.Advisory, error) {

	// Open index
	index, err := bleve.Open(indexPath)
	if err == bleve.Error(1) { // ErrorIndexPathDoesNotExist
		bleve.Config.DefaultKVStore = "leveldb"

		keywordField := bleve.NewTextFieldMapping()
		keywordField.Analyzer = keyword.Name

		// Declare a document type
		advisory := bleve.NewDocumentMapping()
		advisory.AddFieldMappingsAt("@type", keywordField)
		advisory.AddFieldMappingsAt("id", keywordField)
		advisory.AddFieldMappingsAt("severity", keywordField)
		advisory.AddFieldMappingsAt("cve", keywordField)

		// Create a document mapping
		mapping := bleve.NewIndexMapping()
		mapping.TypeField = "@type"
		mapping.AddDocumentMapping(AdvisoryNamespace, advisory)

		// Create an index
		index, err = bleve.New(indexPath, mapping)
		if err != nil {
			return nil, err
		}
	}

	return &badgerAdvisoryRepository{
		db:    db,
		index: index,
	}, nil
}

// -----------------------------------------------------------------------------

func (r *badgerAdvisoryRepository) Create(_ context.Context, entity *models.Advisory) error {
	// Validate entity first
	if err := entity.Validate(); err != nil {
		return err
	}

	// Start transaction
	return r.db.Update(func(txn *badger.Txn) error {
		// Encode payload
		value, err := r.encodeValue(entity)
		if err != nil {
			return err
		}

		// Prepare a badger entry
		entry := badger.NewEntry(r.key(entity.ID), value)

		// Insert in the kv store
		if err := txn.SetEntry(entry); err != nil {
			return err
		}

		// Prepare indexable document
		doc := make(map[string]interface{})
		if err := r.decodeValue(value, &doc); err != nil {
			return err
		}

		// Set document type
		doc["@type"] = AdvisoryNamespace

		// Index document
		return r.index.Index(entity.ID, doc)
	})
}

func (r *badgerAdvisoryRepository) Get(_ context.Context, id string) (*models.Advisory, error) {
	var entity models.Advisory

	// Read only transaction
	if err := r.db.View(func(txn *badger.Txn) error {
		// Retrieve from KV store
		item, err := txn.Get(r.key(id))
		if err == badger.ErrKeyNotFound {
			return db.ErrNoResult
		} else if err != nil {
			return err
		}

		// Decode value
		return item.Value(func(val []byte) error {
			return r.decodeValue(val, &entity)
		})
	}); err != nil {
		return nil, err
	}

	// Return decoded entity
	return &entity, nil
}

func (r *badgerAdvisoryRepository) Update(_ context.Context, entity *models.Advisory) error {
	// Validate entity first
	if err := entity.Validate(); err != nil {
		return err
	}

	// Start transaction
	return r.db.Update(func(txn *badger.Txn) error {
		var saved models.Advisory

		// Retrieve from KV store
		item, err := txn.Get(r.key(entity.ID))
		if err != nil {
			return err
		}

		// Decode value
		if err := item.Value(func(val []byte) error {
			return r.decodeValue(val, &saved)
		}); err != nil {
			return err
		}

		// Merge entities
		if err := mergo.Merge(entity, saved); err != nil {
			return err
		}

		// Encode payload
		value, err := r.encodeValue(entity)
		if err != nil {
			return err
		}

		// Prepare a badger entry
		entry := badger.NewEntry(r.key(entity.ID), value)

		// Insert in the kv store
		if err := txn.SetEntry(entry); err != nil {
			return err
		}

		// Prepare indexable document
		doc := make(map[string]interface{})
		if err := r.decodeValue(value, &doc); err != nil {
			return err
		}

		// Set document type
		doc["@type"] = AdvisoryNamespace

		// Index document
		return r.index.Index(entity.ID, doc)
	})
}

func (r *badgerAdvisoryRepository) Delete(_ context.Context, id string) error {
	// Read Write transaction
	return r.db.Update(func(txn *badger.Txn) error {
		// Delete from KV store
		if err := txn.Delete(r.key(id)); err != nil {
			return err
		}

		// Delete from index
		return r.index.Delete(id)
	})
}

// -----------------------------------------------------------------------------

func (r *badgerAdvisoryRepository) key(id string) []byte {
	return []byte(fmt.Sprintf("%s:%s", AdvisoryNamespace, id))
}

func (r *badgerAdvisoryRepository) encodeValue(payload interface{}) ([]byte, error) {
	return json.Marshal(payload)
}

func (r *badgerAdvisoryRepository) decodeValue(body []byte, result interface{}) error {
	return json.Unmarshal(body, result)
}
