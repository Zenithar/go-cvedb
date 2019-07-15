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

package mongodb

import (
	"context"

	mongowrapper "github.com/opencensus-integrations/gomongowrapper"
	"go.mongodb.org/mongo-driver/bson"
	mongodb "go.zenithar.org/pkg/db/adapter/mongodb"

	"go.zenithar.org/cvedb/internal/models"
	"go.zenithar.org/cvedb/internal/repositories"
	"go.zenithar.org/pkg/db"
)

type mgoAdvisoryRepository struct {
	adapter *mongodb.Default
}

// Advisories returns an advisory management repository instance
func Advisories(cfg *mongodb.Configuration, session *mongowrapper.WrappedClient) repositories.Advisory {
	return &mgoAdvisoryRepository{
		adapter: mongodb.NewCRUDTable(session, cfg.DatabaseName, AdvisoryTableName),
	}
}

// -----------------------------------------------------------------------------

func (r *mgoAdvisoryRepository) Synchronize(ctx context.Context, entity *models.Advisory) error {
	// Validate entity first
	if err := entity.Validate(); err != nil {
		return err
	}

	return r.adapter.InsertOrUpdate(ctx, bson.M{
		"cve": entity.Cve,
	}, entity)
}

func (r *mgoAdvisoryRepository) Search(ctx context.Context, filter *repositories.AdvisorySearchFilter, pagination *db.Pagination, sortParams *db.SortParameters) ([]*models.Advisory, uint, error) {
	var results []*models.Advisory

	filterMap := bson.M{}

	// Parse filter
	if len(filter.Affects) > 0 {
		orFilter := bson.A{}
		for _, aff := range filter.Affects {
			orFilter = append(orFilter, bsonAffect(aff))
		}
		filterMap["$or"] = orFilter
	}

	// Run the query
	total, err := r.adapter.Search(ctx, filterMap, sortParams, pagination, &results)
	if err != nil {
		return nil, 0, err
	}
	if len(results) == 0 {
		return results, 0, db.ErrNoResult
	}

	return results, uint(total), nil
}

// -----------------------------------------------------------------------------

func bsonAffect(aff *models.Affect) bson.M {
	q := bson.M{}

	if aff.Vendor != "" && aff.Vendor != "*" {
		q["affects.vendor"] = aff.Vendor
	}
	if aff.Product != "" && aff.Product != "*" {
		q["affects.product"] = aff.Product
	}
	if aff.Version != "" && aff.Version != "*" {
		q["affects.version"] = aff.Version
	}

	return q
}
