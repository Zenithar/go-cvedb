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
	db "go.zenithar.org/pkg/db/adapter/mongodb"

	"go.zenithar.org/cvedb/internal/models"
	"go.zenithar.org/cvedb/internal/repositories"
)

type mgoAdvisoryRepository struct {
	adapter *db.Default
}

// Advisories returns an advisory management repository instance
func Advisories(cfg *db.Configuration, session *mongowrapper.WrappedClient) repositories.Advisory {
	return &mgoAdvisoryRepository{
		adapter: db.NewCRUDTable(session, cfg.DatabaseName, AdvisoryTableName),
	}
}

// -----------------------------------------------------------------------------

func (r *mgoAdvisoryRepository) Create(ctx context.Context, entity *models.Advisory) error {
	// Validate entity first
	if err := entity.Validate(); err != nil {
		return err
	}

	return r.adapter.Insert(ctx, entity)
}

func (r *mgoAdvisoryRepository) Get(ctx context.Context, id string) (*models.Advisory, error) {
	var entity models.Advisory

	if err := r.adapter.WhereAndFetchOne(ctx, map[string]interface{}{
		"_id": id,
	}, &entity); err != nil {
		return nil, err
	}

	return &entity, nil
}

func (r *mgoAdvisoryRepository) Update(ctx context.Context, entity *models.Advisory) error {
	// Validate entity first
	if err := entity.Validate(); err != nil {
		return err
	}

	return r.adapter.Update(ctx, map[string]interface{}{
		"description": entity.Description,
		"score":       entity.Score,
		"severity":    entity.Severity,
	}, map[string]interface{}{
		"_id": entity.ID,
	})
}
