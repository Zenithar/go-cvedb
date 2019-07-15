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

package repositories

import (
	"context"

	"go.zenithar.org/cvedb/internal/models"
	"go.zenithar.org/pkg/db"
)

// AdvisoryAdmin is the contract for advisory management.
type AdvisoryAdmin interface {
	Synchronize(ctx context.Context, entity *models.Advisory) error
}

// AdvisorySearchFilter is used to create search criteria for Advisory list.
type AdvisorySearchFilter struct {
	Affects []*models.Affect
}

// AdvisorySearch is the contract for advisory search and consultation.
type AdvisorySearch interface {
	Search(ctx context.Context, filter *AdvisorySearchFilter, pagination *db.Pagination, sortParams *db.SortParameters) ([]*models.Advisory, uint, error)
}

// Advisory describves advisory management contract
type Advisory interface {
	AdvisoryAdmin
	AdvisorySearch
}
