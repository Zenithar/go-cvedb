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

package v1

import (
	"net/http"

	"github.com/go-chi/chi"
	"go.uber.org/zap"

	v1 "go.zenithar.org/cvedb/internal/services/v1"
	advisoryv1 "go.zenithar.org/cvedb/pkg/gen/go/cvedb/advisory/v1"

	"go.zenithar.org/pkg/log"
	"go.zenithar.org/pkg/web/request"
	"go.zenithar.org/pkg/web/respond"
)

type advisoryCtrl struct {
	advisories v1.Advisories
}

// -----------------------------------------------------------------------------

// AdvisoryRoutes returns identifier generator related API
func AdvisoryRoutes(advisories v1.Advisories) http.Handler {
	r := chi.NewRouter()

	// Initialize controller
	ctrl := &advisoryCtrl{
		advisories: advisories,
	}

	// Map routes
	r.Post("/", ctrl.search())

	// Return router
	return r
}

// -----------------------------------------------------------------------------

func (c *advisoryCtrl) search() http.HandlerFunc {
	// Handler
	return func(w http.ResponseWriter, r *http.Request) {
		// Request type
		var req advisoryv1.SearchRequest

		// Prepare context
		ctx := r.Context()

		// Decode request
		if err := request.Parse(r, &req); err != nil {
			respond.WithError(w, r, http.StatusBadRequest, err)
			return
		}

		// Do the call
		res, err := c.advisories.Search(ctx, &req)
		if err != nil {
			log.For(ctx).Error("Unable to query database", zap.Error(err))
			respond.WithError(w, r, http.StatusInternalServerError, "Unable to query advisory database")
			return
		}

		// Marshal response
		respond.With(w, r, http.StatusOK, &CollectionResponse{
			Resource: &respond.Resource{
				Context: "https://go.zenithar.org/cvedb",
				Type:    "Collection",
				ID:      r.URL.RequestURI(),
			},
			Members: res.Advisories,
		})
	}
}
