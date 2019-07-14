package v1

import (
	"net/http"

	"github.com/go-chi/chi"

	v1 "go.zenithar.org/cvedb/internal/services/v1"
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
		// Prepare context
		ctx := r.Context()

		res, err := c.advisories.Search(ctx)
		if err != nil {
			respond.WithError(w, r, http.StatusInternalServerError, "Unable to generate identifier")
			return
		}

		// Marshal response
		respond.With(w, r, http.StatusOK, res)
	}
}
