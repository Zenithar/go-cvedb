package advisory

import (
	"context"

	"go.zenithar.org/cvedb/internal/repositories"
	v1 "go.zenithar.org/cvedb/internal/services/v1"
	"go.zenithar.org/cvedb/pkg/pagination"
	"go.zenithar.org/pkg/db"

	advisoryv1 "go.zenithar.org/cvedb/pkg/gen/go/cvedb/advisory/v1"
)

type service struct {
	advisories repositories.Advisory
	key        pagination.Key
}

// New returns an advisory service instance.
func New(key pagination.Key, advisories repositories.Advisory) v1.Advisories {
	return &service{
		advisories: advisories,
		key:        key,
	}
}

// -----------------------------------------------------------------------------
type cursor struct {
	Page uint `json:"page"`
}

func (s *service) Search(ctx context.Context, req *advisoryv1.SearchRequest) (res *advisoryv1.SearchResponse, err error) {
	// Check cursor token ------------------------------------------------------
	currentPage := &cursor{
		Page: 0,
	}

	if pagination.Token(req.Cursor) != pagination.FirstPageToken {
		if err := s.key.UnmarshalToken(pagination.Token(req.Cursor), currentPage); err != nil {
			return nil, err
		}
	}

	// -------------------------------------------------------------------------
	res = &advisoryv1.SearchResponse{}

	// Prepare filter
	sortParams := db.SortConverter(req.Sorts)
	pagination := db.NewPaginator(uint(currentPage.Page), uint(req.Limit))
	filter := &repositories.AdvisorySearchFilter{}

	// Do the search
	entities, total, err := s.advisories.Search(ctx, filter, pagination, sortParams)
	if err != nil && err != db.ErrNoResult {
		return res, err
	}

	// Set pagination total for paging calcul
	pagination.SetTotal(uint(total))

	// If no result back to first page
	if err != db.ErrNoResult {
		res.Advisories = FromCollection(entities)
	}

	// Encode cursor
	if pagination.HasNext() {
		nextPage, err := s.key.MarshalToken(&cursor{
			Page: pagination.NextPage(),
		})
		if err != nil {
			return res, err
		}
		res.NextCursor = string(nextPage)
	}
	if pagination.HasPrev() {
		previousPage, err := s.key.MarshalToken(&cursor{
			Page: pagination.PrevPage(),
		})
		if err != nil {
			return res, err
		}
		res.PreviousCursor = string(previousPage)
	}

	return res, nil
}
