package advisory

import (
	"context"

	"go.zenithar.org/cvedb/internal/repositories"
	v1 "go.zenithar.org/cvedb/internal/services/v1"
)

type service struct {
	advisories repositories.Advisory
}

// New returns an advisory service instance.
func New(advisories repositories.Advisory) v1.Advisories {
	return &service{
		advisories: advisories,
	}
}

// -----------------------------------------------------------------------------

func (s *service) Search(ctx context.Context) (interface{}, error) {
	return nil, nil
}
