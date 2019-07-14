package advisory

import (
	"go.zenithar.org/cvedb/internal/models"
	advisoryv1 "go.zenithar.org/cvedb/pkg/gen/go/cvedb/advisory/v1"
)

// FromEntity converts entity object to service object
func FromEntity(entity *models.Advisory) *advisoryv1.Advisory {
	return &advisoryv1.Advisory{
		Id:          entity.ID,
		Description: entity.Description,
		Score:       entity.Score,
		Cve:         entity.Cve,
		Cwes:        entity.Cwe,
	}
}

// FromCollection returns a service object collection from entities
func FromCollection(entities []*models.Advisory) []*advisoryv1.Advisory {
	res := make([]*advisoryv1.Advisory, len(entities))

	for i, entity := range entities {
		res[i] = FromEntity(entity)
	}

	return res
}
