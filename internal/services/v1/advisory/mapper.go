package advisory

import (
	"github.com/gogo/protobuf/types"
	"go.zenithar.org/cvedb/internal/models"
	advisoryv1 "go.zenithar.org/cvedb/pkg/gen/go/cvedb/advisory/v1"
)

// FromEntity converts entity object to service object
func FromEntity(entity *models.Advisory) *advisoryv1.Advisory {
	dto := &advisoryv1.Advisory{
		Cve:         entity.Cve,
		Description: entity.Description,
		Score:       entity.Score,
		Cwes:        entity.Cwe,
	}

	var err error

	// Date
	dto.LastModifiedTime, err = types.TimestampProto(entity.LastModifiedDate)
	if err != nil {
		panic(err)
	}
	dto.PublishedTime, err = types.TimestampProto(entity.PublishedDate)
	if err != nil {
		panic(err)
	}

	// CVSS
	dto.Cvss = &advisoryv1.CVSS{}
	if entity.CVSS.V2 != nil {
		dto.Cvss.V2 = &advisoryv1.CVSSComponent{
			Version: "2",
			Vector:  entity.CVSS.V2.VectorString,
			Score:   entity.CVSS.V2.Score,
		}
	}
	if entity.CVSS.V3 != nil {
		dto.Cvss.V3 = &advisoryv1.CVSSComponent{
			Version: "3",
			Vector:  entity.CVSS.V3.VectorString,
			Score:   entity.CVSS.V3.Score,
		}
	}

	// References
	dto.Refs = []*advisoryv1.Reference{}
	for _, r := range entity.References {
		dto.Refs = append(dto.Refs, &advisoryv1.Reference{
			Link:   r.Link,
			Source: r.Source,
			Name:   r.Name,
			Tags:   r.Tags,
		})
	}

	// Affects
	dto.Affects = []*advisoryv1.Affect{}
	for _, r := range entity.Affects {
		dto.Affects = append(dto.Affects, &advisoryv1.Affect{
			Vendor:  r.Vendor,
			Product: r.Product,
			Version: r.Version,
		})
	}

	return dto
}

// FromCollection returns a service object collection from entities
func FromCollection(entities []*models.Advisory) []*advisoryv1.Advisory {
	res := make([]*advisoryv1.Advisory, len(entities))

	for i, entity := range entities {
		res[i] = FromEntity(entity)
	}

	return res
}
