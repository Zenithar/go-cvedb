package models

import "github.com/dchest/uniuri"

// Advisory is the advisory information holder
type Advisory struct {
	ID string `json:"id" bson:"_id"`

	Description string  `json:"description" bson:"description"`
	Score       float64 `json:"score" bson:"score"`
	Severity    string  `json:"severity" bson:"severity"`

	CVE *CVEDetails `json:"cve" bson:"cve"`
}

// NewAdvisory returns a advisory model
func NewAdvisory() *Advisory {
	return &Advisory{
		ID: uniuri.NewLen(32),
	}
}

// -----------------------------------------------------------------------------
