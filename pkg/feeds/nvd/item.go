package nvd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// Data represents root item
type Data struct {
	CVEDataType         string    `json:"CVE_data_type"`
	CVEDataFormat       string    `json:"CVE_data_format"`
	CVEDataVersion      string    `json:"CVE_data_version"`
	CVEDataNumberOfCVEs string    `json:"CVE_data_numberOfCVEs"`
	CVEDataTimestamp    string    `json:"CVE_data_timestamp"`
	CVEItems            []CVEItem `json:"CVE_Items"`
}

// CVEItem is a CVE item of Root
type CVEItem struct {
	CVE              CVE            `json:"cve"`
	Configurations   Configurations `json:"configurations"`
	Impact           Impact         `json:"impact"`
	PublishedDate    string         `json:"publishedDate"`
	LastModifiedDate string         `json:"lastModifiedDate"`
}

// Hash of the item.
func (cve CVEItem) Hash() (string, error) {
	b, err := json.Marshal(cve)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%02x", sha256.Sum256(b)), nil
}

// -----------------------------------------------------------------------------

// Impact describes CVSS score
type Impact struct {
	BaseMetricV2 BaseMetricV2 `json:"baseMetricV2"`
	BaseMetricV3 BaseMetricV3 `json:"baseMetricV3"`
}

// BaseMetricV2 is used for CVSS v2 metrics
type BaseMetricV2 struct {
	CvssV2                  CVSSV2  `json:"cvssV2"`
	Severity                string  `json:"severity"`
	ExploitabilityScore     float64 `json:"exploitabilityScore"`
	ImpactScore             float64 `json:"impactScore"`
	ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
	ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool    `json:"userInteractionRequired"`
}

// CVSSV2 is the CVSS version 2.0 score component holder
type CVSSV2 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
}

// BaseMetricV3 is used for CVSS v3 metrics
type BaseMetricV3 struct {
	CvssV3              CVSSV3  `json:"cvssV3"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

// CVSSV3 is the CVSS version 3.0 score component holder
type CVSSV3 struct {
	Version      string `json:"version"`
	VectorString string `json:"vectorString"`
}

// -----------------------------------------------------------------------------

type CVE struct {
	DataType    string         `json:"data_type"`
	DataFormat  string         `json:"data_format"`
	DataVersion string         `json:"data_version"`
	CVEDataMeta DataMeta       `json:"CVE_data_meta"`
	Affects     Affects        `json:"affects"`
	Problemtype ProblemType    `json:"problemtype"`
	References  References     `json:"references"`
	Description CVEDescription `json:"description"`
}

type Affects struct {
	Vendor Vendor `json:"vendor"`
}

type Vendor struct {
	VendorData []VendorData `json:"vendor_data"`
}

type VendorData struct {
	VendorName string  `json:"vendor_name"`
	Product    Product `json:"product"`
}

type Product struct {
	ProductData []ProductData `json:"product_data"`
}

type ProductData struct {
	ProductName string  `json:"product_name"`
	Version     Version `json:"version"`
}

type Version struct {
	VersionData []VersionData `json:"version_data"`
}

type VersionData struct {
	VersionValue    string `json:"version_value"`
	VersionAffected string `json:"version_affected"`
}

type References struct {
	ReferenceData []ReferenceData `json:"reference_data"`
}

type ReferenceData struct {
	URL       string   `json:"url"`
	Name      string   `json:"name"`
	Refsource string   `json:"refsource"`
	Tags      []string `json:"tags"`
}

type ProblemType struct {
	ProblemtypeData []ProblemTypeData `json:"problemtype_data"`
}

type ProblemTypeData struct {
	Description []Description `json:"description"`
}

type CVEDescription struct {
	DescriptionData []Description `json:"description_data"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type DataMeta struct {
	ID       string `json:"ID"`
	ASSIGNER string `json:"ASSIGNER"`
}

type Configurations struct {
	CVEDataVersion string `json:"CVE_data_version"`
	Nodes          []Node `json:"nodes"`
}

type Node struct {
	Operator string     `json:"operator"`
	CpeMatch []CPEMatch `json:"cpe_match"`
}

type CPEMatch struct {
	Vulnerable          bool   `json:"vulnerable"`
	Cpe23URI            string `json:"cpe23Uri"`
	VersionEndExcluding string `json:"versionEndExcluding,omitempty"`
}
