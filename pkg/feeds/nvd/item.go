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

package nvd

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

// -----------------------------------------------------------------------------

// Impact describes CVSS score
type Impact struct {
	BaseMetricV2 *BaseMetricV2 `json:"baseMetricV2"`
	BaseMetricV3 *BaseMetricV3 `json:"baseMetricV3"`
}

// BaseMetricV2 is used for CVSS v2 metrics
type BaseMetricV2 struct {
	CvssV2              CVSSV2  `json:"cvssV2"`
	Severity            string  `json:"severity"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

// CVSSV2 is the CVSS version 2.0 score component holder
type CVSSV2 struct {
	Version          string  `json:"version"`
	VectorString     string  `json:"vectorString"`
	BaseScore        float64 `json:"baseScore"`
	AccessVector     string  `json:"accessVector"`
	AccessComplexity string  `json:"accessComplexity"`
	Authentication   string  `json:"authentication"`
	ConfImpact       string  `json:"confidentialityImpact"`
	IntegImpact      string  `json:"integrityImpact"`
	AvailImpact      string  `json:"availabilityImpact"`
}

// BaseMetricV3 is used for CVSS v3 metrics
type BaseMetricV3 struct {
	CvssV3              CVSSV3  `json:"cvssV3"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore         float64 `json:"impactScore"`
}

// CVSSV3 is the CVSS version 3.0 score component holder
type CVSSV3 struct {
	Version            string  `json:"version"`
	VectorString       string  `json:"vectorString"`
	BaseScore          float64 `json:"baseScore"`
	AttackVector       string  `json:"attackVector"`
	AttackComplexity   string  `json:"attackComplexity"`
	PrivilegesRequired string  `json:"privilegesRequired"`
	UserInteraction    string  `json:"userInteraction"`
	Scope              string  `json:"scope"`
	ConfImpact         string  `json:"confidentialityImpact"`
	IntegImpact        string  `json:"integrityImpact"`
	AvailImpact        string  `json:"availabilityImpact"`
}

// -----------------------------------------------------------------------------

// CVE details
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

// Affects contains vendor reference to product
type Affects struct {
	Vendor Vendor `json:"vendor"`
}

// Vendor contains product references
type Vendor struct {
	VendorData []VendorData `json:"vendor_data"`
}

// VendorData represents vendor information
type VendorData struct {
	VendorName string  `json:"vendor_name"`
	Product    Product `json:"product"`
}

// Product is a list of product data
type Product struct {
	ProductData []ProductData `json:"product_data"`
}

// ProductData represents product information
type ProductData struct {
	ProductName string  `json:"product_name"`
	Version     Version `json:"version"`
}

// Version is a list of version data
type Version struct {
	VersionData []VersionData `json:"version_data"`
}

// VersionData represents version information
type VersionData struct {
	VersionValue    string `json:"version_value"`
	VersionAffected string `json:"version_affected"`
}

// References is a list of reference
type References struct {
	ReferenceData []ReferenceData `json:"reference_data"`
}

// ReferenceData represents reference information
type ReferenceData struct {
	URL       string   `json:"url"`
	Name      string   `json:"name"`
	Refsource string   `json:"refsource"`
	Tags      []string `json:"tags"`
}

// ProblemType is a list of problem
type ProblemType struct {
	ProblemtypeData []ProblemTypeData `json:"problemtype_data"`
}

// ProblemTypeData describes a problem
type ProblemTypeData struct {
	Description []Description `json:"description"`
}

// CVEDescription is a list of i18n description
type CVEDescription struct {
	DescriptionData []Description `json:"description_data"`
}

// Description represents a loclized description in a given language
type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// DataMeta is the metadata holder
type DataMeta struct {
	ID       string `json:"ID"`
	ASSIGNER string `json:"ASSIGNER"`
}

// Configurations represents the CPE filter expression that match the vulnerability
type Configurations struct {
	CVEDataVersion string `json:"CVE_data_version"`
	Nodes          []Node `json:"nodes"`
}

// Node is an element of a CPE Expression filter
type Node struct {
	Operator string     `json:"operator,omitempty"`
	CpeMatch []CPEMatch `json:"cpe_match,omitempty"`
	Children []Node     `json:"children,omitempty"`
}

// CPEMatch is an edge expression that match a given CPE filter
type CPEMatch struct {
	Vulnerable          bool   `json:"vulnerable"`
	Cpe23URI            string `json:"cpe23Uri"`
	VersionEndExcluding string `json:"versionEndExcluding,omitempty"`
}
