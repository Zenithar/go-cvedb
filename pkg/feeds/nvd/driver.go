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

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"

	"go.zenithar.org/cvedb/internal/models"
	"go.zenithar.org/cvedb/internal/repositories"
)

// Import a feed into the database
func Import(ctx context.Context, advisories repositories.Advisory) error {
	// Retrieve feeds

	for y := uint64(2002); y <= uint64(time.Now().Year()); y++ {
		fmt.Printf("Processing %d ...\n", y)

		fmt.Println("Downloading ...")
		// Recent
		data, _, err := Year(y)
		if err != nil {
			return err
		}

		fmt.Println("Import ...")
		// Display progress bar
		bar := pb.Full.Start(len(data.CVEItems))

		for _, item := range data.CVEItems {
			adv, err := toModel(item)
			if err != nil {
				return err
			}

			advisories.Create(ctx, adv)
			bar.Increment()
		}

		bar.Finish()
	}

	return nil
}

// -----------------------------------------------------------------------------

func toModel(item CVEItem) (*models.Advisory, error) {
	// References
	refs := []models.Reference{}
	for _, r := range item.CVE.References.ReferenceData {
		ref := models.Reference{
			Link:   r.URL,
			Source: r.Refsource,
			Name:   r.Name,
			Tags:   r.Tags,
		}
		refs = append(refs, ref)
	}

	// CWEs
	cwes := []string{}
	for _, data := range item.CVE.Problemtype.ProblemtypeData {
		for _, desc := range data.Description {
			cwes = append(cwes, desc.Value)
		}
	}

	// Affects
	affects := []models.Affect{}
	for _, vendor := range item.CVE.Affects.Vendor.VendorData {
		for _, prod := range vendor.Product.ProductData {
			for _, version := range prod.Version.VersionData {
				affects = append(affects, models.Affect{
					Vendor:  vendor.VendorName,
					Product: prod.ProductName,
					Version: version.VersionValue,
				})
			}
		}
	}

	score := 0.0

	// CVSS
	cvss := models.Cvss{}
	if item.Impact.BaseMetricV2 != nil {
		cvss.V2 = &models.CvssV2{
			Score:        item.Impact.BaseMetricV2.CvssV2.BaseScore,
			VectorString: item.Impact.BaseMetricV2.CvssV2.VectorString,
		}
		score = item.Impact.BaseMetricV2.CvssV2.BaseScore
	}
	if item.Impact.BaseMetricV3 != nil {
		cvss.V3 = &models.CvssV3{
			Score:        item.Impact.BaseMetricV3.CvssV3.BaseScore,
			VectorString: item.Impact.BaseMetricV3.CvssV3.VectorString,
		}
	}

	// Description
	descs := map[string]string{}
	for _, desc := range item.CVE.Description.DescriptionData {
		descs[desc.Lang] = desc.Value
	}

	// Dates

	publishedDate, err := time.Parse("2006-01-02T15:04Z", item.PublishedDate)
	if err != nil {
		return nil, err
	}
	lastModifiedDate, err := time.Parse("2006-01-02T15:04Z", item.LastModifiedDate)
	if err != nil {
		return nil, err
	}

	// Return result
	return &models.Advisory{
		ID:               fmt.Sprintf("nvd:%s", strings.ToLower(item.CVE.CVEDataMeta.ID)),
		Cve:              item.CVE.CVEDataMeta.ID,
		Score:            score,
		Description:      descs,
		Cwe:              cwes,
		References:       refs,
		PublishedDate:    publishedDate,
		LastModifiedDate: lastModifiedDate,
		CVSS:             cvss,
		Affects:          affects,
	}, nil
}
