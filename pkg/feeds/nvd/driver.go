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
	"time"

	"github.com/cheggaaa/pb/v3"

	"go.zenithar.org/cvedb/internal/models"
	"go.zenithar.org/cvedb/internal/repositories"
	"go.zenithar.org/pkg/log"
)

// ImportOptions defines import strategy
type ImportOptions struct {
	Since    uint64
	Modified bool
	Recent   bool
}

// Import a feed into the database
func Import(ctx context.Context, advisories repositories.Advisory, opts ImportOptions) error {
	// Retrieve feeds
	var err error

	if opts.Since >= 2002 {
		log.For(ctx).Info("Processing all year feed")

		err = importYear(ctx, advisories, opts.Since)
		if err != nil {
			return err
		}
	}
	if opts.Modified {
		log.For(ctx).Info("Processing modified cve")

		err = importModified(ctx, advisories)
		if err != nil {
			return err
		}
	}
	if opts.Recent {
		log.For(ctx).Info("Processing recent cve")

		err = importRecent(ctx, advisories)
		if err != nil {
			return err
		}
	}

	return nil
}

func importRecent(ctx context.Context, advisories repositories.Advisory) error {
	data, _, err := Recent()
	if err != nil {
		return err
	}

	log.For(ctx).Info("Recent advisories to synchronize")

	return synchronize(ctx, advisories, data)
}

func importModified(ctx context.Context, advisories repositories.Advisory) error {
	data, _, err := Modified()
	if err != nil {
		return err
	}

	log.For(ctx).Info("Modified advisories to synchronize")

	return synchronize(ctx, advisories, data)
}

func importYear(ctx context.Context, advisories repositories.Advisory, start uint64) error {
	for y := uint64(start); y <= uint64(time.Now().Year()); y++ {
		data, _, err := Year(y)
		if err != nil {
			return err
		}

		log.For(ctx).Info("Year feed to synchronize")

		if err := synchronize(ctx, advisories, data); err != nil {
			return err
		}
	}

	return nil
}

func synchronize(ctx context.Context, advisories repositories.Advisory, data Data) error {
	// Display progress bar
	bar := pb.Full.Start(len(data.CVEItems))

	for _, item := range data.CVEItems {
		adv, err := toModel(item)
		if err != nil {
			return err
		}

		if err := advisories.Synchronize(ctx, adv); err != nil {
			log.For(ctx).Error("Unable to synchronize advisory", log.Error(err), log.String("id", adv.Cve))
			return err
		}

		bar.Increment()
	}

	bar.Finish()

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
