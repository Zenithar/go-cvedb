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

	"go.zenithar.org/cvedb/internal/models"
	"go.zenithar.org/cvedb/internal/repositories"
	"golang.org/x/xerrors"
)

// Import a feed into the database
func Import(ctx context.Context, advisories repositories.Advisory) error {
	// Retrieve feeds

	// Recent
	data, _, err := Recent()
	if err != nil {
		return err
	}

	for _, item := range data.CVEItems {
		adv, err := toAdvisory(item)
		if err != nil {
			return err
		}

		advisories.Create(ctx, adv)
	}

	return nil
}

// -----------------------------------------------------------------------------

func toAdvisory(item CVEItem) (*models.Advisory, error) {
	// Initialize a new advisory instance
	advisory := models.NewAdvisory()

	// Update
	publishedDate, err := time.Parse(time.RFC3339, item.PublishedDate)
	if err != nil {
		return nil, xerrors.Errorf("nvd: unable to parse publishedDate: %w", err)
	}
	advisory.PublishedDate = publishedDate

	lastModifiedDate, err := time.Parse(time.RFC3339, item.LastModifiedDate)
	if err != nil {
		return nil, xerrors.Errorf("nvd: unable to parse lastModifiedDate: %w", err)
	}
	advisory.LastModifiedDate = lastModifiedDate

	// Text
	advisory.Description = item.CVE.Description.DescriptionData[0].Value

	// Score
	if item.Impact.BaseMetricV3 != nil {
		advisory.Score = item.Impact.BaseMetricV3.CvssV3.BaseScore
	}
	if item.Impact.BaseMetricV2 != nil {
		advisory.Score = item.Impact.BaseMetricV2.CvssV2.BaseScore
	}

	// Return result
	return advisory, nil
}
