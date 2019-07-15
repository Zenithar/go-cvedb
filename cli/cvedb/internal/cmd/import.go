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

package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"go.zenithar.org/cvedb/internal/repositories/pkg/mongodb"
	"go.zenithar.org/cvedb/pkg/feeds/nvd"
	mdb "go.zenithar.org/pkg/db/adapter/mongodb"
	"go.zenithar.org/pkg/log"
)

// -----------------------------------------------------------------------------

var (
	nvdYearFeedStart uint64
	nvdModifiedFeed  bool
	nvdRecentFeed    bool
)

var importNvdCmd = &cobra.Command{
	Use:   "import-nvd",
	Short: "Import NVD feed",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		// Open mongo connection
		cfg := &mdb.Configuration{
			AutoMigrate:      false,
			ConnectionString: "mongodb://localhost:27017",
			DatabaseName:     "cvedb",
		}

		client, err := mdb.Connection(ctx, cfg)
		if err != nil {
			log.For(ctx).Fatal("Unable to connect to database", zap.Error(err))
		}

		// Advisory repository
		advisories := mongodb.Advisories(cfg, client)

		// Import NVD feeds
		if err := nvd.Import(ctx, advisories, nvd.ImportOptions{
			Since:    nvdYearFeedStart,
			Modified: nvdModifiedFeed,
			Recent:   nvdRecentFeed,
		}); err != nil {
			log.For(ctx).Fatal("Unable to import advisories", zap.Error(err))
		}
	},
}

func init() {
	importNvdCmd.Flags().Uint64Var(&nvdYearFeedStart, "since", 0, "Import since year til now")
	importNvdCmd.Flags().BoolVar(&nvdModifiedFeed, "modified", false, "Import modified feed")
	importNvdCmd.Flags().BoolVar(&nvdRecentFeed, "recent", false, "Import recent feed")
}
