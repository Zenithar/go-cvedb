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

	"github.com/cloudflare/tableflip"
	"github.com/oklog/run"
	"github.com/spf13/cobra"

	"go.zenithar.org/cvedb/cli/cvedb/internal/dispatchers/http"
	"go.zenithar.org/cvedb/internal/version"
	"go.zenithar.org/pkg/log"
	"go.zenithar.org/pkg/platform"
)

// -----------------------------------------------------------------------------

var httpCmd = &cobra.Command{
	Use:   "http",
	Short: "Starts the cvedb HTTP server",
	Run: func(cmd *cobra.Command, args []string) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Initialize config
		initConfig()

		// Starting banner
		log.For(ctx).Info("Starting cvedb HTTP server ...")

		// Start goroutine group
		err := platform.Serve(ctx, &platform.Server{
			Debug:           conf.Debug.Enable,
			Name:            "cvedb-http",
			Version:         version.Version,
			Revision:        version.Revision,
			Instrumentation: conf.Instrumentation,
			Builder: func(upg *tableflip.Upgrader, group *run.Group) {
				ln, err := upg.Fds.Listen(conf.Server.HTTP.Network, conf.Server.HTTP.Listen)
				if err != nil {
					log.For(ctx).Fatal("Unable to start HTTP server", log.Error(err))
				}

				server, err := http.New(ctx, conf)
				if err != nil {
					log.For(ctx).Fatal("Unable to start HTTP server", log.Error(err))
				}

				group.Add(
					func() error {
						log.For(ctx).Info("Starting HTTP server", log.String("address", ln.Addr().String()))
						return server.Serve(ln)
					},
					func(e error) {
						log.For(ctx).Info("Shutting HTTP server down")
						log.SafeClose(server, "Unable to close HTTP server")
					},
				)
			},
		})
		log.CheckErrCtx(ctx, "Unable to run application", err)
	},
}
