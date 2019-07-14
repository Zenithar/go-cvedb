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

package http

import (
	"context"
	"net/http"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"go.zenithar.org/cvedb/cli/cvedb/internal/config"
	"go.zenithar.org/pkg/log"
)

type application struct {
	cfg    *config.Configuration
	server *http.Server
}

var (
	app  *application
	once sync.Once
)

// -----------------------------------------------------------------------------

// New initialize the application
func New(ctx context.Context, cfg *config.Configuration) (*http.Server, error) {
	var err error

	once.Do(func() {
		// Initialize application
		app = &application{}

		// Apply configuration
		if err := app.ApplyConfiguration(cfg); err != nil {
			log.For(ctx).Fatal("Unable to initialize server settings", zap.Error(err))
		}
	})

	app.server, err = setup(ctx, cfg)
	if err != nil {
		return nil, xerrors.Errorf("grpc: unable to initialize core services : %w", err)
	}

	// Return server
	return app.server, nil
}

// -----------------------------------------------------------------------------

// ApplyConfiguration apply the configuration after checking it
func (s *application) ApplyConfiguration(cfg interface{}) error {
	// Check configuration validity
	if err := s.checkConfiguration(cfg); err != nil {
		return err
	}

	// Apply to current component (type assertion done if check)
	s.cfg, _ = cfg.(*config.Configuration)

	// No error
	return nil
}

// -----------------------------------------------------------------------------

func (s *application) checkConfiguration(cfg interface{}) error {
	// No error
	return nil
}
