//+build wireinject

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
	"crypto/tls"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/google/wire"
	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/plugin/ochttp/propagation/b3"
	"go.opencensus.io/stats/view"
	"go.uber.org/zap"

	"go.zenithar.org/cvedb/cli/cvedb/internal/config"
	"go.zenithar.org/cvedb/cli/cvedb/internal/core"
	handlerv1 "go.zenithar.org/cvedb/cli/cvedb/internal/dispatchers/http/handlers/v1"
	v1 "go.zenithar.org/cvedb/internal/services/v1"
	"go.zenithar.org/pkg/log"
	"go.zenithar.org/pkg/tlsconfig"
)

func httpServer(ctx context.Context, cfg *config.Configuration, advisories v1.Advisories) (*http.Server, error) {
	r := chi.NewRouter()

	// middleware stack
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	// timeout before request cancelation
	r.Use(middleware.Timeout(60 * time.Second))

	// API endpoint
	r.Route("/api/v1", func(r chi.Router) {
		r.Mount("/advisories", ochttp.WithRouteTag(handlerv1.AdvisoryRoutes(advisories), "/api/v1/advisories"))
	})

	// Assign router to server
	server := &http.Server{
		Handler: &ochttp.Handler{
			Handler:     r,
			Propagation: &b3.HTTPFormat{},
		},
	}

	// Enable TLS if requested
	if cfg.Server.HTTP.UseTLS {
		// Client authentication enabled but not required
		clientAuth := tls.VerifyClientCertIfGiven
		if cfg.Server.HTTP.TLS.ClientAuthenticationRequired {
			clientAuth = tls.RequireAndVerifyClientCert
		}

		// Generate TLS configuration
		tlsConfig, err := tlsconfig.Server(tlsconfig.Options{
			KeyFile:    cfg.Server.HTTP.TLS.PrivateKeyPath,
			CertFile:   cfg.Server.HTTP.TLS.CertificatePath,
			CAFile:     cfg.Server.HTTP.TLS.CACertificatePath,
			ClientAuth: clientAuth,
		})
		if err != nil {
			log.For(ctx).Error("Unable to build TLS configuration from settings", zap.Error(err))
			return nil, err
		}

		// Create the TLS credentials
		server.TLSConfig = tlsConfig
	} else {
		log.For(ctx).Info("No transport encryption enabled for HTTP server")
	}

	// Register stat views
	err := view.Register(
		// HTTP
		ochttp.DefaultServerViews...,
	)
	if err != nil {
		log.For(ctx).Fatal("Unable to register stat views", zap.Error(err))
	}

	// Return result
	return server, nil
}

// -----------------------------------------------------------------------------

func setup(ctx context.Context, cfg *config.Configuration) (*http.Server, error) {
	wire.Build(
		core.V1ServiceSet,
		httpServer,
	)
	return &http.Server{}, nil
}
