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

package config

import "go.zenithar.org/pkg/platform"

// Configuration contains kornflake settings
type Configuration struct {
	Debug struct {
		Enable bool `toml:"enable" default:"false" comment:"allow debug mode"`
	} `toml:"Debug" comment:"###############################\n Debug \n##############################"`

	Instrumentation platform.InstrumentationConfig `toml:"Instrumentation" comment:"###############################\n Instrumentation \n##############################"`

	DB struct {
		AutoMigrate bool   `toml:"-" default:"false"`
		Type        string `toml:"type" default:"mongodb" comment:"Database connector to use: mongodb."`
		Hosts       string `toml:"hosts" default:"mongodb://127.0.0.1:27017" comment:"Database hosts (comma separated)"`
		Database    string `toml:"database" default:"cvedb" comment:"Database namespace"`
		Username    string `toml:"username" default:"" comment:"Database connection username"`
		Password    string `toml:"password" default:"" comment:"Database connection password"`
	} `toml:"DB" comment:"###############################\n Database Settings \n##############################"`

	Server struct {
		PaginationKey string `toml:"paginationKey" default:"" comment:"Pagination encryption key for cursor based pagination"`

		GRPC struct {
			Network string `toml:"network" default:"tcp" comment:"Network class used for listen (tcp, tcp4, tcp6, unixsocket)"`
			Listen  string `toml:"listen" default:":5555" comment:"Listen address for gRPC server"`
			UseTLS  bool   `toml:"useTLS" default:"false" comment:"Enable TLS listener"`
			TLS     struct {
				CertificatePath              string `toml:"certificatePath" default:"" comment:"Certificate path"`
				PrivateKeyPath               string `toml:"privateKeyPath" default:"" comment:"Private Key path"`
				CACertificatePath            string `toml:"caCertificatePath" default:"" comment:"CA Certificate Path"`
				ClientAuthenticationRequired bool   `toml:"clientAuthenticationRequired" default:"false" comment:"Force client authentication"`
			} `toml:"TLS" comment:"TLS Socket settings"`
		} `toml:"GRPC" comment:"###############################\n gRPC Settings \n##############################"`
		HTTP struct {
			Network string `toml:"network" default:"tcp" comment:"Network class used for listen (tcp, tcp4, tcp6, unixsocket)"`
			Listen  string `toml:"listen" default:":8080" comment:"Listen address for HTTP server"`
			UseTLS  bool   `toml:"useTLS" default:"false" comment:"Enable TLS listener"`
			TLS     struct {
				CertificatePath              string `toml:"certificatePath" default:"" comment:"Certificate path"`
				PrivateKeyPath               string `toml:"privateKeyPath" default:"" comment:"Private Key path"`
				CACertificatePath            string `toml:"caCertificatePath" default:"" comment:"CA Certificate Path"`
				ClientAuthenticationRequired bool   `toml:"clientAuthenticationRequired" default:"false" comment:"Force client authentication"`
			} `toml:"TLS" comment:"TLS Socket settings"`
		} `toml:"HTTP" comment:"###############################\n HTTP Settings \n##############################"`
	}
}
