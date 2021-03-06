// Copyright (c) 2018, Google, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package auth

import (
	"github.com/estebangarcia/spin/config/auth/basic"
	gsa "github.com/estebangarcia/spin/config/auth/googleserviceaccount"
	config "github.com/estebangarcia/spin/config/auth/iap"
	"github.com/estebangarcia/spin/config/auth/ldap"
	"github.com/estebangarcia/spin/config/auth/oauth2"
	"github.com/estebangarcia/spin/config/auth/x509"
)

type AuthMethod string

const (
	X509   AuthMethod = "x509"
	OAuth2 AuthMethod = "oauth2"
	Basic  AuthMethod = "basic"
	Iap    AuthMethod = "iap"
	Ldap   AuthMethod = "ldap"
	Google AuthMethod = "google"
)

// AuthConfig is the CLI's authentication configuration.
type AuthConfig struct {
	Enabled bool                 `yaml:"enabled"`
	Method  AuthMethod           `yaml:"method"`
	X509    *x509.X509Config     `yaml:"x509,omitempty"`
	OAuth2  *oauth2.OAuth2Config `yaml:"oauth2,omitempty"`
	Basic   *basic.BasicConfig   `yaml:"basic,omitempty"`
	Iap     *config.IapConfig    `yaml:"iap,omitempty"`
	Ldap    *ldap.LdapConfig     `yaml:"ldap,omitempty`

	GoogleServiceAccount *gsa.GoogleServiceAccountConfig `yaml:"google_service_account,omitempty"`
}
