// Copyright (c) 2018, Google, Inc.
// Copyright (c) 2019, Noel Cower.
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

package gateclient

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	_ "net/http/pprof"
	"net/url"
	"os"
	"strings"

	"github.com/spinnaker/spin/config"
	"github.com/spinnaker/spin/config/auth"
	iap "github.com/spinnaker/spin/config/auth/iap"
	"github.com/spinnaker/spin/util"
	"github.com/spinnaker/spin/version"

	"github.com/mitchellh/go-homedir"
	"gopkg.in/yaml.v2"

	"crypto/sha256"
	"encoding/base64"

	gate "github.com/spinnaker/spin/gateapi"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	// defaultConfigFileMode is the default file mode used for config files. This corresponds to
	// the Unix file permissions u=rw,g=,o= so that config files with cached tokens, at least by
	// default, are only readable by the user that owns the config file.
	defaultConfigFileMode os.FileMode = 0600 // u=rw,g=,o=
)

// GatewayClient is the wrapper with authentication
type GatewayClient struct {
	// The exported fields below should be set by anyone using a command
	// with an GatewayClient field. These are expected to be set externally
	// (not from within the command itself).

	// Generate Gate Api client.
	*gate.APIClient

	// Spin CLI configuration.
	Config config.Config

	// Context for OAuth2 access token.
	Context context.Context

	// This is the set of flags global to the command parser.
	gateEndpoint string

	ignoreCertErrors bool

	// Location of the spin config.
	configLocation string

	// Raw Http Client to do OAuth2 login.
	httpClient *http.Client
}

func (m *GatewayClient) GateEndpoint() string {
	if m.Config.Gate.Endpoint == "" && m.gateEndpoint == "" {
		return "http://localhost:8084"
	}
	if m.gateEndpoint != "" {
		return m.gateEndpoint
	}
	return m.Config.Gate.Endpoint
}

func (m *GatewayClient) determineAuthMethod() {
	authConfig := m.Config.Auth
	if authConfig.Method != "" || !authConfig.Enabled {
		return
	}

	if authConfig.X509.IsValid() {
		authConfig.Method = auth.X509
	} else if authConfig.OAuth2.IsValid() {
		authConfig.Method = auth.OAuth2
	} else if authConfig.Ldap.IsValid() {
		authConfig.Method = auth.Ldap
	} else if authConfig.Basic.IsValid() {
		authConfig.Method = auth.Basic
	} else if authConfig.Iap.IsValid() {
		authConfig.Method = auth.Iap
	} else {
		authConfig.Method = auth.Google
	}

}

// NewGateClientWithConfig - Create new GateClient using provided config
func NewGateClientWithConfig(config config.Config) (*GatewayClient, error) {

	if util.UI == nil {
		util.InitUI(false, true, "")
	}

	gateClient, err := createClient(config)
	if err != nil {
		return nil, err
	}

	gateClient.determineAuthMethod()

	// Api client initialization.
	httpClient, err := gateClient.initializeClient()
	if err != nil {
		util.UI.Error("Could not initialize http client, failing.")
		return nil, err
	}

	gateClient.httpClient = httpClient

	err = gateClient.authenticateOAuth2()
	if err != nil {
		util.UI.Error("OAuth2 Authentication failed.")
		return nil, err
	}

	err = gateClient.authenticateGoogleServiceAccount()
	if err != nil {
		util.UI.Error(fmt.Sprintf("Google service account authentication failed: %v", err))
		return nil, err
	}

	if err = gateClient.authenticateLdap(); err != nil {
		util.UI.Error("LDAP Authentication Failed")
		return nil, err
	}

	m := make(map[string]string)

	if config.Gate.DefaultHeaders != "" {
		headers := strings.Split(config.Gate.DefaultHeaders, ",")
		for _, element := range headers {
			header := strings.Split(element, "=")
			m[strings.TrimSpace(header[0])] = strings.TrimSpace(header[1])
		}
	}

	cfg := &gate.Configuration{
		BasePath:      gateClient.GateEndpoint(),
		DefaultHeader: m,
		UserAgent:     fmt.Sprintf("%s/%s", version.UserAgent, version.String()),
		HTTPClient:    httpClient,
	}
	gateClient.APIClient = gate.NewAPIClient(cfg)

	// TODO: Verify version compatibility between Spin CLI and Gate.
	_, _, err = gateClient.VersionControllerApi.GetVersionUsingGET(gateClient.Context)
	if err != nil {
		util.UI.Error("Could not reach Gate, please ensure it is running. Failing.")
		return nil, err
	}

	return gateClient, nil
}

// NewGateClient - Create new spinnaker gateway client get config from viper
func NewGateClient() (*GatewayClient, error) {
	config, err := config.Parse()
	if err != nil {
		return nil, err
	}

	return NewGateClientWithConfig(config)
}

func createClient(config config.Config) (*GatewayClient, error) {
	return &GatewayClient{
		Config:           config,
		gateEndpoint:     config.Gate.Endpoint,
		ignoreCertErrors: config.Gate.Insecure,
		configLocation:   config.Location,
	}, nil
}

func (m *GatewayClient) initializeClient() (*http.Client, error) {
	authConfig := m.Config.Auth
	cookieJar, _ := cookiejar.New(nil)
	client := http.Client{
		Jar: cookieJar,
	}

	if m.ignoreCertErrors {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if authConfig != nil && authConfig.Enabled && authConfig.X509 != nil && authConfig.Method == auth.X509 {
		X509 := authConfig.X509
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{},
		}

		if !X509.IsValid() {
			// Misconfigured.
			return nil, errors.New("Incorrect x509 auth configuration.\nMust specify certPath/keyPath or cert/key pair.")
		}

		if X509.CertPath != "" && X509.KeyPath != "" {
			certPath, err := homedir.Expand(X509.CertPath)
			if err != nil {
				return nil, err
			}
			keyPath, err := homedir.Expand(X509.KeyPath)
			if err != nil {
				return nil, err
			}

			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return nil, err
			}

			clientCA, err := ioutil.ReadFile(certPath)
			if err != nil {
				return nil, err
			}

			return m.initializeX509Config(client, clientCA, cert), nil
		} else if X509.Cert != "" && X509.Key != "" && authConfig.Method == auth.X509 {
			certBytes := []byte(X509.Cert)
			keyBytes := []byte(X509.Key)
			cert, err := tls.X509KeyPair(certBytes, keyBytes)
			if err != nil {
				return nil, err
			}

			return m.initializeX509Config(client, certBytes, cert), nil
		} else {
			// Misconfigured.
			return nil, errors.New("Incorrect x509 auth configuration.\nMust specify certPath/keyPath or cert/key pair.")
		}
	} else if authConfig != nil && authConfig.Enabled && authConfig.Iap != nil && authConfig.Method == auth.Iap {
		accessToken, err := m.authenticateIAP()
		m.Context = context.WithValue(context.Background(), gate.ContextAccessToken, accessToken)
		return &client, err
	} else if authConfig != nil && authConfig.Enabled && authConfig.Basic != nil && authConfig.Method == auth.Basic {
		if !authConfig.Basic.IsValid() {
			return nil, errors.New("Incorrect Basic auth configuration. Must include username and password.")
		}
		m.Context = context.WithValue(context.Background(), gate.ContextBasicAuth, gate.BasicAuth{
			UserName: authConfig.Basic.Username,
			Password: authConfig.Basic.Password,
		})
		return &client, nil
	} else {
		return &client, nil
	}
}

func (m *GatewayClient) initializeX509Config(client http.Client, clientCA []byte, cert tls.Certificate) *http.Client {
	clientCertPool := x509.NewCertPool()
	clientCertPool.AppendCertsFromPEM(clientCA)

	client.Transport.(*http.Transport).TLSClientConfig.MinVersion = tls.VersionTLS12
	client.Transport.(*http.Transport).TLSClientConfig.PreferServerCipherSuites = true
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{cert}
	if m.ignoreCertErrors {
		client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
	}
	return &client
}

func (m *GatewayClient) authenticateOAuth2() error {
	authConfig := m.Config.Auth
	if authConfig != nil && authConfig.Enabled && authConfig.OAuth2 != nil && authConfig.Method == auth.OAuth2 {
		OAuth2 := authConfig.OAuth2
		if !OAuth2.IsValid() {
			// TODO(jacobkiefer): Improve this error message.
			return errors.New("incorrect OAuth2 auth configuration")
		}

		config := &oauth2.Config{
			ClientID:     OAuth2.ClientId,
			ClientSecret: OAuth2.ClientSecret,
			RedirectURL:  "http://localhost:8085",
			Scopes:       OAuth2.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  OAuth2.AuthUrl,
				TokenURL: OAuth2.TokenUrl,
			},
		}
		var newToken *oauth2.Token
		var err error

		if authConfig.OAuth2.CachedToken != nil {
			// Look up cached credentials to save oauth2 roundtrip.
			token := authConfig.OAuth2.CachedToken
			tokenSource := config.TokenSource(context.Background(), token)
			newToken, err = tokenSource.Token()
			if err != nil {
				util.UI.Error(fmt.Sprintf("Could not refresh token from source: %v", tokenSource))
				return err
			}
		} else {
			// Do roundtrip.
			http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				code := r.FormValue("code")
				fmt.Fprintln(w, code)
			}))
			go http.ListenAndServe(":8085", nil)
			// Note: leaving server connection open for scope of request, will be reaped on exit.

			verifier, verifierCode, err := generateCodeVerifier()
			if err != nil {
				return err
			}

			codeVerifier := oauth2.SetAuthURLParam("code_verifier", verifier)
			codeChallenge := oauth2.SetAuthURLParam("code_challenge", verifierCode)
			challengeMethod := oauth2.SetAuthURLParam("code_challenge_method", "S256")

			authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline, oauth2.ApprovalForce, challengeMethod, codeChallenge)
			util.UI.Output(fmt.Sprintf("Navigate to %s and authenticate", authURL))
			code := prompt()

			newToken, err = config.Exchange(context.Background(), code, codeVerifier)
			if err != nil {
				return err
			}
		}

		util.UI.Info("Caching oauth2 token.")
		OAuth2.CachedToken = newToken
		_ = m.writeYAMLConfig()

		m.login(newToken.AccessToken)
		m.Context = context.Background()
	}
	return nil
}

func (m *GatewayClient) authenticateIAP() (string, error) {
	authConfig := m.Config.Auth
	iapConfig := authConfig.Iap
	token, err := iap.GetIapToken(*iapConfig)
	return token, err
}

func (m *GatewayClient) authenticateGoogleServiceAccount() (err error) {
	authConfig := m.Config.Auth
	if authConfig == nil || authConfig.Method != auth.Google {
		return nil
	}

	gsa := authConfig.GoogleServiceAccount
	if !gsa.IsEnabled() {
		return nil
	}

	if gsa.CachedToken != nil && gsa.CachedToken.Valid() {
		return m.login(gsa.CachedToken.AccessToken)
	}
	gsa.CachedToken = nil

	var source oauth2.TokenSource
	if gsa.File == "" {
		source, err = google.DefaultTokenSource(context.Background(), "profile", "email")
	} else {
		serviceAccountJSON, ferr := ioutil.ReadFile(gsa.File)
		if ferr != nil {
			return ferr
		}
		source, err = google.JWTAccessTokenSourceFromJSON(serviceAccountJSON, "https://accounts.google.com/o/oauth2/v2/auth")
	}
	if err != nil {
		return err
	}

	token, err := source.Token()
	if err != nil {
		return err
	}

	if err := m.login(token.AccessToken); err != nil {
		return err
	}

	gsa.CachedToken = token
	m.Context = context.Background()

	// Cache token if login succeeded
	gsa.CachedToken = token
	_ = m.writeYAMLConfig()

	return nil
}

func (m *GatewayClient) login(accessToken string) error {
	loginReq, err := http.NewRequest("GET", m.GateEndpoint()+"/login", nil)
	if err != nil {
		return err
	}
	loginReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	m.httpClient.Do(loginReq) // Login to establish session.
	return nil
}

func (m *GatewayClient) authenticateLdap() error {
	authConfig := m.Config.Auth
	if authConfig != nil && authConfig.Enabled && authConfig.Ldap != nil && authConfig.Method == auth.Ldap {
		if !authConfig.Ldap.IsValid() {
			return errors.New("Incorrect LDAP auth configuration. Must include username and password.")
		}

		form := url.Values{}
		form.Add("username", authConfig.Ldap.Username)
		form.Add("password", authConfig.Ldap.Password)

		loginReq, err := http.NewRequest("POST", m.GateEndpoint()+"/login", strings.NewReader(form.Encode()))
		loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err != nil {
			return err
		}

		_, err = m.httpClient.Do(loginReq) // Login to establish session.

		if err != nil {
			return errors.New("ldap authentication failed")
		}

		m.Context = context.Background()
	}

	return nil
}

// writeYAMLConfig writes an updated YAML configuration file to the reciever's config file location.
// It returns an error, but the error may be ignored.
func (m *GatewayClient) writeYAMLConfig() error {
	// Write updated config file with u=rw,g=,o= permissions by default.
	// The default permissions should only be used if the file no longer exists.
	err := writeYAML(&m.Config, m.configLocation, defaultConfigFileMode)
	if err != nil {
		util.UI.Warn(fmt.Sprintf("Error caching oauth2 token: %v", err))
	}
	return err
}

func writeYAML(v interface{}, dest string, defaultMode os.FileMode) error {
	// Write config with cached token
	buf, err := yaml.Marshal(v)
	if err != nil {
		return err
	}

	mode := defaultMode
	info, err := os.Stat(dest)
	if err != nil && !os.IsNotExist(err) {
		return nil
	} else {
		// Preserve existing file mode
		mode = info.Mode()
	}

	return ioutil.WriteFile(dest, buf, mode)
}

// generateCodeVerifier generates an OAuth2 code verifier
// in accordance to https://www.oauth.com/oauth2-servers/pkce/authorization-request and
// https://tools.ietf.org/html/rfc7636#section-4.1.
func generateCodeVerifier() (verifier string, code string, err error) {
	randomBytes := make([]byte, 64)
	if _, err := rand.Read(randomBytes); err != nil {
		util.UI.Error("Could not generate random string for code_verifier")
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(randomBytes)
	verifierHash := sha256.Sum256([]byte(verifier))
	code = base64.RawURLEncoding.EncodeToString(verifierHash[:]) // Slice for type conversion
	return verifier, code, nil
}

func prompt() string {
	reader := bufio.NewReader(os.Stdin)
	util.UI.Output("Paste authorization code:")
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}
