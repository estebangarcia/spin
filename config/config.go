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

package config

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"github.com/spinnaker/spin/config/auth"
)

// Config is the CLI configuration kept in '~/.spin/config'.
type Config struct {
	Gate struct {
		Endpoint       string `yaml:"endpoint" cli:"help=Gate (API server) endpoint (default http://localhost:8084);visible"`
		DefaultHeaders string `yaml:"defaultheaders" cli:"help=configure default headers for gate client as comma separated list (e.g. key1=value1,key2=value2);visible"`
		Insecure       bool   `yaml:"insecure" cli:"help=ignore certificate errors;visible"`
	} `yaml:"gate"`
	Auth     *auth.AuthConfig `yaml:"auth"`
	Location string           `yaml:"-"`
}

func (c Config) String() string {
	out, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return string(out)
}

func Parse() (Config, error) {
	filePath := viper.GetString("config")
	if filePath == "" {
		userHome := ""
		if usr, err := user.Current(); err != nil {
			userHome = os.Getenv("HOME")
			if userHome == "" {
				return Config{}, errors.New("could not read current user from environment, failing")
			}
		} else {
			userHome = usr.HomeDir
		}
		filePath = filepath.Join(userHome, ".spin", "config")

	}

	return ParseFromFile(filePath)

}

func ParseFromFile(file string) (Config, error) {
	viper.SetEnvPrefix("spin")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	viper.SetConfigFile(file)

	viper.SetConfigType("yaml")
	viper.ReadInConfig()

	var spinConfig Config
	spinConfig.Location = file

	return spinConfig, viper.Unmarshal(&spinConfig)
}
