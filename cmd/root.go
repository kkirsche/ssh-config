// Copyright © 2016 Kevin Kirsche <kev.kirsche@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"
	"os/user"

	"github.com/kkirsche/ssh-config/lib"
	"github.com/spf13/cobra"
)

var cfgFilePath string
var verbose bool

var currentUser *user.User
var logger *sshConfig.Logger

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "ssh-config",
	Short: "ssh-config manages the current user's SSH configuration file.",
	Long: `ssh-config is a program to manage the current user's SSH configuration
file used when providing a clear and easy to use interface.`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().StringVarP(&cfgFilePath, "config", "c", "", "config file path (default is $HOME/.ssh/config)")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	logger = sshConfig.New("", os.Stdout, os.Stderr, verbose)

	var err error
	currentUser, err = user.Current()
	if err != nil {
		logger.Errorf("Could not load current user with error: %s", err.Error())
	}

	if cfgFilePath == "" { // enable ability to specify config file via flag
		cfgFilePath = fmt.Sprintf("%s/.ssh/config", currentUser.HomeDir)
	}

	logger.VerbosePrintf("Using config file: %s", cfgFilePath)
}
