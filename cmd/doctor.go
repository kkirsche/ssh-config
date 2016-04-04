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
	"os"
	"os/user"

	"github.com/spf13/cobra"
)

var (
	fixErrors bool
)

const (
	globalConfigPath        = "/etc/ssh/ssh_config"
	globalConfigFileMode    = 0644
	relativeLocalConfigPath = "/.ssh/config"
)

// doctorCmd represents the doctor command
var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Checks for issues with your SSH configuration file",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if currentUser == nil {
			var err error
			currentUser, err = user.Current()
			if err != nil {
				logger.Errorf("Could not load current user with error: %s", err.Error())
				return
			}
		}

		logger.VerbosePrintf("Opening global configuration at %s", globalConfigPath)
		globalConfig, err := os.Open(globalConfigPath)
		if err != nil {
			logger.Errorf("Could not open global configuration file with error: %s", err.Error())
			return
		}
		defer globalConfig.Close()

		globalConfigDetails, err := globalConfig.Stat()
		if err != nil {
			logger.Errorf("Unable to retrieve statistics about the global configuration file with error: %s.", err.Error())
		}

		if globalConfigDetails.Mode().String() != "-rw-r--r--" {
			logger.Println("[Doctor Fail] Global configuration file has incorrect permissions. Permissions should be -rw-r--r-- (0644) for /etc/ssh/ssh_config.")
			if fixErrors {
				if currentUser != nil {
					if currentUser.Uid != "0" {
						logger.Errorf("[Fix Error] Unable to change global SSH configuration file mode to 0644. Must be root or sudo to take this action.")
					} else {
						err = globalConfig.Chmod(globalConfigFileMode)
						if err != nil {
							logger.Errorf("[Fix Error] Failed to change global ssh configuration file mode to 0644 with error: %s", err.Error())
						} else {
							logger.Println("[Fix Success] Changed global SSH configuration file mode to 0644.")
						}
					}
				}
			}
		} else {
			logger.VerbosePrintln("[Doctor Success] Global configuration file permissions are -rw-r--r-- (0644)")
		}
	},
}

func init() {
	RootCmd.AddCommand(doctorCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	doctorCmd.PersistentFlags().BoolVarP(&fixErrors, "fix", "f", false, "Attempt to fix errors")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// doctorCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
