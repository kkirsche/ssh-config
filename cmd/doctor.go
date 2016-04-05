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
	"strconv"

	"github.com/spf13/cobra"
)

var (
	fixErrors bool
)

const (
	globalConfigPath     = "/etc/ssh/ssh_config"
	globalConfigFileMode = 0644

	rootUID        = 0
	rootUIDString  = "0"
	wheelGID       = 0
	wheelGIDString = "0"

	relativeLocalConfigPath = ".ssh/config"
	localConfigFileMode     = 0644
)

// doctorCmd represents the doctor command
var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Checks for issues with your global and local SSH configuration file",
	Long: `Checks for file permission and ownership issues related to both the
local and global SSH configuration files. If the fix flag is set, the failures
will attempt to be repaired.`,
	Run: func(cmd *cobra.Command, args []string) {
		var localConfigPath string
		if currentUser == nil {
			var err error
			currentUser, err = user.Current()
			if err != nil {
				logger.Errorf("Could not load current user with error: %s", err.Error())
				return
			}
		}

		if currentUser.Uid != rootUIDString {
			localConfigPath = fmt.Sprintf("%s/%s", currentUser.HomeDir, relativeLocalConfigPath)

			logger.Printf("[Doctor Action] Opening local SSH configuration at %s", localConfigPath)
			localConfig, err := os.Open(localConfigPath)
			if err != nil {
				logger.Errorf("[Doctor Error] Could not open local configuration file with error: %s", err.Error())
				return
			}
			defer localConfig.Close()

			localConfigDetails, err := localConfig.Stat()
			if err != nil {
				logger.Errorf("[Doctor Error] Unable to retrieve statistics about the local configuration file with error: %s.", err.Error())
			}

			if localConfigDetails.Mode().String() != "-rw-r--r--" {
				logger.Println("[Doctor Fail] Local configuration file has incorrect permissions. Permissions should be -rw-r--r-- (0644) for /etc/ssh/ssh_config.")
				if fixErrors {
					err = localConfig.Chmod(localConfigFileMode)
					if err != nil {
						logger.Errorf("[Doctor Error] Failed to change global ssh configuration file mode to 0644 with error: %s", err.Error())
					} else {
						logger.Println("[Doctor Success] Changed global SSH configuration file mode to 0644.")
					}
				}
			} else {
				logger.VerbosePrintln("[Doctor Success] Global configuration file permissions are -rw-r--r-- (0644)")
			}

			currentUID, err := strconv.Atoi(currentUser.Uid)
			if err != nil {
				logger.Errorf("[Doctor Error] Failed to retrieve the current user's ID.")
			}

			currentGID, err := strconv.Atoi(currentUser.Gid)
			if err != nil {
				logger.Errorf("[Doctor Error] Failed to retrieve the current user's group ID.")
			}

			if currentUID >= 0 && currentGID >= 0 {
				err = localConfig.Chown(currentUID, currentGID)
				if err != nil {
					logger.Errorf("[Doctor Error] Failed to set local configuration file ownership to UID: %d and GID: %d with error: %s", currentUID, currentGID, err.Error())
				} else {
					logger.Println("[Doctor Success] Global configuration file is correctly owned.")
				}
			}
		} else {
			logger.Errorf("[Doctor Error] Could not open local SSH configuration. Currently running as root. Re-run ssh-config doctor as a lower privilege user.")
		}

		logger.VerbosePrintf("[Doctor Action] Opening global configuration at %s", globalConfigPath)
		globalConfig, err := os.Open(globalConfigPath)
		if err != nil {
			logger.Errorf("[Doctor Error] Could not open global configuration file with error: %s", err.Error())
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
						logger.Errorf("[Doctor Error] Unable to change global SSH configuration file mode to 0644. Must be root or sudo to take this action.")
					} else {
						err = globalConfig.Chmod(globalConfigFileMode)
						if err != nil {
							logger.Errorf("[Doctor Error] Failed to change global ssh configuration file mode to 0644 with error: %s", err.Error())
						} else {
							logger.Println("[Doctor Success] Changed global SSH configuration file mode to 0644.")
						}
					}
				} else {
					logger.Errorf("[Doctor Error] Could not retrieve the current user.")
				}
			}
		} else {
			logger.VerbosePrintln("[Doctor Success] Global configuration file permissions are -rw-r--r-- (0644)")
		}

		err = globalConfig.Chown(rootUID, wheelGID)
		if err != nil {
			logger.Errorf("[Doctor Error] Failed to set global configuration file ownership to UID: 0 and GID: 0 with error: %s", err.Error())
		} else {
			logger.Println("[Doctor Success] Global configuration file is correctly owned.")
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
