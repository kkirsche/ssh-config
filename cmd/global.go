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
	"bufio"
	"os"

	"github.com/spf13/cobra"
)

// globalCmd represents the global command
var globalCmd = &cobra.Command{
	Use:   "global",
	Short: "Prints the contents of the current user's SSH configuration file.",
	Long: `Prints the contents of the current user's SSH configuration file to
	Stdout.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Location per http://linux.die.net/man/5/ssh_config
		cfgFilePath = "/etc/ssh/ssh_config"

		logger.VerbosePrintf("Opening configuration file handle at %s", cfgFilePath)
		file, err := os.Open(cfgFilePath)
		if err != nil {
			logger.Errorf("Could not open SSH configuration file %s due to an error: %s",
				cfgFilePath, err.Error())
		}
		defer file.Close()

		logger.VerbosePrintln("Creating new SSH configuration file scanner")
		scanner := bufio.NewScanner(file)

		logger.VerbosePrintln("Outputting file:\n")
		logger.VerbosePrintln("#", cfgFilePath)
		for scanner.Scan() {
			logger.Println(scanner.Text())
		}
	},
}

func init() {
	showCmd.AddCommand(globalCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// globalCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// globalCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
