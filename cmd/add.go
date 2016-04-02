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
	"html/template"
	"os"
	"os/user"

	"github.com/spf13/cobra"
)

var hostNickname string
var remoteHost string
var remotePort int
var remoteUsername string

type configEntry struct {
	Host     string
	Hostname string
	Port     int
	User     string
}

const (
	sshConfigTemplate = `Host {{ .Host}}
{{with .Hostname -}}
Hostname {{.}}
{{- end}}
{{with .Port -}}
Port {{.}}
{{- end}}
{{with .User -}}
User {{.}}
{{- end}}`
)

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		config := configEntry{
			Host:     "Ghost",
			Hostname: "1.2.3.4",
			Port:     22,
			User:     "WTF BBQ",
		}

		t := template.Must(template.New("sshConfig").Parse(sshConfigTemplate))
		t.Execute(os.Stdout, config)
	},
}

func init() {
	RootCmd.AddCommand(addCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:

	// Nicknames
	addCmd.PersistentFlags().StringVarP(&hostNickname, "name", "n", "",
		`The name is the name argument given on the command
			     line to sshd when connecting to the remote host.`)

	// #  Remote Machine Details
	// ## Connection Details
	addCmd.PersistentFlags().StringVarP(&remoteHost, "remote-host", "r", "",
		`The remote IP or hostname to connect to using SSH.`)
	addCmd.PersistentFlags().IntVarP(&remotePort, "port", "p", 22, `The remote sshd port.`)

	var err error
	currentUser, err = user.Current()
	if err != nil {
		logger.Errorf("Could not load current user with error: %s", err.Error())
	}
	if currentUser != nil {
		addCmd.PersistentFlags().StringVarP(&remoteUsername, "username", "u", currentUser.Name, `The remote SSH username.`)
	}

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// addCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
