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

	"github.com/kkirsche/ssh-config/lib"
	"github.com/spf13/cobra"
)

var batchmode bool
var challengeRespAuth bool
var checkHostIP bool
var compression bool
var exitOnForwardFailure bool
var forwardAgent bool
var identitiesOnly bool
var writeToFile bool

var addressFamily string
var bindAddress string
var ciphers string
var clearAllForwardings string
var identityFile string
var host string
var hostname string
var username string

var connectionAttempts int
var connectTimeout int
var port int

const (
	yes = "yes"
	no  = "no"
)

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "adds generates and (optionally) writes new configuration entries",
	Long:  `This `,
	Run: func(cmd *cobra.Command, args []string) {
		validation := true
		config := sshConfig.SSHConfigurationEntry{
			AddressFamily:      addressFamily,
			BindAddress:        bindAddress,
			Ciphers:            ciphers,
			ConnectionAttempts: connectionAttempts,
			ConnectTimeout:     connectTimeout,
			IdentityFile:       identityFile,
			Hostname:           hostname,
			Host:               host,
			Port:               port,
			User:               username,
		}

		if host == "" {
			validation = false
			logger.Errorf("Name not provided. Please provide the name via --name or -n")
			return
		}

		if !sshConfig.ValidStringArgs(sshConfig.ValidAddressFamilyAnswers(), addressFamily) {
			validation = false
			logger.Errorf("Invalid value provided to --address-family (-a). Please enter any, inet, or inet6. You provided: %s", addressFamily)
			return
		}

		if batchmode {
			config.BatchMode = yes
		}

		if compression {
			config.Compression = yes
		}

		if challengeRespAuth {
			config.ChallengeResponseAuthentication = yes
		}

		if checkHostIP {
			config.CheckHostIP = yes
		}

		if exitOnForwardFailure {
			config.ExitOnForwardFailure = yes
		}

		if forwardAgent {
			config.ForwardAgent = yes
		}

		if identitiesOnly {
			config.IdentitiesOnly = yes
		}

		if validation == true {
			t := template.Must(template.New("sshConfig").Parse(sshConfig.SSHConfigurationEntryTemplate))
			err := t.Execute(os.Stdout, config)
			if err != nil {
				logger.Errorf("Couldn't execute SSH Configuration Template with error: %s", err.Error())
			}
		}
	},
}

func init() {
	// Register the command
	RootCmd.AddCommand(addCmd)

	// Define the flags that have POSIX short versions
	addCmd.PersistentFlags().StringVarP(&addressFamily, "address-family", "a", "", "Specifies which address family to use\n\t\t\t\t\t when connecting. Valid arguments are\n\t\t\t\t\t 'any', 'inet' (use IPv4 only), or\n\t\t\t\t\t 'inet6' (use IPv6 only).")
	addCmd.PersistentFlags().BoolVarP(&batchmode, "batchmode", "b", false, "If set to 'yes', passphrase/password\n\t\t\t\t\t querying will be disabled. This option\n\t\t\t\t\t is useful in scripts and other batch\n\t\t\t\t\t jobs where no user is present to supply\n\t\t\t\t\t the password. The argument must be\n\t\t\t\t\t 'yes' or 'no'. The default is 'no'.")
	// c is for the configuration file flag
	addCmd.PersistentFlags().StringVarP(&bindAddress, "bind-address", "d", "", "Use the specified address on the local\n\t\t\t\t\t machine as the source address of the\n\t\t\t\t\t connection. Only useful on systems with\n\t\t\t\t\t more than one address. Note that this\n\t\t\t\t\t option does not work if\n\t\t\t\t\t UsePrivilegedPort is set to 'yes'.")
	addCmd.PersistentFlags().BoolVarP(&checkHostIP, "check-host-ip", "e", false, "If this flag is set to 'yes', ssh will\n\t\t\t\t\t additionally check the host IP address\n\t\t\t\t\t in the known_hosts file. This allows\n\t\t\t\t\t ssh to detect if a host key changed due\n\t\t\t\t\t to DNS spoofing. If the option\n\t\t\t\t\t is set to 'no', the check will not be\n\t\t\t\t\t executed. The default is 'yes'.")
	addCmd.PersistentFlags().BoolVarP(&forwardAgent, "forward-agent", "f", false, "Specifies whether the connection to the\n\t\t\t\t\t authentication agent (if any) will be\n\t\t\t\t\t forwarded to the remote machine.\n\t\t\t\t\t The argument must be 'yes' or 'no'.\n\t\t\t\t\t The default is 'no'.\n\n\t\t\t\t\t Agent forwarding should be enabled with\n\t\t\t\t\t caution. Users with the ability to\n\t\t\t\t\t bypass file permissions on the\n\t\t\t\t\t remote host (for the agent's\n\t\t\t\t\t Unix-domain socket) can access the\n\t\t\t\t\t local agent through the forwarded\n\t\t\t\t\t connection. An attacker cannot obtain\n\t\t\t\t\t key material from the agent, however\n\t\t\t\t\t they can perform operations on the keys\n\t\t\t\t\t that enable them to authenticate using\n\t\t\t\t\t the identities loaded into the agent.")
	// g is undefined
	// h is for the help text flag
	addCmd.PersistentFlags().BoolVarP(&challengeRespAuth, "challenge-response-auth", "l", false, "Specifies whether to use\n\t\t\t\t\t challenge-response authentication.\n\t\t\t\t\t The argument to this keyword must be\n\t\t\t\t\t 'yes' or 'no'. The default is 'yes'.")
	addCmd.PersistentFlags().BoolVarP(&compression, "compression", "m", false, "Specifies whether to use compression.\n\t\t\t\t\t The argument must be 'yes' or 'no'.\n\t\t\t\t\t The default is 'no'.")
	addCmd.PersistentFlags().StringVarP(&host, "name", "n", "", "The name is the name argument given on\n\t\t\t\t\t the command line to sshd when\n\t\t\t\t\t connecting to the remote host.")
	addCmd.PersistentFlags().IntVarP(&connectionAttempts, "connection-attempts", "o", 0, "Specifies the number of tries (one per\n\t\t\t\t\t second) to make before exiting.\n\t\t\t\t\t This may be useful in scripts if the\n\t\t\t\t\t connection sometimes fails.")
	addCmd.PersistentFlags().IntVarP(&port, "port", "p", 22, "Specifies the port number to connect\n\t\t\t\t\t on the remote host.")
	// q is undefined
	addCmd.PersistentFlags().StringVarP(&hostname, "hostname", "r", "", "Specifies the real host name to log\n\t\t\t\t\t into. This can be used to specify\n\t\t\t\t\t nicknames or abbreviations for hosts.\n\t\t\t\t\t The default is the name given\n\t\t\t\t\t on the command line. Numeric IP\n\t\t\t\t\t addresses are also permitted.")
	addCmd.PersistentFlags().StringVarP(&ciphers, "ciphers", "s", "", "Specifies the ciphers allowed for\n\t\t\t\t\t protocol version 2 in order of\n\t\t\t\t\t preference. Multiple ciphers must be\n\t\t\t\t\t comma-separated. The supported ciphers\n\t\t\t\t\t are '3des-cbc', 'aes128-cbc',\n\t\t\t\t\t 'aes192-cbc', 'aes256-cbc',\n\t\t\t\t\t 'aes128-ctr', 'aes192-ctr',\n\t\t\t\t\t 'aes256-ctr', 'arcfour128',\n\t\t\t\t\t 'arcfour256', 'arcfour',\n\t\t\t\t\t 'blowfish-cbc', and 'cast128-cbc'.")
	addCmd.PersistentFlags().IntVarP(&connectTimeout, "connect-timeout", "t", 0, "Specifies the timeout (in seconds) used\n\t\t\t\t\t when connecting to the SSH server,\n\t\t\t\t\t instead of using the default system\n\t\t\t\t\t TCP timeout. This value is used only\n\t\t\t\t\t when the target is down or really\n\t\t\t\t\t unreachable, not when it refuses\n\t\t\t\t\t the connection.")
	addCmd.PersistentFlags().StringVarP(&username, "user", "u", "", "The remote username to connect as.")
	// v is defined for Verbose mode
	addCmd.PersistentFlags().BoolVarP(&writeToFile, "write", "w", false, "Write the output of the tool to a file in\n\t\t\t\t\t addition to stdout.")
	addCmd.PersistentFlags().BoolVarP(&exitOnForwardFailure, "exit-on-forward-failure", "x", false, "Specifies whether ssh should\n\t\t\t\t\t terminate the connection if it cannot\n\t\t\t\t\t set up all requested dynamic, tunnel,\n\t\t\t\t\t local, and remote port forwardings.\n\t\t\t\t\t The argument must be 'yes' or 'no'.\n\t\t\t\t\t The default is 'no'.")
	// y is undefined
	addCmd.PersistentFlags().BoolVarP(&exitOnForwardFailure, "identities-only", "z", false, "Specifies that ssh should only use the\n\t\t\t\t\t authentication identity files\n\t\t\t\t\t configured in the ssh_config files,\n\t\t\t\t\t even if ssh-agent offers more\n\t\t\t\t\t identities. The argument to this\n\t\t\t\t\t keyword must be 'yes' or 'no'. This\n\t\t\t\t\t option is intended for situations\n\t\t\t\t\t where ssh-agent offers many different\n\t\t\t\t\t identities. The default is 'no'.")

}
