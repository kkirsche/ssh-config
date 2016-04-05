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
	"strings"

	"github.com/kkirsche/ssh-config/lib"
	"github.com/spf13/cobra"
)

var (
	batchmode                    bool
	challengeRespAuth            bool
	checkHostIP                  bool
	clearAllForwardings          bool
	compression                  bool
	exitOnForwardFailure         bool
	forwardAgent                 bool
	forwardX11                   bool
	forwardX11Trusted            bool
	gatewayPorts                 bool
	gssAPIAuthentication         bool
	gssAPIDelegateCredentials    bool
	gssAPIKeyExchange            bool
	gssAPIRenewalForcesRekey     bool
	gssAPITrustDNS               bool
	hashKnownHosts               bool
	hostBasedAuth                bool
	identitiesOnly               bool
	kbdInteractiveAuthentication bool
	noHostAuthForLocalhost       bool
	passwordAuthentication       bool
	permitLocalCommand           bool
	publicKeyAuthentication      bool
	rhostsRSAAuthentication      bool
	rsaAuthentication            bool
	tcpKeepAlive                 bool
	usePrivilegedPort            bool
	visualHostKey                bool

	compressionLevel        int
	connectionAttempts      int
	connectTimeout          int
	numberOfPasswordPrompts int
	port                    int
	serverAliveCountMax     int
	serverAliveInterval     int

	addressFamily            string
	bindAddress              string
	ciphers                  string
	cipher                   string
	controlMaster            string
	controlPath              string
	dynamicForward           string
	escapeChar               string
	gssAPIClientIdentity     string
	hostKeyAlgorithms        string
	hostKeyAlias             string
	hostname                 string
	host                     string
	identityFile             string
	kbdInteractiveDevices    string
	localCommand             string
	localForward             string
	logLevel                 string
	macs                     string
	preferredAuthentications string
	protocol                 string
	proxyCommand             string
	rekeyLimit               string
	remoteForward            string
	sendEnv                  string
	smartcardDevice          string
	strictHostkeyChecking    string
	tunnelDevice             string
	tunnel                   string
	userKnownHostsFile       string
	username                 string
	verifyHostKeyDNS         string
	writeToFile              string
	xAuthLocation            string
)

const (
	yes = "yes"
	no  = "no"
)

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "adds generates and prints new configuration entries",
	Long: `This command generates and prints SSH configuration file entries to
stdout as well as (if specified) a file.`,
	Run: func(cmd *cobra.Command, args []string) {
		validation := true
		config := sshConfig.SSHConfigurationEntry{
			AddressFamily:         addressFamily,
			BindAddress:           bindAddress,
			Cipher:                cipher,
			Ciphers:               ciphers,
			CompressionLevel:      compressionLevel,
			ConnectionAttempts:    connectionAttempts,
			ConnectTimeout:        connectTimeout,
			ControlMaster:         controlMaster,
			ControlPath:           controlPath,
			DynamicForward:        dynamicForward,
			EscapeChar:            escapeChar,
			GSSAPIClientIdentity:  gssAPIClientIdentity,
			Host:                  host,
			HostKeyAlgorithms:     hostKeyAlgorithms,
			HostKeyAlias:          hostKeyAlias,
			Hostname:              hostname,
			IdentityFile:          identityFile,
			KBDInteractiveDevices: kbdInteractiveDevices,
			LocalCommand:          localCommand,
			LocalForward:          localForward,
			LogLevel:              logLevel,
			MACs:                  macs,
			NumberOfPasswordPrompts: numberOfPasswordPrompts,
			Port: port,
			PreferredAuthentications: preferredAuthentications,
			Protocol:                 protocol,
			ProxyCommand:             proxyCommand,
			RekeyLimit:               rekeyLimit,
			RemoteForward:            remoteForward,
			SendEnv:                  sendEnv,
			ServerAliveCountMax:      serverAliveCountMax,
			ServerAliveInterval:      serverAliveInterval,
			SmartcardDevice:          smartcardDevice,
			StrictHostKeyChecking:    strictHostkeyChecking,
			Tunnel:                   tunnel,
			TunnelDevice:             tunnelDevice,
			User:                     username,
			UserKnownHostsFile:       userKnownHostsFile,
			VerifyHostKeyDNS:         verifyHostKeyDNS,
			XAuthLocation:            xAuthLocation,
		}

		if args != nil {
			joinedArgs := strings.Join(args, "_")
			logger.VerbosePrintf("[Add Info] Detected passed arguments: %v. Combined as: %s.", args, joinedArgs)
			config.Host = joinedArgs
		}

		if config.Host == "" {
			validation = false
			logger.Errorf("[Add Error] Host's name not provided. Please provide the name via --name or -n.")
			return
		}

		if !sshConfig.ValidStringArgs(sshConfig.ValidAddressFamilyAnswers(), addressFamily) {
			validation = false
			logger.Errorf("[Add Error] Invalid value provided to --address-family (-a). Please enter any, inet, or inet6. You provided: %s", addressFamily)
			return
		}

		if batchmode {
			config.BatchMode = yes
		}

		if challengeRespAuth {
			config.ChallengeResponseAuthentication = no
		}

		if checkHostIP {
			config.CheckHostIP = no
		}

		if clearAllForwardings {
			config.ClearAllForwardings = yes
		}

		if compression {
			config.Compression = yes
		}

		if exitOnForwardFailure {
			config.ExitOnForwardFailure = yes
		}

		if forwardAgent {
			config.ForwardAgent = yes
		}

		if forwardX11 {
			config.ForwardX11 = yes
		}

		if forwardX11Trusted {
			config.ForwardX11Trusted = yes
		}

		if gatewayPorts {
			config.GatewayPorts = yes
		}

		if gssAPIAuthentication {
			config.GSSAPIAuthentication = yes
		}

		if gssAPIKeyExchange {
			config.GSSAPIKeyExchange = yes
		}

		if gssAPIDelegateCredentials {
			config.GSSAPIDelegateCredentials = yes
		}

		if gssAPIRenewalForcesRekey {
			config.GSSAPIRenewalForcesRekey = yes
		}

		if gssAPITrustDNS {
			config.GSSAPITrustDNS = yes
		}

		if hashKnownHosts {
			config.HashKnownHosts = yes
		}

		if hostBasedAuth {
			config.HostbasedAuthentication = yes
		}

		if identitiesOnly {
			config.IdentitiesOnly = yes
		}

		if kbdInteractiveAuthentication {
			config.KBDInteractiveAuthentication = yes
		}

		if noHostAuthForLocalhost {
			config.NoHostAuthenticationForLocalhost = yes
		}

		if passwordAuthentication {
			config.PasswordAuthentication = yes
		}

		if permitLocalCommand {
			config.PermitLocalCommand = yes
		}

		if publicKeyAuthentication {
			config.PubkeyAuthentication = yes
		}

		if rhostsRSAAuthentication {
			config.RhostsRSAAuthentication = yes
		}

		if rsaAuthentication {
			config.RSAAuthentication = yes
		}

		if tcpKeepAlive {
			config.TCPKeepAlive = yes
		}

		if noHostAuthForLocalhost {
			config.NoHostAuthenticationForLocalhost = yes
		}

		if usePrivilegedPort {
			config.UsePrivilegedPort = yes
		}

		if visualHostKey {
			config.VisualHostKey = yes
		}

		if validation == true {
			t := template.Must(template.New("sshConfig").Parse(sshConfig.SSHConfigurationEntryTemplate))
			logger.Printf("[Add Info] Printing SSH configuration entry to stdout.\n")
			err := t.Execute(os.Stdout, config)
			if err != nil {
				logger.Errorf("\n[Add Error] Couldn't finish printing SSH Configuration Template to stdout. Received error during printing: %s", err.Error())
				return
			}

			if writeToFile != "" {
				file, err := os.OpenFile(writeToFile, os.O_APPEND|os.O_WRONLY, 0666)
				if err != nil {
					logger.Errorf("\n[Add Error] Couldn't open the SSH Configuration file at %s. Received error: %s", writeToFile, err.Error())
					return
				}
				defer file.Close()

				err = t.Execute(file, config)
				if err != nil {
					logger.Errorf("\n[Add Error] Couldn't execute SSH Configuration Template on file. Received error: %s", err.Error())
					return
				}
				logger.Println("\n[Add Success] SSH Configuration Entry Successfully Appended")
			}
		}
	},
}

func init() {
	// Register the command
	RootCmd.AddCommand(addCmd)

	// Define the flags that have POSIX short versions
	// c is for the configuration file flag
	// g is undefined
	// h is for the help text flag
	// q is undefined
	// v is defined for Verbose mode
	// y is undefined
	addCmd.PersistentFlags().BoolVar(&clearAllForwardings, "clear-all-forwardings", false, "Specifies that all local, remote, and\n\t\t\t\t\t\t dynamic port forwardings\n\t\t\t\t\t\t specified in the configuration\n\t\t\t\t\t\t files or on the command line\n\t\t\t\t\t\t be cleared.")
	addCmd.PersistentFlags().BoolVar(&forwardX11, "forward-x11", false, "Specifies whether X11 connections will\n\t\t\t\t\t\t be automatically redirected\n\t\t\t\t\t\t over the secure channel and\n\t\t\t\t\t\t DISPLAY set.")
	addCmd.PersistentFlags().BoolVar(&forwardX11Trusted, "forward-x11-trusted", false, "If this option is enabled, remote X11\n\t\t\t\t\t\t clients will have full access\n\t\t\t\t\t\t to the original X11 display.")
	addCmd.PersistentFlags().BoolVar(&gatewayPorts, "gateway-ports", false, "Specifies whether remote hosts are\n\t\t\t\t\t\t allowed to connect to local\n\t\t\t\t\t\t forwarded ports.")
	addCmd.PersistentFlags().BoolVar(&gssAPIAuthentication, "gssapi-authentication", false, "Specifies whether user authentication\n\t\t\t\t\t\t based on GSSAPI is allowed.")
	addCmd.PersistentFlags().BoolVar(&gssAPIDelegateCredentials, "gssapi-delegate-credentials", false, "Forward (delegate) credentials to the\n\t\t\t\t\t\t server.")
	addCmd.PersistentFlags().BoolVar(&gssAPIKeyExchange, "gssapi-key-exchange", false, "Specifies whether key exchange based\n\t\t\t\t\t\t on GSSAPI may be used.")
	addCmd.PersistentFlags().BoolVar(&gssAPIRenewalForcesRekey, "gssapi-renewal-forces-rekey", false, "If enabled, then renewal of the\n\t\t\t\t\t\t client's GSSAPI credentials\n\t\t\t\t\t\t will force the rekeying of the\n\t\t\t\t\t\t ssh connection.")
	addCmd.PersistentFlags().BoolVar(&gssAPITrustDNS, "gssapi-trust-dns", false, "Enable this feature to indicate that\n\t\t\t\t\t\t the DNS is trusted to securely\n\t\t\t\t\t\t canonicalize' the name of the\n\t\t\t\t\t\t host being connected to.")
	addCmd.PersistentFlags().BoolVar(&hashKnownHosts, "hash-known-hosts", false, "Indicates that ssh should hash host\n\t\t\t\t\t\t names and addresses when they\n\t\t\t\t\t\t are added to\n\t\t\t\t\t\t ~/.ssh/known_hosts. These\n\t\t\t\t\t\t hashed names may be used\n\t\t\t\t\t\t normally by ssh and sshd, but\n\t\t\t\t\t\t they do not reveal identifying\n\t\t\t\t\t\t information should the file's\n\t\t\t\t\t\t contents be disclosed.")
	addCmd.PersistentFlags().BoolVar(&hostBasedAuth, "host-based-auth", false, "Specifies whether to try rhosts based\n\t\t\t\t\t\t authentication with public key\n\t\t\t\t\t\t authentication.")
	addCmd.PersistentFlags().BoolVar(&kbdInteractiveAuthentication, "kbd-interactive-auth", false, "Specifies keyboard-interactive\n\t\t\t\t\t\t authentication should\n\t\t\t\t\t\t be used.")
	addCmd.PersistentFlags().BoolVar(&passwordAuthentication, "password-auth", false, "Specifies whether to use password\n\t\t\t\t\t\t authentication.")
	addCmd.PersistentFlags().BoolVar(&permitLocalCommand, "permit-local-cmd", false, "Allow local command execution via the\n\t\t\t\t\t\t LocalCommand option or using\n\t\t\t\t\t\t the !command escape sequence in\n\t\t\t\t\t\t ssh.")
	addCmd.PersistentFlags().BoolVar(&publicKeyAuthentication, "public-key-auth", false, "Specifies whether to try public key\n\t\t\t\t\t\t authentication.")
	addCmd.PersistentFlags().BoolVar(&rhostsRSAAuthentication, "rhosts-rsa-auth", false, "Specifies whether to try rhosts based\n\t\t\t\t\t\t authentication with RSA host\n\t\t\t\t\t\t authentication.")
	addCmd.PersistentFlags().BoolVar(&rsaAuthentication, "rsa-auth", false, "Specifies whether to try RSA\n\t\t\t\t\t\t authentication. RSA\n\t\t\t\t\t\t authentication will only\n\t\t\t\t\t\t be attempted if the identity\n\t\t\t\t\t\t file exists, or an\n\t\t\t\t\t\t authentication agent is\n\t\t\t\t\t\t running. Note that this option\n\t\t\t\t\t\t applies to protocol version 1\n\t\t\t\t\t\t only.")
	addCmd.PersistentFlags().BoolVar(&tcpKeepAlive, "tcp-keepalive", false, "Specifies whether the system should\n\t\t\t\t\t\t send TCP keepalive messages to\n\t\t\t\t\t\t the other side. If they are\n\t\t\t\t\t\t sent, death of the connection\n\t\t\t\t\t\t or crash of one of the machines\n\t\t\t\t\t\t will be properly noticed.\n\t\t\t\t\t\t However, this means that\n\t\t\t\t\t\t connections will die if the\n\t\t\t\t\t\t route is down temporarily, and\n\t\t\t\t\t\t some people find it annoying.")
	addCmd.PersistentFlags().BoolVar(&usePrivilegedPort, "use-priviledged-port", false, "Specifies whether to use a privileged\n\t\t\t\t\t\t port for outgoing connections.\n\t\t\t\t\t\t If enabled, ssh must be setuid\n\t\t\t\t\t\t root.")
	addCmd.PersistentFlags().BoolVar(&visualHostKey, "visual-hostkey", false, "If enabled, an ASCII art\n\t\t\t\t\t\t representation of the remote\n\t\t\t\t\t\t host key fingerprint is printed\n\t\t\t\t\t\t in addition to the hex\n\t\t\t\t\t\t fingerprint string at login and\n\t\t\t\t\t\t for unknown host keys.")

	addCmd.PersistentFlags().BoolVarP(&batchmode, "batchmode", "b", false, "If set, passphrase/password\n\t\t\t\t\t\t querying will be disabled.")
	addCmd.PersistentFlags().BoolVarP(&challengeRespAuth, "challenge-response-auth", "l", false, "If set, the host will not use\n\t\t\t\t\t\t challenge-response\n\t\t\t\t\t\t authentication.")
	addCmd.PersistentFlags().BoolVarP(&checkHostIP, "check-host-ip", "e", false, "If this flag is set, ssh will\n\t\t\t\t\t\t not additionally check the\n\t\t\t\t\t\t host IP address in the\n\t\t\t\t\t\t known_hosts file.")
	addCmd.PersistentFlags().BoolVarP(&compression, "compression", "m", false, "Specifies that compression should be\n\t\t\t\t\t\t used.")
	addCmd.PersistentFlags().BoolVarP(&exitOnForwardFailure, "exit-on-forward-failure", "x", false, "Specifies whether ssh should terminate\n\t\t\t\t\t\t the connection if it cannot set\n\t\t\t\t\t\t up all requested dynamic,\n\t\t\t\t\t\t tunnel, local, and remote port\n\t\t\t\t\t\t forwardings.")
	addCmd.PersistentFlags().BoolVarP(&forwardAgent, "forward-agent", "f", false, "Specifies whether the connection\n\t\t\t\t\t\t to the authentication agent\n\t\t\t\t\t\t (if any) will be forwarded to\n\t\t\t\t\t\t the remote machine. Agent\n\t\t\t\t\t\t forwarding should be enabled\n\t\t\t\t\t\t with caution.")
	addCmd.PersistentFlags().BoolVarP(&identitiesOnly, "identities-only", "z", false, "Specifies that ssh should only use\n\t\t\t\t\t\t the authentication identity\n\t\t\t\t\t\t files configured in the\n\t\t\t\t\t\t ssh_config files.")

	addCmd.PersistentFlags().IntVar(&compressionLevel, "compression-level", 0, "Specifies the compression level to use\n\t\t\t\t\t\t if compression is enabled. The\n\t\t\t\t\t\t argument must be an integer\n\t\t\t\t\t\t from 1 (fast) to 9 (slow,\n\t\t\t\t\t\t best). Note that this option\n\t\t\t\t\t\t applies to protocol version 1\n\t\t\t\t\t\t only.")
	addCmd.PersistentFlags().IntVar(&numberOfPasswordPrompts, "number-of-password-prompts", 0, "Specifies the number of password\n\t\t\t\t\t\t prompts before giving up.")
	addCmd.PersistentFlags().IntVar(&serverAliveCountMax, "server-alive-count-max", 0, "Sets the number of server alive\n\t\t\t\t\t\t messages which may be sent\n\t\t\t\t\t\t without ssh receiving any\n\t\t\t\t\t\t messages back from the server.\n\t\t\t\t\t\t If this threshold is reached\n\t\t\t\t\t\t while server alive messages are\n\t\t\t\t\t\t being sent, ssh will disconnect\n\t\t\t\t\t\t from the server, terminating\n\t\t\t\t\t\t the session.")
	addCmd.PersistentFlags().IntVar(&serverAliveInterval, "server-alive-interval", 0, "Sets a timeout interval in seconds\n\t\t\t\t\t\t after which if no data has been\n\t\t\t\t\t\t received from the server, ssh\n\t\t\t\t\t\t will send a message through the\n\t\t\t\t\t\t encrypted channel to request a\n\t\t\t\t\t\t response from the server.")

	addCmd.PersistentFlags().IntVarP(&connectionAttempts, "connection-attempts", "o", 0, "Specifies the number of tries (one per\n\t\t\t\t\t\t second) to make before exiting.")
	addCmd.PersistentFlags().IntVarP(&connectTimeout, "connect-timeout", "t", 0, "Specifies the timeout (in seconds)\n\t\t\t\t\t\t used when connecting to the SSH\n\t\t\t\t\t\t server, instead of using the\n\t\t\t\t\t\t default system TCP timeout.")
	addCmd.PersistentFlags().IntVarP(&port, "port", "p", 0, "Specifies the port number to connect\n\t\t\t\t\t\t on the remote host.")

	addCmd.PersistentFlags().StringVar(&cipher, "cipher", "", "Specifies the cipher to use for\n\t\t\t\t\t\t encrypting the session in\n\t\t\t\t\t\t protocol version 1.")
	addCmd.PersistentFlags().StringVar(&controlMaster, "control-master", "", "Enables the sharing of multiple\n\t\t\t\t\t\t sessions over a single network\n\t\t\t\t\t\t connection.")
	addCmd.PersistentFlags().StringVar(&controlPath, "control-path", "", "Specify the path to the control socket\n\t\t\t\t\t\t used for connection sharing.")
	addCmd.PersistentFlags().StringVar(&dynamicForward, "dynamic-forward", "", "Specifies that a TCP port on the local\n\t\t\t\t\t\t machine be forwarded over the\n\t\t\t\t\t\t secure channel, and the\n\t\t\t\t\t\t application protocol is then\n\t\t\t\t\t\t used to determine where to\n\t\t\t\t\t\t connect to from the\n\t\t\t\t\t\t remote machine.")
	addCmd.PersistentFlags().StringVar(&escapeChar, "escape-char", "", "Sets the escape character.")
	addCmd.PersistentFlags().StringVar(&gssAPIClientIdentity, "gssapi-client-identity", "", "If set, specifies the GSSAPI client\n\t\t\t\t\t\t identity that ssh should use\n\t\t\t\t\t\t when connecting to the server.")
	addCmd.PersistentFlags().StringVar(&hostKeyAlgorithms, "host-key-algorithms", "", "Specifies the protocol version 2 host\n\t\t\t\t\t\t key algorithms that the client\n\t\t\t\t\t\t wants to use in order of\n\t\t\t\t\t\t preference.")
	addCmd.PersistentFlags().StringVar(&hostKeyAlias, "host-key-alias", "", "Specifies an alias that should be used\n\t\t\t\t\t\t instead of the real host name\n\t\t\t\t\t\t when looking up or saving the\n\t\t\t\t\t\t host key in the host key\n\t\t\t\t\t\t database files. This option is\n\t\t\t\t\t\t useful for tunneling SSH\n\t\t\t\t\t\t connections or for multiple\n\t\t\t\t\t\t servers running on a single\n\t\t\t\t\t\t host.")
	addCmd.PersistentFlags().StringVar(&identityFile, "identity-file", "", "Specifies a file from which the user's\n\t\t\t\t\t\t RSA or DSA authentication\n\t\t\t\t\t\t identity is read.")
	addCmd.PersistentFlags().StringVar(&kbdInteractiveDevices, "kbd-interactive-devices", "", "Specifies the list of methods to use\n\t\t\t\t\t\t in keyboard-interactive\n\t\t\t\t\t\t authentication. Multiple method\n\t\t\t\t\t\t names must be comma-separated.")
	addCmd.PersistentFlags().StringVar(&localCommand, "local-command", "", "Specifies a command to execute on the\n\t\t\t\t\t\t local machine after\n\t\t\t\t\t\t successfully connecting to the\n\t\t\t\t\t\t server.")
	addCmd.PersistentFlags().StringVar(&localForward, "local-forward", "", "Specifies that a TCP port on the local\n\t\t\t\t\t\t machine be forwarded over the\n\t\t\t\t\t\t secure channel to the specified\n\t\t\t\t\t\t host and port from the remote\n\t\t\t\t\t\t machine.")
	addCmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "Gives the verbosity level that is\n\t\t\t\t\t\t used when logging messages\n\t\t\t\t\t\t from ssh.")
	addCmd.PersistentFlags().StringVar(&macs, "macs", "", "Specifies the MAC (message\n\t\t\t\t\t\t authentication code) algorithms\n\t\t\t\t\t\t in order of preference. The MAC\n\t\t\t\t\t\t algorithm is used in protocol\n\t\t\t\t\t\t version 2 for data integrity\n\t\t\t\t\t\t protection. Multiple algorithms\n\t\t\t\t\t\t must be comma-separated.")
	addCmd.PersistentFlags().StringVar(&preferredAuthentications, "preferred-auths", "", "Specifies the order in which the\n\t\t\t\t\t\t client should try protocol 2\n\t\t\t\t\t\t authentication methods.")
	addCmd.PersistentFlags().StringVar(&protocol, "protocol", "", "Specifies the protocol versions ssh\n\t\t\t\t\t\t should support in order of\n\t\t\t\t\t\t preference. The possible\n\t\t\t\t\t\t values are '1' and '2'.\n\t\t\t\t\t\t Multiple versions must be\n\t\t\t\t\t\t comma-separated.")
	addCmd.PersistentFlags().StringVar(&proxyCommand, "proxy-command", "", "Specifies the command to use to\n\t\t\t\t\t\t connect to the server.")
	addCmd.PersistentFlags().StringVar(&rekeyLimit, "rekey-limit", "", "Specifies the maximum amount of data\n\t\t\t\t\t\t that may be transmitted\n\t\t\t\t\t\t before the session key is\n\t\t\t\t\t\t renegotiated. The argument is\n\t\t\t\t\t\t the number of bytes, with an\n\t\t\t\t\t\t optional suffix of 'K', 'M', or\n\t\t\t\t\t\t 'G' to indicate Kilobytes,\n\t\t\t\t\t\t Megabytes, or Gigabytes,\n\t\t\t\t\t\t respectively. This option\n\t\t\t\t\t\t applies to protocol version 2\n\t\t\t\t\t\t only.")
	addCmd.PersistentFlags().StringVar(&remoteForward, "remote-forward", "", "Specifies that a TCP port on the\n\t\t\t\t\t\t remote machine be forwarded\n\t\t\t\t\t\t over the secure channel to the\n\t\t\t\t\t\t specified host and port from\n\t\t\t\t\t\t the local machine.")
	addCmd.PersistentFlags().StringVar(&sendEnv, "send-env", "", "Specifies what variables from the\n\t\t\t\t\t\t local environ should be sent\n\t\t\t\t\t\t to the server. Note that\n\t\t\t\t\t\t environment passing is only\n\t\t\t\t\t\t supported for protocol 2.")
	addCmd.PersistentFlags().StringVar(&smartcardDevice, "smartcard-device", "", "Specifies which smartcard device to\n\t\t\t\t\t\t use. The argument to this\n\t\t\t\t\t\t keyword is the device ssh\n\t\t\t\t\t\t should use to communicate\n\t\t\t\t\t\t with a smartcard used for\n\t\t\t\t\t\t storing the user's private RSA\n\t\t\t\t\t\t key.")
	addCmd.PersistentFlags().StringVar(&strictHostkeyChecking, "strict-host-key-checking", "", "If this flag is set to 'yes', ssh will\n\t\t\t\t\t\t never automatically add host\n\t\t\t\t\t\t keys to the ~/.ssh/known_hosts\n\t\t\t\t\t\t file, and refuses to connect to\n\t\t\t\t\t\t hosts whose host key has\n\t\t\t\t\t\t changed. The host keys of known\n\t\t\t\t\t\t hosts will be verified\n\t\t\t\t\t\t automatically in all cases. The\n\t\t\t\t\t\t argument must be 'yes', 'no',\n\t\t\t\t\t\t or 'ask'.")
	addCmd.PersistentFlags().StringVar(&tunnel, "tunnel", "", "Request tun device forwarding between\n\t\t\t\t\t\t the client and the server.\n\t\t\t\t\t\t The argument must be 'yes',\n\t\t\t\t\t\t 'point-to-point' (layer 3),\n\t\t\t\t\t\t 'ethernet' (layer 2), or 'no'.\n\t\t\t\t\t\t Specifying 'yes' requests the\n\t\t\t\t\t\t default tunnel mode, which is\n\t\t\t\t\t\t 'point-to-point'.")
	addCmd.PersistentFlags().StringVar(&tunnelDevice, "tunnel-device", "", "Specifies the tun devices to open on\n\t\t\t\t\t\t the client (local_tun) and the\n\t\t\t\t\t\t server (remote_tun).")
	addCmd.PersistentFlags().StringVar(&userKnownHostsFile, "user-known-hosts-file", "", "Specifies a file to use for the user\n\t\t\t\t\t\t host key database instead of\n\t\t\t\t\t\t ~/.ssh/known_hosts.")
	addCmd.PersistentFlags().StringVar(&verifyHostKeyDNS, "verify-host-key-dns", "", "Specifies whether to verify the remote\n\t\t\t\t\t\t key using DNS and SSHFP\n\t\t\t\t\t\t resource records. The argument\n\t\t\t\t\t\t must be 'yes', 'no', or 'ask'.\n\t\t\t\t\t\t Note that this option applies\n\t\t\t\t\t\t to protocol version 2 only.")
	addCmd.PersistentFlags().StringVar(&xAuthLocation, "x-auth-loc", "", "Specifies the full pathname of the\n\t\t\t\t\t\t xauth program.")

	addCmd.PersistentFlags().StringVarP(&addressFamily, "address-family", "a", "", "Specifies which address family to use\n\t\t\t\t\t\t when connecting.")
	addCmd.PersistentFlags().StringVarP(&bindAddress, "bind-address", "d", "", "Use the specified address on the local\n\t\t\t\t\t\t machine as the source address\n\t\t\t\t\t\t of the connection.")
	addCmd.PersistentFlags().StringVarP(&ciphers, "ciphers", "s", "", "Specifies the ciphers allowed for\n\t\t\t\t\t\t protocol version 2 in order of\n\t\t\t\t\t\t preference. Multiple ciphers\n\t\t\t\t\t\t must be comma-separated. ")
	addCmd.PersistentFlags().StringVarP(&host, "name", "n", "", "The name argument sets the name which\n\t\t\t\t\t\t should be provided to sshd when\n\t\t\t\t\t\t connecting to the remote host.")
	addCmd.PersistentFlags().StringVarP(&hostname, "hostname", "r", "", "Specifies the real host name to log\n\t\t\t\t\t\t into. This can be used to\n\t\t\t\t\t\t specify nicknames or\n\t\t\t\t\t\t abbreviations for hosts. The\n\t\t\t\t\t\t default is the name given on\n\t\t\t\t\t\t the command line. Numeric IP\n\t\t\t\t\t\t addresses are also permitted.")
	addCmd.PersistentFlags().StringVarP(&username, "user", "u", "", "The remote username to connect as.")
	addCmd.PersistentFlags().StringVarP(&writeToFile, "write", "w", "", "Write the output of the tool to the\n\t\t\t\t\t\t specified file path in addition\n\t\t\t\t\t\t to stdout.")
}
