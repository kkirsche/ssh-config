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
	writeToFile                  bool

	addressFamily            string
	bindAddress              string
	cipher                   string
	ciphers                  string
	controlMaster            string
	controlPath              string
	dynamicForward           string
	escapeChar               string
	gssAPIClientIdentity     string
	host                     string
	hostKeyAlgorithms        string
	hostKeyAlias             string
	hostname                 string
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
	tunnel                   string
	tunnelDevice             string
	userKnownHostsFile       string
	username                 string
	verifyHostKeyDNS         string
	xAuthLocation            string

	compressionLevel        int
	connectionAttempts      int
	connectTimeout          int
	numberOfPasswordPrompts int
	port                    int
	serverAliveCountMax     int
	serverAliveInterval     int
)

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

		if challengeRespAuth {
			config.ChallengeResponseAuthentication = yes
		}

		if checkHostIP {
			config.CheckHostIP = yes
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
			err := t.Execute(os.Stdout, config)
			if err != nil {
				logger.Errorf("\nCouldn't execute SSH Configuration Template with error: %s", err.Error())
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
	addCmd.PersistentFlags().BoolVarP(&identitiesOnly, "identities-only", "z", false, "Specifies that ssh should only use the\n\t\t\t\t\t authentication identity files\n\t\t\t\t\t configured in the ssh_config files,\n\t\t\t\t\t even if ssh-agent offers more\n\t\t\t\t\t identities. The argument to this\n\t\t\t\t\t keyword must be 'yes' or 'no'. This\n\t\t\t\t\t option is intended for situations\n\t\t\t\t\t where ssh-agent offers many different\n\t\t\t\t\t identities. The default is 'no'.")

	// Define the flags that do not have short versions :(
	addCmd.PersistentFlags().StringVar(&cipher, "cipher", "", "Specifies the cipher to use for encrypting the session in protocol version 1. Currently, 'blowfish', '3des', and 'des' are supported. des is only supported in the ssh client for interoperability with legacy protocol 1 implementations that do not support the 3des cipher. Its use is strongly discouraged due to cryptographic weaknesses. The default is '3des'.")
	addCmd.PersistentFlags().StringVar(&identityFile, "identity-file", "", "Specifies a file from which the user's RSA or DSA authentication identity is read.")
	addCmd.PersistentFlags().BoolVar(&clearAllForwardings, "clear-all-forwardings", false, "Specifies that all local, remote, and dynamic port forwardings specified in the configuration files or on the command line be cleared. This option is primarily useful when used from the ssh command line to clear port forwardings set in configuration files, and is automatically set by scp and sftp.")
	addCmd.PersistentFlags().BoolVar(&forwardX11, "forward-x11", false, "Specifies whether X11 connections will be automatically redirected over the secure channel and DISPLAY set.")
	addCmd.PersistentFlags().BoolVar(&forwardX11Trusted, "forward-x11-trusted", false, "If this option is enabled, remote X11 clients will have full access to the original X11 display.")
	addCmd.PersistentFlags().BoolVar(&gatewayPorts, "gateway-ports", false, "Specifies whether remote hosts are allowed to connect to local forwarded ports. By default, ssh binds local port forwardings to the loopback address. This prevents other remote hosts from connecting to forwarded ports.")
	addCmd.PersistentFlags().BoolVar(&gssAPIAuthentication, "gssapi-authentication", false, "Specifies whether user authentication based on GSSAPI is allowed.")
	addCmd.PersistentFlags().BoolVar(&gssAPIDelegateCredentials, "gssapi-delegate-credentials", false, "Forward (delegate) credentials to the server.")
	addCmd.PersistentFlags().BoolVar(&gssAPIKeyExchange, "gssapi-key-exchange", false, "Specifies whether key exchange based on GSSAPI may be used. When using GSSAPI key exchange the server need not have a host key.")
	addCmd.PersistentFlags().BoolVar(&gssAPIRenewalForcesRekey, "gssapi-renewal-forces-rekey", false, "If enabled, then renewal of the client's GSSAPI credentials will force the rekeying of the ssh connection. With a compatible server, this can delegate the renewed credentials to a session on the server.")
	addCmd.PersistentFlags().BoolVar(&gssAPITrustDNS, "gssapi-trust-dns", false, "Enable this feature to indicate that the DNS is trusted to securely canonicalize' the name of the host being connected to.")
	addCmd.PersistentFlags().StringVar(&gssAPIClientIdentity, "gssapi-client-identity", "", "If set, specifies the GSSAPI client identity that ssh should use when connecting to the server. The default is unset, which means that the default identity will be used.")
	addCmd.PersistentFlags().BoolVar(&hashKnownHosts, "hash-known-hosts", false, "Indicates that ssh should hash host names and addresses when they are added to ~/.ssh/known_hosts. These hashed names may be used normally by ssh and sshd(8), but they do not reveal identifying information should the file's contents be disclosed.")
	addCmd.PersistentFlags().BoolVar(&kbdInteractiveAuthentication, "kbd-interactive-auth", false, "Specifies whether to use keyboard-interactive authentication.")
	addCmd.PersistentFlags().BoolVar(&passwordAuthentication, "password-auth", false, "Specifies whether to use password authentication.")
	addCmd.PersistentFlags().BoolVar(&permitLocalCommand, "permit-local-cmd", false, "Allow local command execution via the LocalCommand option or using the !command escape sequence in ssh.")
	addCmd.PersistentFlags().BoolVar(&publicKeyAuthentication, "public-key-auth", false, "Specifies whether to try public key authentication.")
	addCmd.PersistentFlags().BoolVar(&rhostsRSAAuthentication, "rhosts-rsa-auth", false, "Specifies whether to try rhosts based authentication with RSA host authentication.")
	addCmd.PersistentFlags().BoolVar(&rsaAuthentication, "rsa-auth", false, "Specifies whether to try RSA authentication. RSA authentication will only be attempted if the identity file exists, or an authentication agent is running. Note that this option applies to protocol version 1 only.")
	addCmd.PersistentFlags().BoolVar(&tcpKeepAlive, "tcp-keepalive", false, "Specifies whether the system should send TCP keepalive messages to the other side. If they are sent, death of the connection or crash of one of the machines will be properly noticed. However, this means that connections will die if the route is down temporarily, and some people find it annoying.")
	addCmd.PersistentFlags().BoolVar(&usePrivilegedPort, "use-priviledged-port", false, "Specifies whether to use a privileged port for outgoing connections. If enabled, ssh must be setuid root.")
	addCmd.PersistentFlags().BoolVar(&visualHostKey, "visual-hostkey", false, "If enabled, an ASCII art representation of the remote host key fingerprint is printed in addition to the hex fingerprint string at login and for unknown host keys.")
	addCmd.PersistentFlags().StringVar(&hostBasedAuth, "host-based-auth", "", "Specifies whether to try rhosts based authentication with public key authentication.")
	addCmd.PersistentFlags().StringVar(&controlMaster, "control-master", "", "Enables the sharing of multiple sessions over a single network connection.")
	addCmd.PersistentFlags().StringVar(&controlPath, "control-path", "", "Specify the path to the control socket used for connection sharing as described in the ControlMaster section above or the string 'none' to disable connection sharing.")
	addCmd.PersistentFlags().StringVar(&dynamicForward, "dynamic-forward", "", "Specifies that a TCP port on the local machine be forwarded over the secure channel, and the application protocol is then used to determine where to connect to from the remote machine.")
	addCmd.PersistentFlags().StringVar(&escapeChar, "escape-char", "", "Sets the escape character.")
	addCmd.PersistentFlags().StringVar(&hostKeyAlgorithms, "host-key-algorithms", "", "Specifies the protocol version 2 host key algorithms that the client wants to use in order of preference.")
	addCmd.PersistentFlags().StringVar(&hostKeyAlias, "host-key-alias", "", "Specifies an alias that should be used instead of the real host name when looking up or saving the host key in the host key database files. This option is useful for tunneling SSH connections or for multiple servers running on a single host.")
	addCmd.PersistentFlags().StringVar(&kbdInteractiveDevices, "kbd-interactive-devices", "", "Specifies the list of methods to use in keyboard-interactive authentication. Multiple method names must be comma-separated.")
	addCmd.PersistentFlags().StringVar(&localCommand, "local-command", "", "Specifies a command to execute on the local machine after successfully connecting to the server.")
	addCmd.PersistentFlags().StringVar(&localForward, "local-forward", "", "Specifies that a TCP port on the local machine be forwarded over the secure channel to the specified host and port from the remote machine.")
	addCmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "Gives the verbosity level that is used when logging messages from ssh. The possible values are: QUIET, FATAL, ERROR, INFO, VERBOSE, DEBUG, DEBUG1, DEBUG2, and DEBUG3.")
	addCmd.PersistentFlags().StringVar(&macs, "macs", "", "Specifies the MAC (message authentication code) algorithms in order of preference. The MAC algorithm is used in protocol version 2 for data integrity protection. Multiple algorithms must be comma-separated.")
	addCmd.PersistentFlags().StringVar(&preferredAuthentications, "preferred-auths", "", "Specifies the order in which the client should try protocol 2 authentication methods. This allows a client to prefer one method (e.g. keyboard-interactive) over another method (e.g. password).")
}
