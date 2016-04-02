package sshConfig

const (
	// SSHConfigurationEntryTemplate holds the text template used to generate a
	// new SSH configuration file entry.
	SSHConfigurationEntryTemplate = `Host {{ .Host}}
{{- if  .AddressFamily }}{{ print "\n" }}AddressFamily {{.AddressFamily}}{{- end}}
{{- if  .BatchMode }}{{ print "\n" }}BatchMode {{.BatchMode}}{{- end }}
{{- if  .BindAddress }}{{ print "\n" }}BindAddress {{.BindAddress}}{{- end}}
{{- if  .ChallengeResponseAuthentication }}{{ print "\n" }}ChallengeResponseAuthentication {{.ChallengeResponseAuthentication}}{{- end}}
{{- if  .CheckHostIP }}{{ print "\n" }}CheckHostIP {{.CheckHostIP}}{{- end}}
{{- if  .Cipher }}{{ print "\n" }}Cipher {{.Cipher}}{{- end}}
{{- if  .Ciphers }}{{ print "\n" }}Ciphers {{.Ciphers}}{{- end}}
{{- if  .ClearAllForwardings }}{{ print "\n" }}ClearAllForwardings {{.ClearAllForwardings}}{{- end}}
{{- if  .Compression }}{{ print "\n" }}Compression {{.Compression}}{{- end}}
{{- if  .CompressionLevel }}{{ print "\n" }}CompressionLevel {{.CompressionLevel}}{{- end}}
{{- if  .ConnectionAttempts }}{{ print "\n" }}ConnectionAttempts {{.ConnectionAttempts}}{{- end}}
{{- if  .ConnectTimeout }}{{ print "\n" }}ConnectTimeout {{.ConnectTimeout}} # In seconds{{- end}}
{{- if  .ControlMaster }}{{ print "\n" }}ControlMaster {{.ControlMaster}}{{- end}}
{{- if  .ControlPath }}{{ print "\n" }}ControlPath {{.ControlPath}}{{- end}}
{{- if  .DynamicForward }}{{ print "\n" }}DynamicForward {{.DynamicForward}}{{- end}}
{{- if  .EnableSSHKeysign }}{{ print "\n" }}EnableSSHKeysign {{.EnableSSHKeysign}}{{- end}}
{{- if  .EscapeChar }}{{ print "\n" }}EscapeChar {{.EscapeChar}}{{- end}}
{{- if  .ExitOnForwardFailure }}{{ print "\n" }}ExitOnForwardFailure {{.ExitOnForwardFailure}}{{- end}}
{{- if  .ForwardAgent }}{{ print "\n" }}ForwardAgent {{.ForwardAgent}}{{- end}}
{{- if  .ForwardX11 }}{{ print "\n" }}ForwardX11 {{.ForwardX11}}{{- end}}
{{- if  .ForwardX11Trusted }}{{ print "\n" }}ForwardX11Trusted {{.ForwardX11Trusted}}{{- end}}
{{- if  .GatewayPorts }}{{ print "\n" }}GatewayPorts {{.GatewayPorts}}{{- end}}
{{- if  .GSSAPIAuthentication }}{{ print "\n" }}GSSAPIAuthentication {{.GSSAPIAuthentication}}{{- end}}
{{- if  .GSSAPIKeyExchange }}{{ print "\n" }}GSSAPIKeyExchange {{.GSSAPIKeyExchange}}{{- end}}
{{- if  .GSSAPIClientIdentity }}{{ print "\n" }}GSSAPIClientIdentity {{.GSSAPIClientIdentity}}{{- end}}
{{- if  .GSSAPIDelegateCredentials }}{{ print "\n" }}GSSAPIDelegateCredentials {{.GSSAPIDelegateCredentials}}{{- end}}
{{- if  .GSSAPIRenewalForcesRekey }}{{ print "\n" }}GSSAPIRenewalForcesRekey {{.GSSAPIRenewalForcesRekey}}{{- end}}
{{- if  .GSSAPIRenewalForcesRekey }}{{ print "\n" }}GSSAPIRenewalForcesRekey {{.GSSAPIRenewalForcesRekey}}{{- end}}
{{- if  .GSSAPITrustDNS }}{{ print "\n" }}GSSAPITrustDns {{.GSSAPITrustDNS}}{{- end}}
{{- if  .HashKnownHosts }}{{ print "\n" }}HashKnownHosts {{.HashKnownHosts}}{{- end}}
{{- if  .HostbasedAuthentication }}{{ print "\n" }}HostbasedAuthentication {{.HostbasedAuthentication}}{{- end}}
{{- if  .HostKeyAlgorithms }}{{ print "\n" }}HostKeyAlgorithms {{.HostKeyAlgorithms}}{{- end}}
{{- if  .HostKeyAlias }}{{ print "\n" }}HostKeyAlias {{.HostKeyAlias}}{{- end}}
{{- if  .Hostname }}{{ print "\n" }}Hostname {{.Hostname}}{{- end}}
{{- if  .IdentitiesOnly }}{{ print "\n" }}IdentitiesOnly {{.IdentitiesOnly}}{{- end}}
{{- if  .IdentityFile }}{{ print "\n" }}IdentityFile {{.IdentityFile}}{{- end}}
{{- if  .KBDInteractiveAuthentication }}{{ print "\n" }}KbdInteractiveAuthentication {{.KBDInteractiveAuthentication}}{{- end}}
{{- if  .KBDInteractiveDevices }}{{ print "\n" }}KbdInteractiveDevices {{.KBDInteractiveDevices}}{{- end}}
{{- if  .LocalCommand }}{{ print "\n" }}LocalCommand {{.LocalCommand}}{{- end}}
{{- if  .LocalForward }}{{ print "\n" }}LocalForward {{.LocalForward}}{{- end}}
{{- if  .LogLevel }}{{ print "\n" }}LogLevel {{.LogLevel}}{{- end}}
{{- if  .MACs }}{{ print "\n" }}MACs {{.MACs}}{{- end}}
{{- if  .NoHostAuthenticationForLocalhost }}{{ print "\n" }}NoHostAuthenticationForLocalhost {{.NoHostAuthenticationForLocalhost}}{{- end}}
{{- if  .NumberOfPasswordPrompts }}{{ print "\n" }}NumberOfPasswordPrompts {{.NumberOfPasswordPrompts}}{{- end}}
{{- if  .PasswordAuthentication }}{{ print "\n" }}PasswordAuthentication {{.PasswordAuthentication}}{{- end}}
{{- if  .PermitLocalCommand }}{{ print "\n" }}PermitLocalCommand {{.PermitLocalCommand}}{{- end}}
{{- if  .Port }}{{ print "\n" }}Port {{.Port}}{{- end}}
{{- if  .PreferredAuthentications }}{{ print "\n" }}PreferredAuthentications {{.PreferredAuthentications}}{{- end}}
{{- if  .Protocol }}{{ print "\n" }}Protocol {{.Protocol}}{{- end}}
{{- if  .ProxyCommand }}{{ print "\n" }}ProxyCommand {{.ProxyCommand}}{{- end}}
{{- if  .PubkeyAuthentication }}{{ print "\n" }}PubkeyAuthentication {{.PubkeyAuthentication}}{{- end}}
{{- if  .RekeyLimit }}{{ print "\n" }}RekeyLimit {{.RekeyLimit}}{{- end}}
{{- if  .RemoteForward }}{{ print "\n" }}RemoteForward {{.RemoteForward}}{{- end}}
{{- if  .RhostsRSAAuthentication }}{{ print "\n" }}RhostsRSAAuthentication {{.RhostsRSAAuthentication}}{{- end}}
{{- if  .RSAAuthentication }}{{ print "\n" }}RSAAuthentication {{.RSAAuthentication}}{{- end}}
{{- if  .SendEnv }}{{ print "\n" }}SendEnv {{.SendEnv}}{{- end}}
{{- if  .ServerAliveCountMax }}{{ print "\n" }}ServerAliveCountMax {{.ServerAliveCountMax}}{{- end}}
{{- if  .ServerAliveInterval }}{{ print "\n" }}ServerAliveInterval {{.ServerAliveInterval}}{{- end}}
{{- if  .SmartcardDevice }}{{ print "\n" }}SmartcardDevice {{.SmartcardDevice}}{{- end}}
{{- if  .StrictHostKeyChecking }}{{ print "\n" }}StrictHostKeyChecking {{.StrictHostKeyChecking}}{{- end}}
{{- if  .TCPKeepAlive }}{{ print "\n" }}TCPKeepAlive {{.TCPKeepAlive}}{{- end}}
{{- if  .Tunnel }}{{ print "\n" }}Tunnel {{.Tunnel}}{{- end}}
{{- if  .TunnelDevice }}{{ print "\n" }}TunnelDevice {{.TunnelDevice}}{{- end}}
{{- if  .UsePrivilegedPort }}{{ print "\n" }}UsePrivilegedPort {{.UsePrivilegedPort}}{{- end}}
{{- if  .User }}{{ print "\n" }}User {{.User}}{{- end}}
{{- if  .UserKnownHostsFile }}{{ print "\n" }}UserKnownHostsFile {{.UserKnownHostsFile}}{{- end}}
{{- if  .VisualHostKey }}{{ print "\n" }}VisualHostKey {{.VisualHostKey}}{{- end}}
{{- if  .XAuthLocation }}{{ print "\n" }}XAuthLocation {{.XAuthLocation}}{{- end}}
`
)
