package sshConfig

// SSHConfigurationEntry represents the data which can be used to generate an
// SSH Configuration File Entry.
type SSHConfigurationEntry struct {
	AddressFamily                   string
	BatchMode                       string
	BindAddress                     string
	ChallengeResponseAuthentication string
	CheckHostIP                     string
	Ciphers                         string
	Compression                     string
	CompressionLevel                int
	ConnectionAttempts              int
	ConnectTimeout                  int
	ExitOnForwardFailure            string
	ForwardAgent                    string
	IdentitiesOnly                  string
	IdentityFile                    string
	Host                            string
	Hostname                        string
	Port                            int
	User                            string
}

const (
	// SSHConfigurationEntryTemplate holds the text template used to generate a
	// new SSH configuration file entry.
	SSHConfigurationEntryTemplate = `Host {{ .Host}}
{{- if  .AddressFamily }}{{ print "\n" }}AddressFamily {{.AddressFamily}}{{- end}}
{{- if  .BatchMode }}{{ print "\n" }}BatchMode {{.BatchMode}} # Valid options: yes or no. Default: no.{{- end }}
{{- if  .BindAddress }}{{ print "\n" }}BindAddress {{.BindAddress}}{{- end}}
{{- if  .ChallengeResponseAuthentication }}{{ print "\n" }}ChallengeResponseAuthentication {{.ChallengeResponseAuthentication}} # Valid options: yes or no. Default: yes{{- end}}
{{- if  .CheckHostIP }}{{ print "\n" }}CheckHostIP {{.CheckHostIP}} # Valid options: yes or no. Default: yes{{- end}}
{{- if  .Ciphers }}{{ print "\n" }}Ciphers {{.Ciphers}}{{- end}}
{{- if  .Compression }}{{ print "\n" }}Compression {{.Compression}} # Valid options: yes or no. Default: no{{- end}}
{{- if  .ConnectionAttempts }}{{ print "\n" }}ConnectionAttempts {{.ConnectionAttempts}}{{- end}}
{{- if  .ConnectTimeout }}{{ print "\n" }}ConnectTimeout {{.ConnectTimeout}} # In seconds{{- end}}
{{- if  .DynamicForward }}{{ print "\n" }}DynamicForward {{.DynamicForward}}{{- end}}
{{- if  .ExitOnForwardFailure }}{{ print "\n" }}ExitOnForwardFailure {{.ExitOnForwardFailure}} # Valid options: yes or no. Default: no{{- end}}
{{- if  .ForwardAgent }}{{ print "\n" }}ForwardAgent {{.ForwardAgent}} # Valid options: yes or no. Default: no{{- end}}
{{- if  .IdentitiesOnly }}{{ print "\n" }}IdentitiesOnly {{.IdentitiesOnly}} # Default: no{{- end}}
{{- if  .IdentityFile }}{{ print "\n" }}IdentityFile {{.IdentityFile}}{{- end}}
{{- if  .Hostname }}{{ print "\n" }}Hostname {{.Hostname}}{{- end}}
{{- if  .Port }}{{ print "\n" }}Port {{.Port}}{{- end}}
{{- if  .User }}{{ print "\n" }}User {{.}}{{- end}}
`
)
