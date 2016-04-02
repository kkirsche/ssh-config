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
{{- if  .Ciphers }}{{ print "\n" }}Ciphers {{.Ciphers}}{{- end}}
{{- if  .Compression }}{{ print "\n" }}Compression {{.Compression}}{{- end}}
{{- if  .ConnectionAttempts }}{{ print "\n" }}ConnectionAttempts {{.ConnectionAttempts}}{{- end}}
{{- if  .ConnectTimeout }}{{ print "\n" }}ConnectTimeout {{.ConnectTimeout}} # In seconds{{- end}}
{{- if  .ExitOnForwardFailure }}{{ print "\n" }}ExitOnForwardFailure {{.ExitOnForwardFailure}}{{- end}}
{{- if  .ForwardAgent }}{{ print "\n" }}ForwardAgent {{.ForwardAgent}}{{- end}}
{{- if  .IdentitiesOnly }}{{ print "\n" }}IdentitiesOnly {{.IdentitiesOnly}}{{- end}}
{{- if  .IdentityFile }}{{ print "\n" }}IdentityFile {{.IdentityFile}}{{- end}}
{{- if  .Hostname }}{{ print "\n" }}Hostname {{.Hostname}}{{- end}}
{{- if  .Port }}{{ print "\n" }}Port {{.Port}}{{- end}}
{{- if  .User }}{{ print "\n" }}User {{.User}}{{- end}}
`
)
