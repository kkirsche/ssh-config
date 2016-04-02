package sshConfig

// ValidAddressFamilyAnswers contains valid values for the SSH Configuration AddressFamily enty
func ValidAddressFamilyAnswers() []string {
	return []string{"", "any", "inet", "inet6"}
}

// ValidYesOrNo is used when validating input which should have an answer of
// yes or no. A blank value is included to account for default string values
// when nothing is passed in
func ValidYesOrNo() []string {
	return []string{"", "yes", "no"}
}

// ValidStringArgs is used to validate arguments provided to sshConfig via
// the command line.
func ValidStringArgs(possibilities []string, received string) bool {
	for _, possible := range possibilities {
		if possible == received {
			return true
		}
	}
	return false
}
