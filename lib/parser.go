package sshConfig

import (
	"regexp"
	"strings"
)

func isLineNewHost(line string) bool {
	isNewHost := false
	lowercaseLine := strings.ToLower(line)

	hostRegexp := regexp.MustCompile(`(\s*)?host\s`)
	if hostRegexp.FindString(lowercaseLine) != "" {
		isNewHost = true
	}

	return isNewHost
}
