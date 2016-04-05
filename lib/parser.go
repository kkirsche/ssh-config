package sshConfig

import (
	"regexp"
	"strings"
)

// IsLineNewHost returns a boolean value stating the new host on this line,
// otherwise this returns an empty string.
func IsLineNewHost(line string) string {
	trimmedSplitLine := strings.Split(strings.TrimSpace(line), " ")

	hostRegexp := regexp.MustCompile(`host`)

	var foundHost bool
	var newHostArray []string
	for _, word := range trimmedSplitLine {
		if foundHost {
			newHostArray = append(newHostArray, word)
		} else {
			match := hostRegexp.FindStringIndex(strings.ToLower(word))
			if match != nil {
				foundHost = true
			}
		}
	}

	return strings.Join(newHostArray, "_")
}
