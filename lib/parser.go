package sshConfig

import (
	"regexp"
	"strings"
)

// FindHost returns a string value corresponding to the new SSH host on this
// line, otherwise this returns an empty string.
func FindHost(line string) string {
	hostRegexp := regexp.MustCompile(`host`)
	hostMatch := ExtractValueRegexp(line, hostRegexp)
	return hostMatch
}

// ExtractValueRegexp extracts the value using a regular expression returning
// values extracted after the first match of the regexp.
func ExtractValueRegexp(line string, regex *regexp.Regexp) string {
	var found bool
	var valueArray []string
	splitLine := strings.Split(strings.TrimSpace(line), " ")
	for _, word := range splitLine {
		if found {
			valueArray = append(valueArray, word)
		} else {
			match := regex.FindStringIndex(strings.ToLower(word))
			if match != nil {
				found = true
			}
		}
	}

	return strings.Join(valueArray, " ")
}
