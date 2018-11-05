package pack

import (
	"regexp"
	"strings"
)

// VersionRegexMatch determines whether v1 is a version matching v2 by treating
// v1 as a regular expression and matching it against v2.
func VersionRegexMatch(v1, v2 string) Found {
	re := regexp.MustCompile(v1)
	return Found(re.MatchString(v2))
}

// VersionIsPrefx determines whether v1 is a version matching v2 by checking
// if v1 is a prefix of v2.
func VersionIsPrefix(v1, v2 string) Found {
	return Found(strings.HasPrefix(v2, v1))
}

// VersionIsSuffix determines whether v1 is a version matching v2 by checkin
// if v1 is a suffix of v2.
func VersionIsSuffix(v1, v2 string) Found {
	return Found(strings.HasSuffix(v2, v1))
}
