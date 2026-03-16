// Package hushspec provides parsing, validation, merging, and evaluation of
// HushSpec security policy documents.
package hushspec

const Version = "0.1.0"

var SupportedVersions = []string{"0.1.0"}

// IsSupported reports whether the given schema version is handled by this SDK.
func IsSupported(version string) bool {
	for _, v := range SupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}
