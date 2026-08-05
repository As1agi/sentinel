package utils

import (
	"strings"
)

func RemoveBraces(input string) string {
	// Chain ReplaceAll to target different types of braces
	noBraces := strings.ReplaceAll(input, "{", "")
	noBraces = strings.ReplaceAll(noBraces, "}", "")
	noBraces = strings.ReplaceAll(noBraces, "(", "")
	noBraces = strings.ReplaceAll(noBraces, ")", "")
	noBraces = strings.ReplaceAll(noBraces, "[", "")
	noBraces = strings.ReplaceAll(noBraces, "]", "")

	return noBraces
}
