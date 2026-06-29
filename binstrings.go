package main

import (
	"os"
)

func extractFromBinary(binPath string) (string, error) {
	data, err := os.ReadFile(binPath)
	if err != nil {
		return "", err
	}
	return findChromeVersion(data), nil
}

func findChromeVersion(data []byte) string {
	matches := chromeStringRe.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return ""
	}

	counts := map[string]int{}
	for _, m := range matches {
		counts[string(m[1])]++
	}

	var best string
	var bestCount int
	for v, c := range counts {
		if c > bestCount {
			best = v
			bestCount = c
		}
	}
	return best
}
