package main

import (
	"fmt"
	"os"
	"testing"
)

func TestResolveURLVersionLive(t *testing.T) {
	if os.Getenv("HUNTER_NET_TESTS") == "" {
		t.Skip("set HUNTER_NET_TESTS=1 to run live network tests")
	}
	for _, u := range []string{
		"https://central.github.com/deployments/desktop/desktop/latest/darwin?format=zip",
		"https://update.code.visualstudio.com/latest/darwin-universal/stable",
		"https://desktop.figma.com/mac/Figma.zip",
		"https://desktop.clickup.com/mac",
		"https://slack.com/ssb/download-osx-universal",
	} {
		fmt.Printf("%-70s => %q\n", u, resolveURLVersion(u))
	}
}

func TestResolveVersionAPILive(t *testing.T) {
	if os.Getenv("HUNTER_NET_TESTS") == "" {
		t.Skip("set HUNTER_NET_TESTS=1 to run live network tests")
	}
	v := resolveVersionAPI("https://update.code.visualstudio.com/api/update/darwin-universal/stable/latest")
	fmt.Printf("vs code api => %q\n", v)
	if v == "" {
		t.Error("VS Code productVersion not extracted")
	}
}

func TestExtractVersionToken(t *testing.T) {
	cases := map[string]string{
		"https://desktop.githubusercontent.com/releases/3.6.4-28955b81/GitHubDesktop-x64.zip": "3.6.4",
		"https://github.com/signalapp/Signal-Desktop/releases/download/v7.6.1/signal-desktop-macos-7.6.1.dmg": "7.6.1",
		"https://desktop.figma.com/mac/Figma.zip":     "",
		"https://updates.framer.com/electron/darwin/arm64/Framer.zip": "",
		"https://dl.pstmn.io/download/latest/osx":     "",
		"https://cdn.example.com/builds/20260818/app.dmg": "",
	}
	for u, want := range cases {
		if got := extractVersionToken(u); got != want {
			t.Errorf("extractVersionToken(%s) = %q, want %q", u, got, want)
		}
	}
}