package main

import (
	"strings"
	"testing"
)

func TestInstallerCommandLineIsSilentAndLeavesDFlagLast(t *testing.T) {
	got := installerCommandLine(`C:\Temp\EduShield Installer.exe`, `D:\Tools\EduShield App`)
	want := `"C:\Temp\EduShield Installer.exe" /S /D=D:\Tools\EduShield App`
	if got != want {
		t.Fatalf("installerCommandLine = %q, want %q", got, want)
	}
	if !strings.HasSuffix(got, `/D=D:\Tools\EduShield App`) {
		t.Fatalf("/D= must be the final unquoted NSIS token, got %q", got)
	}
}
