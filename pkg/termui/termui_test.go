package termui

import (
	"bytes"
	"strings"
	"testing"
)

func TestColorLogWriterColorsBySubsystem(t *testing.T) {
	var out bytes.Buffer
	writer := &colorLogWriter{dst: &out, enabled: true}
	if _, err := writer.Write([]byte("2026/08/16 [Client] Connected\n")); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	result := out.String()
	if !strings.Contains(result, Green+"2026/08/16 [Client] Connected"+Reset+"\n") {
		t.Fatalf("client log was not colored: %q", result)
	}
}

func TestColorizeCLILeavesDisabledOutputPlain(t *testing.T) {
	const input = "[CLI] hello\n"
	if got := ColorizeCLI(input, false); got != input {
		t.Fatalf("disabled CLI output changed: %q", got)
	}
}
