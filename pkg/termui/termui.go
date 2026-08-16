// Package termui contains the small terminal presentation helpers shared by
// the command-line clients.  It deliberately has no external dependencies so
// redirected output and Windows builds keep the same behavior.
package termui

import (
	"io"
	"os"
	"strings"
	"sync"
)

const (
	Reset   = "\x1b[0m"
	Bold    = "\x1b[1m"
	Dim     = "\x1b[2m"
	Red     = "\x1b[31m"
	Green   = "\x1b[32m"
	Yellow  = "\x1b[33m"
	Blue    = "\x1b[34m"
	Magenta = "\x1b[35m"
	Cyan    = "\x1b[36m"
	White   = "\x1b[37m"
)

// Enabled reports whether ANSI presentation should be used for the writer.
// NO_COLOR and TERM=dumb are honored so logs remain suitable for pipes and
// automation. Tests and other in-memory writers are intentionally uncolored.
func Enabled(w io.Writer) bool {
	if w == nil || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// Paint wraps text in an ANSI style only when enabled.
func Paint(style, text string, enabled bool) string {
	if !enabled || text == "" {
		return text
	}
	return style + text + Reset
}

// ColorizeCLI applies restrained semantic colors to ordinary CLI output.
// Richer views such as the ping graph paint their individual cells directly.
func ColorizeCLI(text string, enabled bool) string {
	if !enabled || text == "" {
		return text
	}

	var b strings.Builder
	lines := strings.SplitAfter(text, "\n")
	for _, line := range lines {
		body, newline := line, ""
		if strings.HasSuffix(body, "\n") {
			body = strings.TrimSuffix(body, "\n")
			newline = "\n"
		}
		if strings.HasSuffix(body, "\r") {
			body = strings.TrimSuffix(body, "\r")
			newline = "\r" + newline
		}
		if body == "" {
			b.WriteString(line)
			continue
		}

		style := ""
		lower := strings.ToLower(body)
		switch {
		case strings.Contains(body, "Error:"), strings.Contains(body, "Unknown command"), strings.Contains(lower, "failed"):
			style = Red
		case strings.Contains(lower, "warning"), strings.Contains(lower, "offline"), strings.Contains(lower, "idle"), strings.Contains(body, "N/A"):
			style = Yellow
		case strings.Contains(body, "Left4Proxy"), strings.Contains(body, "Commands:"), strings.HasPrefix(body, "===="):
			style = Bold + Cyan
		case strings.HasPrefix(body, "[CLI]"):
			style = Cyan
		case strings.Contains(lower, "active"), strings.Contains(lower, "online"), strings.Contains(lower, "connected"), strings.Contains(lower, "enabled"), strings.Contains(lower, "successfully"):
			style = Green
		}
		if style != "" {
			b.WriteString(style)
			b.WriteString(body)
			b.WriteString(Reset)
		} else {
			b.WriteString(body)
		}
		b.WriteString(newline)
	}
	return b.String()
}

// ColorizeLogLine gives standard log output a stable color by severity and
// subsystem. The complete line is wrapped so timestamps and prefixes stay
// visually grouped in a busy terminal.
func ColorizeLogLine(line string, enabled bool) string {
	if !enabled || line == "" {
		return line
	}
	lower := strings.ToLower(line)
	style := ""
	switch {
	case strings.Contains(lower, "error"), strings.Contains(lower, "failed"), strings.Contains(lower, "invalid"):
		style = Red
	case strings.Contains(lower, "warning"), strings.Contains(lower, "offline"), strings.Contains(lower, "unreachable"):
		style = Yellow
	case strings.Contains(line, "[Server]"):
		style = Blue
	case strings.Contains(line, "[Config]"):
		style = Magenta
	case strings.Contains(line, "[UPnP]"):
		style = Yellow
	case strings.Contains(line, "[Client]"):
		style = Green
	default:
		style = Dim
	}
	return style + line + Reset
}

type colorLogWriter struct {
	dst     io.Writer
	enabled bool
	mu      sync.Mutex
}

// NewColorLogWriter returns an io.Writer suitable for log.SetOutput.
func NewColorLogWriter(dst io.Writer) io.Writer {
	return &colorLogWriter{dst: dst, enabled: Enabled(dst)}
}

func (w *colorLogWriter) Write(p []byte) (int, error) {
	if w == nil || w.dst == nil {
		return 0, io.ErrClosedPipe
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	input := string(p)
	if !w.enabled {
		return w.dst.Write(p)
	}
	parts := strings.SplitAfter(input, "\n")
	var b strings.Builder
	for _, part := range parts {
		if part == "" {
			continue
		}
		body, suffix := part, ""
		if strings.HasSuffix(body, "\n") {
			body = strings.TrimSuffix(body, "\n")
			suffix = "\n"
		}
		b.WriteString(ColorizeLogLine(body, true))
		b.WriteString(suffix)
	}
	if _, err := io.WriteString(w.dst, b.String()); err != nil {
		return 0, err
	}
	return len(p), nil
}
