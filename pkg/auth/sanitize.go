package auth

import (
	"strings"
	"unicode/utf8"
)

const (
	maxCodeLen        = 64
	maxDescriptionLen = 300
	maxURILen         = 512
	maxScopeLen       = 4096
	maxUserCodeLen    = 64
)

// sanitize makes a server-controlled string safe to print to a terminal or a
// log: it drops C0 and C1 control characters (so no ANSI/OSC escape sequence
// survives), DEL, and the Unicode bidirectional overrides that can make text
// read differently from what it is, then truncates to max runes.
func sanitize(s string, maxRunes int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		if isUnsafeRune(r) {
			continue
		}
		if n == maxRunes {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

func isUnsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f:
		return true
	}
	return false
}

// validUserCode reports whether a device-flow user code is safe to display.
// RFC 8628 § 6.1 suggests short codes from a small alphabet; printable ASCII
// covers every provider seen in practice and excludes anything a terminal
// could interpret.
func validUserCode(code string) bool {
	if code == "" || len(code) > maxUserCodeLen {
		return false
	}
	for i := 0; i < len(code); i++ {
		if c := code[i]; c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
