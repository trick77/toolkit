package notify_test

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/trick77/toolkit/notify"
)

func TestPlain(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"plain", "/wp-login", "/wp-login"},
		{"discord everyone", "@everyone hi", "＠everyone hi"},
		{"slack channel", "<!channel> <@U123> <!here>", "‹!channel› ‹＠U123› ‹!here›"},
		{"slack link", "<https://evil.example|bank>", "‹https∶//evil․example∣bank›"},
		{"markdown link", "[click](https://evil.example/x)", "［click］(https∶//evil․example/x)"},
		{"bare domain", "www.evil.example", "www․evil․example"},
		{"mail", "a@b.example", "a＠b․example"},
		{"code", "```rm -rf /```", "ˋˋˋrm -rf /ˋˋˋ"},
		{"emphasis", "*bold* _it_ ~~del~~ ||spoiler||", "∗bold∗ ˍitˍ ∼∼del∼∼ ∣∣spoiler∣∣"},
		{"heading", "# big", "＃ big"},
		{"newlines", "a\r\nBcc: x\n\n\tb", "a Bcc: x b"},
		{"control", "a\x00b\x1bc\U00000085d", "a b c d"},
		{"line separator", "a\U00002028b\U00002029c", "a b c"},
		{"rtl override", "evil\U0000202Egnp.exe", "evilgnp․exe"},
		{"zero-width scheme", "https:\U0000200B//x", "https∶//x"},
		{"bom and isolates", "\U0000FEFFa\U00002066b\U00002069", "ab"},
		{"trim", "  \n a  b \t ", "a b"},
		{"invalid utf-8", "a\xffb", "a\U0000FFFDb"},
	} {
		if got := notify.Plain(tc.in, 200); got != tc.want {
			t.Errorf("%s: Plain(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestPlainClips(t *testing.T) {
	for _, tc := range []struct {
		in   string
		max  int
		want string
	}{
		{"abcdef", 6, "abcdef"},
		{"abcdefg", 6, "abcde…"},
		{"ääääääää", 4, "äää…"},
		{"abc def", 5, "abc…"},
		{"abc", 1, "…"},
		{"abc", 0, ""},
		{"abc", -1, ""},
		{"https://x", 7, "https∶…"},
	} {
		if got := notify.Plain(tc.in, tc.max); got != tc.want {
			t.Errorf("Plain(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}

// Whatever comes in, what goes out is one line of valid UTF-8 within max,
// with none of the characters a channel reads as markup.
func TestPlainNeverLeaks(t *testing.T) {
	nasty := "@everyone <!channel> [x](javascript:alert(1)) `a` *b* _c_ ~d~ |e| #f https://g.example\r\n" +
		"\U0000202E\U0000200B\x00" + strings.Repeat("\U00000301", 50) + "\xff\xfe"
	for max := 1; max < 120; max++ {
		got := notify.Plain(nasty, max)
		if !utf8.ValidString(got) {
			t.Fatalf("max %d: invalid UTF-8 %q", max, got)
		}
		if n := utf8.RuneCountInString(got); n > max {
			t.Fatalf("max %d: %d runes", max, n)
		}
		if strings.ContainsAny(got, "@<>`*_~|[]#.") || strings.Contains(got, "://") {
			t.Fatalf("max %d: markup survived in %q", max, got)
		}
		for _, r := range got {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || (unicode.IsSpace(r) && r != ' ') {
				t.Fatalf("max %d: %U survived in %q", max, r, got)
			}
		}
	}
}
