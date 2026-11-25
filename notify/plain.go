package notify

import "unicode"

// defused swaps each character a channel reads as markup for a look-alike
// that reads as nothing: Slack's <!channel> and <url|text>, Discord's
// @everyone, ||spoilers|| and # headings, Markdown's emphasis, code and
// [links](…), Telegram's #hashtags and $CASHTAGS, :emoji: shortcodes, a
// scheme's "://", a mail client's autolinked a@b.c and example.com.
// Escaping with a backslash would show the backslash on every plain-text
// channel (mail, Pushover, Gotify, a webhook).
var defused = map[rune]rune{
	'@':  '＠', // U+FF20: no mention, no mail address
	'.':  '․', // U+2024: no bare domain to autolink
	':':  '∶', // U+2236: no scheme, no :shortcode:
	'<':  '‹', // U+2039
	'>':  '›', // U+203A
	'`':  'ˋ', // U+02CB
	'*':  '∗', // U+2217
	'_':  'ˍ', // U+02CD
	'~':  '∼', // U+223C
	'|':  '∣', // U+2223
	'[':  '［', // U+FF3B
	']':  '］', // U+FF3D
	'#':  '＃', // U+FF03
	'$':  '＄', // U+FF04
	'&':  '＆', // U+FF06: no &#8238; bringing an override back in an HTML channel
	'\\': '∖', // U+2216: escapes whatever the caller puts after the text
}

// Plain makes untrusted text (a request path, a referrer, a user agent, an
// error key) safe to put in a message: one line of at most max runes that no
// channel formats, links or turns into a mention. It reads the same to a
// person; it is no longer what was sent, so it is for display only.
//
// Control and invisible format characters go first (a CR/LF starts a new
// line or mail header, a right-to-left override reverses what follows,
// a zero-width space hides "://" from a check), then whitespace runs become
// one space. A "/" starting a word becomes "∕" (U+2215): Telegram links
// /word as a bot command. Clipped text ends in "…", counted within max;
// max < 1 is "".
//
// Not covered: phone numbers and other digit runs a phone's client links on
// its own (defusing digits would mangle every number), and a client that
// folds the look-alikes back to ASCII (NFKC) before it links.
func Plain(s string, max int) string {
	if max < 1 {
		return ""
	}
	// Bounded by the input, never by max (math.MaxInt), and the loop stops
	// one rune past max: a megabyte of path costs max runes, not megabytes.
	out := make([]rune, 0, min(len(s), max)+2)
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r) || unicode.IsControl(r):
			space = len(out) > 0
			continue
		case unicode.Is(unicode.Cf, r):
			continue
		}
		if space {
			out = append(out, ' ')
			space = false
		}
		switch d, ok := defused[r]; {
		case ok:
			r = d
		case r == '/' && (len(out) == 0 || out[len(out)-1] == ' '):
			r = '∕'
		}
		out = append(out, r)
		if len(out) > max {
			break
		}
	}
	if len(out) > max {
		out = out[:max-1]
		for len(out) > 0 && out[len(out)-1] == ' ' {
			out = out[:len(out)-1]
		}
		out = append(out, '…')
	}
	return string(out)
}
