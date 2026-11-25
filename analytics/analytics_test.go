package analytics

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
	"unsafe"
)

func TestOrigin(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"https://analytics.example.com", "https://analytics.example.com"},
		{"https://analytics.example.com/", "https://analytics.example.com"},
		{"  https://analytics.example:8443  ", "https://analytics.example:8443"},
		{"http://localhost:8090", "http://localhost:8090"},
		{"http://[::1]:8090", "http://[::1]:8090"},
		{"https://Analytics.Example", "https://analytics.example"},
		{"https://192.0.2.10:443", "https://192.0.2.10:443"},
		{"https://analytics.example:", "https://analytics.example"},
		{"https://xn--analytics-abc.example", "https://xn--analytics-abc.example"},
	} {
		got, err := Origin(tc.raw)
		if err != nil || got != tc.want {
			t.Errorf("Origin(%q) = %q, %v, want %q", tc.raw, got, err, tc.want)
		}
	}
	for _, raw := range []string{
		"",
		"analytics.example.com",                     // no scheme
		"ftp://analytics.example",                   // not http(s)
		"https://",                                  // no host
		"https://user:pw@analytics.example",         // userinfo
		"https://analytics.example/sub",             // a path
		"https://analytics.example/?x=1",            // a query
		"https://analytics.example/#x",              // a fragment
		"https://analytics.example; script-src *",   // CSP injection
		`https://analytics.example"><script>`,       // HTML injection
		"https://analytics.example https://evil.ex", // a second source
		"https://analytics.example,https://evil.ex", // a second policy
		"javascript:alert(1)",
		// CSP wildcards and other non-hosts: each would allow scripts from hosts Trakk does not own
		"https://*",
		"https://*.example.com",
		"http://*:8080",
		"https://analytics.*",
		"https://analytics.example:*",
		"https://analytics.example:0",
		"https://analytics.example:70000",
		"https://-analytics.example",
		"https://analytics..example",
		"https://analytics_x.example",
		"https://[fe80::1%25eth0]",
		"https://[192.0.2.1]",
		"https://analytics.example%2f",
	} {
		got, err := Origin(raw)
		if err == nil {
			t.Errorf("Origin(%q) = %q, want an error", raw, got)
		} else if raw != "" && strings.Contains(err.Error(), raw) {
			t.Errorf("Origin(%q): error %q echoes the value", raw, err)
		}
	}
	if _, err := Origin("https://user:hunter2@analytics.example"); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("userinfo: error %v, want one without the password", err)
	}
}

func TestResolve(t *testing.T) {
	for _, tc := range []struct {
		name               string
		url, key           string
		wantOrigin         string
		wantFeed, wantWarn bool
	}{
		{name: "all unset: off"},
		{name: "key without URL: off, warned", key: "k", wantWarn: true},
		{name: "bad URL: off, warned", url: "analytics.example", key: "k", wantWarn: true},
		{name: "URL only: tracker, no feed", url: "https://analytics.example", wantOrigin: "https://analytics.example"},
		{name: "URL and key: feed", url: "https://analytics.example", key: "k", wantOrigin: "https://analytics.example",
			wantFeed: true},
		{name: "key with a newline: tracker only, warned", url: "https://analytics.example", key: "a\nb",
			wantOrigin: "https://analytics.example", wantWarn: true},
		{name: "plain http: feed, warned", url: "http://localhost:8090", key: "k", wantOrigin: "http://localhost:8090",
			wantFeed: true, wantWarn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, warns := Resolve(tc.url, tc.key)
			if s.Origin != tc.wantOrigin {
				t.Errorf("Origin = %q, want %q", s.Origin, tc.wantOrigin)
			}
			if (s.Feed != nil) != tc.wantFeed {
				t.Fatalf("Feed = %+v, want on=%v", s.Feed, tc.wantFeed)
			}
			if s.Feed != nil {
				if s.Feed.Key != tc.key || s.Feed.Endpoint != tc.wantOrigin+"/api/feed" {
					t.Errorf("Feed = %+v, want key %q, endpoint %s/api/feed", s.Feed, tc.key, tc.wantOrigin)
				}
			}
			if (len(warns) > 0) != tc.wantWarn {
				t.Errorf("warnings %q, want some=%v", warns, tc.wantWarn)
			}
			for _, w := range warns {
				if tc.key != "" && strings.Contains(w, tc.key) && len(tc.key) > 1 {
					t.Errorf("warning %q carries the key", w)
				}
			}
		})
	}
}

func TestClip(t *testing.T) {
	if got := clip("short", 512); got != "short" {
		t.Errorf("clip(short) = %q", got)
	}
	long := strings.Repeat("a", 511) + "é" + strings.Repeat("b", 100) // é straddles the cut
	if got := clip(long, 512); got != strings.Repeat("a", 511) {
		t.Errorf("clip cut mid-rune or too early: %d bytes, valid %v", len(got), utf8.ValidString(got))
	}
	// Each run of invalid bytes becomes one U+FFFD here, not one per byte in json.Marshal.
	if got := clip(strings.Repeat("\xff", 300), 512); got != "�" {
		t.Errorf("clip(300 x 0xFF) = %q, want one U+FFFD", got)
	}
}

// Trakk's limits per field, in bytes of the decoded value: it clips a longer one.
var fieldLimits = map[string]int{"method": 16, "route": 200, "sig_agent": 256, "sf_site": 32, "sf_mode": 32, "sf_dest": 32,
	"account": 128, "op": 64, "err": 64, "ua": 512, "lang": 512, "ch_ua": 512, "path": 2048, "ref": 2048}

// Whatever a client sends, every field arrives valid UTF-8 and within Trakk's limit, measured on what Trakk
// decodes.
func TestSanitizedFieldLimits(t *testing.T) {
	for name, junk := range map[string]string{
		"ascii":       strings.Repeat("x", 10_000),
		"invalid":     strings.Repeat("\xff", 10_000),
		"mixed":       strings.Repeat("a\xffé\xfe€", 3_000),
		"multibyte":   strings.Repeat("€", 5_000),
		"control":     strings.Repeat("\x01", 10_000),
		"alternating": strings.Repeat("\xffa", 1_100), // fits the path limit as sent, not after replacement
	} {
		ev, ok := Event{IP: "203.0.113.42", UA: junk, Method: junk, Path: junk, Route: junk, Ref: junk, Lang: junk,
			SFSite: junk, SFMode: junk, SFDest: junk, CHUA: junk, SigAgent: junk, Account: junk, Op: junk, Err: junk}.sanitized()
		if !ok {
			t.Fatalf("%s: refused", name)
		}
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(b, &decoded); err != nil {
			t.Fatal(err)
		}
		for field, limit := range fieldLimits {
			s, _ := decoded[field].(string)
			if len(s) > limit || len(s) == 0 || !utf8.ValidString(s) {
				t.Errorf("%s: %s decodes to %d bytes (valid %v), want 1..%d valid", name, field, len(s),
					utf8.ValidString(s), limit)
			}
		}
	}
	// The reported case: a User-Agent of 300 invalid bytes would decode to 900 bytes without ToValidUTF8.
	ev, _ := Event{IP: "203.0.113.42", UA: strings.Repeat("\xff", 300)}.sanitized()
	b, _ := json.Marshal(ev)
	var decoded map[string]any
	_ = json.Unmarshal(b, &decoded)
	if ua, _ := decoded["ua"].(string); len(ua) > 512 {
		t.Errorf("ua of 300 x 0xFF decodes to %d bytes", len(ua))
	}
	// A value within its limit passes unchanged.
	if ev, _ := (Event{IP: "203.0.113.42", Method: strings.Repeat("M", 16)}).sanitized(); ev.Method != "MMMMMMMMMMMMMMMM" {
		t.Errorf("16-byte method changed to %q", ev.Method)
	}
}

// An ip that is no address is never fed: Trakk would drop the event. A zone is dropped.
func TestSanitizedIP(t *testing.T) {
	for _, ip := range []string{"", "unknown", "203.0.113", "1.2.3.4:80", "[::1]"} {
		if _, ok := (Event{IP: ip}).sanitized(); ok {
			t.Errorf("ip %q accepted", ip)
		}
	}
	for in, want := range map[string]string{"203.0.113.42": "203.0.113.42", "2001:DB8::1": "2001:db8::1",
		"fe80::1%eth0": "fe80::1"} {
		if ev, ok := (Event{IP: in}).sanitized(); !ok || ev.IP != want {
			t.Errorf("ip %q: %q, %v; want %q", in, ev.IP, ok, want)
		}
	}
}

// Every queued string is a copy: a substring of the request line or a header would keep all of it in the queue.
func TestSanitizedCopies(t *testing.T) {
	line := "GET /" + strings.Repeat("q", 1<<20)
	in := Event{IP: strings.Clone("203.0.113.42"), Method: line[:3], Path: line[4:10], Ref: line[4:8], UA: line[:5]}
	ev, ok := in.sanitized()
	if !ok {
		t.Fatal("refused")
	}
	for name, pair := range map[string][2]string{"method": {in.Method, ev.Method}, "path": {in.Path, ev.Path},
		"ref": {in.Ref, ev.Ref}, "ua": {in.UA, ev.UA}} {
		if pair[0] != pair[1] {
			t.Errorf("%s changed: %q -> %q", name, pair[0], pair[1])
		}
		if unsafe.StringData(pair[0]) == unsafe.StringData(pair[1]) { //nolint:gosec // compares addresses only
			t.Errorf("%s shares the request's memory", name)
		}
	}
}
