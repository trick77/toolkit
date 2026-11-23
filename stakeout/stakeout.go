// Package stakeout connects an app to Stakeout (github.com/trick77/stakeout), the self-hosted usage analytics: the
// origin the app's pages load Stakeout's tracker from, and the feed that reports every request the app serves, so
// clients that never run JavaScript (crawlers, probes, API scripts) show up too. The contract is Stakeout's
// INTEGRATION.md. Stakeout is optional: down, slow or misconfigured, it never touches a request.
package stakeout

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The paths Stakeout serves, fixed by its contract.
const (
	ScriptPath = "/stakeout.js"
	FeedPath   = "/api/feed"
)

// Origin is raw (STAKEOUT_URL) reduced to scheme://host[:port], the one form that goes into the CSP header and the
// script tag. Anything that could smuggle more into either (a path, a query, userinfo, whitespace) is refused, not
// cleaned up, and so is any host but a DNS name or an IP literal: a CSP wildcard (https://*, https://*.example)
// would allow scripts from hosts Stakeout does not own. The errors never echo raw: it may hold a password.
func Origin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty")
	}
	if strings.ContainsAny(raw, " \t\r\n;,'\"<>\\") {
		return "", errors.New("not a plain URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("not a URL")
	}
	switch {
	case u.Scheme != "https" && u.Scheme != "http":
		return "", errors.New("want an http(s) URL")
	case u.Host == "" || u.Hostname() == "":
		return "", errors.New("no host")
	case u.User != nil:
		return "", errors.New("userinfo not allowed")
	case u.Path != "" && u.Path != "/", u.RawQuery != "", u.Fragment != "", u.Opaque != "":
		return "", errors.New("want the origin only (no path, query or fragment)")
	}
	host, ok := originHost(u.Host, u.Hostname())
	if !ok {
		return "", errors.New("want a DNS name or an IP literal as host")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("want a port 1-65535")
		}
		host += ":" + strconv.Itoa(n)
	}
	return u.Scheme + "://" + host, nil
}

// originHost is name (u.Hostname of hostport) as a DNS name, an IPv4 address, or a bracketed IPv6 literal without
// a zone; ok is false for anything else, a CSP wildcard in particular.
func originHost(hostport, name string) (string, bool) {
	if strings.HasPrefix(hostport, "[") {
		a, err := netip.ParseAddr(name)
		if err != nil || !a.Is6() || a.Zone() != "" {
			return "", false
		}
		return "[" + a.String() + "]", true
	}
	if a, err := netip.ParseAddr(name); err == nil {
		return a.String(), a.Is4()
	}
	name = strings.ToLower(name)
	if len(name) > 253 {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range []byte(label) {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", false
			}
		}
	}
	return name, true
}

// Settings is what the configuration turns on. The zero value is Stakeout off: no script tag, the app's own CSP, no
// feed.
type Settings struct {
	Origin string  // Stakeout's origin: the tracker's script tag and the CSP; "" is off
	Feed   *Config // the server feed; nil is off
}

// Resolve reads STAKEOUT_URL (rawURL), STAKEOUT_FEED_KEY and STAKEOUT_SITE; defaultSite (the app's public host, ""
// for none) names the site when STAKEOUT_SITE is unset. A URL alone turns on the tracker, a key adds the feed. A value
// that does not work turns the part it belongs to off and comes back as a warning: Stakeout is optional, it never
// stops the app from starting.
func Resolve(rawURL, key, site, defaultSite string) (Settings, []string) {
	rawURL, key, site = strings.TrimSpace(rawURL), strings.TrimSpace(key), strings.TrimSpace(site)
	if rawURL == "" {
		if key != "" {
			return Settings{}, []string{"STAKEOUT_FEED_KEY is set without STAKEOUT_URL: Stakeout off"}
		}
		return Settings{}, nil
	}
	origin, err := Origin(rawURL)
	if err != nil {
		return Settings{}, []string{"STAKEOUT_URL: " + err.Error() + ": Stakeout off"}
	}
	s := Settings{Origin: origin}
	if key == "" {
		return s, nil
	}
	if site == "" {
		site = defaultSite
	}
	var warns []string
	switch {
	case strings.ContainsFunc(key, func(r rune) bool { return r <= ' ' || r == 0x7f }):
		warns = append(warns, "STAKEOUT_FEED_KEY holds whitespace or control characters: Stakeout feed off")
	case site == "":
		warns = append(warns, "STAKEOUT_SITE is unset and the app has no public host to fall back on: Stakeout feed off")
	default:
		if strings.HasPrefix(origin, "http://") {
			warns = append(warns, "STAKEOUT_URL is plain http: the feed key travels unencrypted")
		}
		s.Feed = &Config{Endpoint: origin + FeedPath, Key: key, Site: site}
	}
	return s, warns
}

// Event is one served request, exactly the fields Stakeout's feed takes and nothing else: no raw header, query string,
// cookie or body leaves the app.
type Event struct {
	T        int64  `json:"t"` // request start, epoch milliseconds
	IP       string `json:"ip"`
	UA       string `json:"ua"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Route    string `json:"route"`
	Status   int    `json:"status"`
	DurMS    int64  `json:"dur_ms"`
	Bytes    int64  `json:"bytes"`
	Ref      string `json:"ref"`
	Lang     string `json:"lang"`
	SFSite   string `json:"sf_site"`
	SFMode   string `json:"sf_mode"`
	SFDest   string `json:"sf_dest"`
	CHUA     string `json:"ch_ua"`
	SigAgent string `json:"sig_agent"` // Signature-Agent (Web Bot Auth), as sent
	Account  string `json:"account"`   // an opaque account id, never an email or a name; "" for none
}

// Stakeout's per-field limits, in bytes of the value it decodes. Stakeout cuts a longer value, but the emitter cuts
// first: the values come from the client (a header can be up to net/http's 1 MB), and they sit in the queue.
const (
	maxMethod   = 16
	maxRoute    = 200
	maxSF       = 32 // each Sec-Fetch value
	maxSigAgent = 256
	maxAcct     = 128
	maxHeader   = 512 // ua, lang, ch_ua
	maxURL      = 2048
)

// clip makes s valid UTF-8 (json.Marshal would turn each invalid byte into a three-byte U+FFFD on the way, past
// the limit), cuts it to limit bytes on a rune boundary, and copies it: a substring would keep the client's whole
// request line or header alive in the queue.
func clip(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) > limit {
		n := limit
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = s[:n]
	}
	return strings.Clone(s)
}

// sanitized is ev as it may be sent: every string within its field's limit and copied, the ip in canonical form.
// ok is false when ip is no address: Stakeout refuses that event, and with it the batch.
func (ev Event) sanitized() (Event, bool) {
	a, err := netip.ParseAddr(ev.IP)
	if err != nil {
		return Event{}, false
	}
	ev.IP = a.WithZone("").String()
	ev.Method = clip(ev.Method, maxMethod)
	ev.Route = clip(ev.Route, maxRoute)
	ev.SFSite, ev.SFMode, ev.SFDest = clip(ev.SFSite, maxSF), clip(ev.SFMode, maxSF), clip(ev.SFDest, maxSF)
	ev.SigAgent = clip(ev.SigAgent, maxSigAgent)
	ev.Account = clip(ev.Account, maxAcct)
	ev.UA, ev.Lang, ev.CHUA = clip(ev.UA, maxHeader), clip(ev.Lang, maxHeader), clip(ev.CHUA, maxHeader)
	ev.Path, ev.Ref = clip(ev.Path, maxURL), clip(ev.Ref, maxURL)
	return ev, true
}
