package notify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

// hostSecrets are the services whose URL host is a credential: Pushover's
// is the user key (the fork tags it sensitive).
var hostSecrets = map[string]bool{"pushover": true}

// placeholderUsers are the services whose URL user is a fixed word
// ("shoutrrr"), not an account.
var placeholderUsers = map[string]bool{"pushover": true}

// settingKeys are the query keys of smtp, ntfy, pushover, gotify and
// telegram whose values are settings or display text, never a credential:
// scrubbed, "markdown" or a title's words would turn to *** in every error,
// every channel's, as the secrets are pooled. None of them is tagged
// sensitive in the fork.
var settingKeys = map[string]bool{
	"title": true, "subject": true, "priority": true, "tags": true, "scheme": true,
	"disabletls": true, "skiptlsverify": true, "insecureskipverify": true, "disabletlsverification": true,
	"markdown": true, "cache": true, "firebase": true, "parsemode": true, "preview": true,
	"notification": true, "usestarttls": true, "starttls": true, "usehtml": true,
	"requirestarttls": true, "encryption": true, "auth": true, "timeout": true,
	"useheader": true, "retry": true, "expire": true, "timestamp": true,
}

// genericKeys are the keys generic reads as its own settings (the fork's
// generic Config). Any other key, "__"-escaped ones, @headers and $extras
// go on to the webhook, so any of them may carry a secret.
var genericKeys = map[string]bool{
	"contenttype": true, "template": true, "title": true, "titlekey": true,
	"messagekey": true, "method": true, "disabletls": true, "skiptlsverify": true,
}

// setting says whether a query key of the service holds a setting, not a
// credential. service "" (a URL inside a value) has none.
func setting(service, key string) bool {
	key = strings.ToLower(key)
	switch service {
	case "":
		return false
	case "generic":
		return genericKeys[key]
	}
	return settingKeys[key]
}

// secretsOf is every part of a channel URL that may be a credential, decoded
// and as written: user and password (and both as Basic auth), every path
// segment, every query value but a setting's, a bare query key, the pieces of
// a composite value ("Bearer <token>", a list, a URL inside a value) and, for
// hostSecrets, the host. Any other host stays: it is what makes an error
// readable. Parts under 6 bytes (a port, "yes") protect nothing and would
// mangle the text.
func secretsOf(raw, service string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var out []string
	var add func(s string)
	add = func(s string) {
		if len(s) < 6 {
			return
		}
		out = append(out, s)
		parts := strings.FieldsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == ',' || r == ';' })
		for _, p := range parts {
			if p != s {
				add(p)
			}
		}
		if strings.Contains(s, "://") {
			out = append(out, secretsOf(s, "")...)
		}
	}
	if u.User != nil {
		if !placeholderUsers[service] {
			add(u.User.Username())
		}
		if p, ok := u.User.Password(); ok {
			add(p)
			add(base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + p)))
		}
		// As written: the URL's own escapes (%2b, %2B for a +) are not
		// necessarily the ones Go would choose.
		name, pass, _ := strings.Cut(rawUserinfo(raw), ":")
		if !placeholderUsers[service] {
			add(name)
		}
		add(pass)
	}
	if hostSecrets[service] {
		add(u.Hostname())
	}
	for _, seg := range strings.Split(u.Path, "/") {
		add(seg)
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		add(seg)
	}
	for _, pair := range strings.Split(u.RawQuery, "&") {
		k, v, hasValue := strings.Cut(pair, "=")
		if !hasValue {
			v = k // a bare ?token
		} else if key, err := url.QueryUnescape(k); err == nil && setting(service, key) {
			continue
		}
		add(v)
		if dv, err := url.QueryUnescape(v); err == nil {
			add(dv)
		}
	}
	return out
}

// rawUserinfo is the userinfo of a URL as written, "" without one.
func rawUserinfo(raw string) string {
	_, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	i := strings.LastIndex(rest, "@")
	if i < 0 {
		return ""
	}
	return rest[:i]
}

// spellings adds the ways an error can quote each secret: net/http escapes a
// path, a query and userinfo each its own way, and a JSON body escapes
// quotes and backslashes (and <, >, & unless told not to). Longest first, so
// a secret containing a shorter one is scrubbed whole, not leaving its tail
// behind.
func spellings(secrets []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range secrets {
		for _, v := range []string{
			s,
			url.PathEscape(s),
			url.QueryEscape(s),
			url.User(s).String(),
			strings.TrimPrefix(url.UserPassword("", s).String(), ":"),
			jsonString(s, true),
			jsonString(s, false),
		} {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// jsonString is s as a JSON string's content, without the quotes.
func jsonString(s string, escapeHTML bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(escapeHTML)
	_ = enc.Encode(s)
	return strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(b.String(), `"`), "\n"), `"`)
}

// scrub removes the URLs' credentials from an error text. The fork reduces
// a request URL in its errors to scheme and host, but a server's answer
// quoted back (a webhook echoing its path) is not covered.
func (c *Channels) scrub(s string) string {
	for _, secret := range c.secrets {
		s = strings.ReplaceAll(s, secret, "***")
	}
	return s
}
