package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trick77/toolkit/notify"
)

// Matrix with a user logs in with the password: one login for the channel,
// not one per message.
func TestMatrixLogsInOnce(t *testing.T) {
	var logins, sent atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply := map[string]any{}
		switch {
		case r.URL.Path == "/_matrix/client/v3/login" && r.Method == http.MethodGet:
			reply["flows"] = []map[string]string{{"type": "m.login.password"}}
		case r.URL.Path == "/_matrix/client/v3/login":
			logins.Add(1)
			reply = map[string]any{"access_token": "tok", "user_id": "@bot:example.com", "device_id": "D"}
		case r.URL.Path == "/_matrix/client/versions":
			reply["versions"] = []string{"v1.11"}
		case r.URL.Path == "/_matrix/client/v3/joined_rooms":
			reply["joined_rooms"] = []string{"!room:example.com"}
		case strings.HasPrefix(r.URL.Path, "/_matrix/client/v3/join/"):
			reply["room_id"] = "!room:example.com"
		case strings.Contains(r.URL.Path, "/send/m.room.message/"):
			sent.Add(1)
			reply["event_id"] = "$e"
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer srv.Close()
	u := "matrix://bot:hunter2hunter2@" + strings.TrimPrefix(srv.URL, "http://") +
		"/?rooms=" + url.QueryEscape("!room:example.com") + "&disabletls=yes"
	c, err := notify.NewChannels([]string{u})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 4)
	for range 4 {
		go func() { done <- c.Send("t", "b") }()
	}
	for range 4 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Send("t", "b"); err != nil {
		t.Fatal(err)
	}
	if logins.Load() != 1 || sent.Load() != 5 {
		t.Errorf("%d logins for %d messages, want 1 for 5", logins.Load(), sent.Load())
	}
}

// Every spelling an error can quote a credential in: decoded, path-, query-
// and userinfo-escaped, and as the URL wrote it.
func TestScrubSpellings(t *testing.T) {
	const (
		password  = "p@ss:w+rd=1&x"
		asWritten = "p%40ss%3Aw%2Brd=1&x"
		token     = "ab+cd/ef=="
		tokenURL  = "ab%2bcd%2Fef%3D%3D"
	)
	spellings := []string{
		password, url.PathEscape(password), url.QueryEscape(password), asWritten,
		strings.TrimPrefix(url.UserPassword("", password).String(), ":"),
		token, url.PathEscape(token), url.QueryEscape(token), tokenURL, "Bearer " + token,
	}
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 40101, "http": 401, "error": strings.Join(spellings, " | ")})
	}))
	defer echo.Close()
	host := strings.TrimPrefix(echo.URL, "http://")
	for u, leaks := range map[string][]string{
		"ntfy://user:" + asWritten + "@" + host + "/topic?scheme=http": {password, asWritten, "w%2Brd", "p%40ss"},
		"ntfy://" + host + "/topic?scheme=http&token=" + tokenURL:      {token, tokenURL, "ab%2Bcd", "ab+cd"},
	} {
		c, err := notify.NewChannels([]string{u})
		if err != nil {
			t.Fatal(err)
		}
		err = c.Send("t", "b")
		if err == nil {
			t.Fatal("a refused credential was accepted")
		}
		msg := err.Error()
		for _, secret := range leaks {
			if strings.Contains(msg, secret) {
				t.Errorf("%q survived in %v", secret, err)
			}
		}
	}
}

func TestSecretsOf(t *testing.T) {
	for _, tc := range []struct {
		url, service string
		has, hasNot  []string
	}{
		{"pushbullet://o.TokenToken123/device", "pushbullet", []string{"o.TokenToken123"}, nil},
		{"pushover://shoutrrr:aTokenToken12345@uUserKey12345678/", "pushover",
			[]string{"aTokenToken12345", "uUserKey12345678"}, []string{"shoutrrr"}},
		{"slack://T00000000/B00000000/XXXXXXXXXXXX", "slack", []string{"T00000000", "XXXXXXXXXXXX"}, nil},
		{"slack://hook:xoxb-123456-abcdef@webhook", "slack", []string{"xoxb-123456-abcdef"}, []string{"webhook"}},
		{"ntfy://ntfy.example.com/alerts?title=Disk+alarms&markdown=yes", "ntfy", []string{"alerts"},
			[]string{"ntfy.example.com", "Disk alarms", "Disk+alarms"}},
		{"generic+https://hooks.example.com/x?@Authorization=Bearer+tok3n123", "generic",
			[]string{"tok3n123", "Bearer tok3n123"}, []string{"hooks.example.com"}},
		{"teams://group@tenant/alt/owner?host=" + url.QueryEscape("https://x.example.com/webhookb2/s3cretpath"), "teams",
			[]string{"s3cretpath"}, nil},
	} {
		got := notify.SecretsOf(tc.url, tc.service)
		for _, s := range tc.has {
			if !slices.Contains(got, s) {
				t.Errorf("%s: %q not a secret in %q", tc.url, s, got)
			}
		}
		for _, s := range tc.hasNot {
			if slices.Contains(got, s) {
				t.Errorf("%s: %q scrubbed", tc.url, s)
			}
		}
	}
}

// An empty title leaves the URL's own; a set one replaces it.
func TestTitleFromURL(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("Title")
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	defer srv.Close()
	c, err := notify.NewChannels([]string{ntfyURL(srv, "&title=FromURL")})
	if err != nil {
		t.Fatal(err)
	}
	for title, want := range map[string]string{"": "FromURL", "Mine": "Mine"} {
		if err := c.Send(title, "b"); err != nil {
			t.Fatal(err)
		}
		if h := <-got; h != want {
			t.Errorf("title %q: Title = %q, want %q", title, h, want)
		}
	}
}

func TestPagerDutyHighIsCritical(t *testing.T) {
	const pd = "pagerduty://events.pagerduty.com/0123456789abcdef0123456789abcdef"
	p, err := notify.ParamsFor(pd, notify.Message{Severity: notify.High})
	if err != nil {
		t.Fatal(err)
	}
	if p["severity"] != "critical" {
		t.Errorf("High: %v", p)
	}
	p, _ = notify.ParamsFor(pd+"?severity=warning", notify.Message{Severity: notify.High})
	if _, set := p["severity"]; set {
		t.Errorf("the URL's severity lost: %v", p)
	}
	p, _ = notify.ParamsFor(pd, notify.Message{Severity: notify.Low})
	if _, set := p["severity"]; set || p["level"] != "Debug" {
		t.Errorf("Low: %v", p)
	}
}

// A send that failed on a deadline of its own before the wait ended keeps
// its error; one that ended with the wait reads as the wait's end.
func TestReport(t *testing.T) {
	own := errors.New("Post: context deadline exceeded")
	wrapped := errors.Join(own, context.DeadlineExceeded)
	for _, tc := range []struct {
		err             error
		answered, early bool
		stopped, want   string
	}{
		{nil, false, false, "timed out after 1s", "timed out after 1s"},
		{nil, true, true, "timed out after 1s", ""},
		{wrapped, true, true, "timed out after 1s", wrapped.Error()},
		{wrapped, true, false, "timed out after 1s", "timed out after 1s"},
		{wrapped, true, true, "", wrapped.Error()},
	} {
		if got := notify.Report(tc.err, tc.answered, tc.early, tc.stopped); got != tc.want {
			t.Errorf("%+v: %q", tc, got)
		}
	}
}

func TestSetTimeout(t *testing.T) {
	var none *notify.Channels
	none.SetTimeout(time.Second) // nil-safe
	c, err := notify.NewChannels(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{0, -time.Second} {
		c.SetTimeout(d)
		if c.Timeout() != notify.SendTimeout {
			t.Errorf("SetTimeout(%v): %v", d, c.Timeout())
		}
	}
}
