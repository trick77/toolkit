package notify_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/trick77/toolkit/notify"
)

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
		{"pushover://shoutrrr:aTokenToken12345@uUserKey12345678/", "pushover",
			[]string{"aTokenToken12345", "uUserKey12345678"}, []string{"shoutrrr"}},
		{"ntfy://ntfy.example.com/alerts?title=Disk+alarms&markdown=yes", "ntfy", []string{"alerts"},
			[]string{"ntfy.example.com", "Disk alarms", "Disk+alarms"}},
		{"ntfy://bob:hunter2hunter2@h.example.com/topic", "ntfy",
			[]string{"hunter2hunter2", base64.StdEncoding.EncodeToString([]byte("bob:hunter2hunter2"))}, nil},
		// generic forwards auth= and title= to the webhook: secrets there.
		{"generic+https://h.example.com/x?auth=s3cretvalue&title=Disk+alarms", "generic",
			[]string{"s3cretvalue", "Disk alarms"}, []string{"h.example.com"}},
		{"generic+https://h.example.com/x?s3cretkey123", "generic", []string{"s3cretkey123"}, nil},
		{"generic+https://h.example.com/x?@Authorization=Bearer+tok3n123", "generic",
			[]string{"tok3n123", "Bearer tok3n123"}, nil},
		{"generic+https://h.example.com/x?next=" + url.QueryEscape("https://y.example.com/hooks/s3cretpath"), "generic",
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

// A send that failed on a deadline of its own before the wait ended keeps
// its error; one that ended with the wait reads as the wait's end.
func TestReport(t *testing.T) {
	wrapped := fmt.Errorf("client timeout: %w", context.DeadlineExceeded)
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
		{errors.New("a\r\nb"), true, true, "", "a  b"},
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
