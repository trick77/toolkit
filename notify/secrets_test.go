package notify_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

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
		// generic forwards auth=, a __-escaped key, a header and an extra to
		// the webhook: secrets there. title= is its own setting.
		{"generic+https://h.example.com/x?auth=s3cretvalue&title=Disk+alarms&__title=hidd3nvalue&$extra=extr4value", "generic",
			[]string{"s3cretvalue", "hidd3nvalue", "extr4value"}, []string{"h.example.com", "Disk alarms"}},
		{"generic+https://h.example.com/x?s3cretkey123", "generic", []string{"s3cretkey123"}, nil},
		{"generic+https://h.example.com/x?@Authorization=Bearer+tok3n123", "generic",
			[]string{"tok3n123", "Bearer tok3n123"}, nil},
		{"generic+https://h.example.com/x?next=" + url.QueryEscape("https://y.example.com/hooks/s3cretpath"), "generic",
			[]string{"s3cretpath"}, nil},
		// A URL inside a value has no settings of its own.
		{"generic+https://h.example.com/x?next=" + url.QueryEscape("https://y.example.com/?title=n3stedtitle"), "generic",
			[]string{"n3stedtitle"}, nil},
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

// The secrets are pooled over the channels: generic's own settings must not
// turn ordinary words to *** in another channel's error, a key it forwards
// still does.
func TestScrubKeepsGenericSettings(t *testing.T) {
	ntfy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 40001, "http": 400,
			"error": "unsupported content type application/json in message subject, auth hunter2hunter2"})
	}))
	defer ntfy.Close()
	hook := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer hook.Close()
	c, err := notify.NewChannels([]string{
		"ntfy://" + strings.TrimPrefix(ntfy.URL, "http://") + "/topic?scheme=http",
		"generic+" + hook.URL + "/hook?contenttype=application/json&messagekey=content&titlekey=subject&auth=hunter2hunter2",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Send("t", "b")
	if err == nil {
		t.Fatal("the ntfy channel accepted the message")
	}
	if msg := err.Error(); !strings.Contains(msg, "unsupported content type application/json in message subject, auth ***") {
		t.Errorf("err = %v", err)
	}
}
