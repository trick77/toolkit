package notify_test

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/trick77/toolkit/notify"
)

func TestPlainBounds(t *testing.T) {
	if got := notify.Plain("ab", math.MaxInt); got != "ab" {
		t.Errorf("max MaxInt: %q", got)
	}
	big := strings.Repeat("/x-y", 1<<18) // 1 MiB
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got := notify.Plain(big, 200)
	runtime.ReadMemStats(&after)
	if n := len([]rune(got)); n != 200 {
		t.Errorf("%d runes", n)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 64<<10 {
		t.Errorf("a 1 MiB input took %d bytes for 200 runes", alloc)
	}
}

// A channel that skips TLS verification keeps one client: its sends reuse
// one connection instead of leaving a transport behind each.
func TestInsecureChannelReusesItsConnection(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	c, err := notify.NewChannels([]string{"ntfy://" + strings.TrimPrefix(srv.URL, "https://") + "/topic?skiptlsverify=yes"})
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if err := c.Send("t", "b"); err != nil {
			t.Fatal(err)
		}
	}
	if n := conns.Load(); n != 1 {
		t.Errorf("5 sends opened %d connections", n)
	}
}

// A server's error text is one line in the log, scrubbed in its JSON and
// Basic auth spellings too, and the channels' errors are joined on it.
func TestSendErrorIsOneLine(t *testing.T) {
	const password = `pa"ss<wo\rd`
	basic := base64.StdEncoding.EncodeToString([]byte("bob:" + password))
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		htmlEscaped := `pa\"ss\` + `u003cwo\\rd`
		msg := "bad " + htmlEscaped + " | " + `pa\"ss<wo\\rd` + " | Basic " + basic + "\r\nFAKE: forged line\U00002028x"
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 40101, "http": 401, "error": msg})
	}))
	defer echo.Close()
	u := "ntfy://bob:" + url.PathEscape(password) + "@" + strings.TrimPrefix(echo.URL, "http://") + "/topic?scheme=http"
	c, err := notify.NewChannels([]string{u, u})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Send("t", "b")
	var sendErr *notify.SendError
	if !errors.As(err, &sendErr) {
		t.Fatalf("err = %v", err)
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\r\n\U00002028") || !strings.Contains(msg, "; channel 2") {
		t.Errorf("not one line: %q", msg)
	}
	for _, leak := range []string{"pa", basic} {
		if strings.Contains(msg, leak) {
			t.Errorf("%q survived in %q", leak, msg)
		}
	}
	if errs := sendErr.Err.(interface{ Unwrap() []error }).Unwrap(); len(errs) != 2 {
		t.Errorf("unwraps to %d errors", len(errs))
	}
}
