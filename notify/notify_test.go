package notify_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trick77/toolkit/notify"
)

func TestChannelsRejectBadURLWithoutQuotingIt(t *testing.T) {
	_, err := notify.NewChannels([]string{"smtp://user:s3cret@mail:587/?to=a@b&from=c@d", "nope://x:topsecret@y"})
	if err == nil {
		t.Fatal("a bad URL was accepted")
	}
	if strings.Contains(err.Error(), "topsecret") {
		t.Errorf("the error leaks a credential: %v", err)
	}
	if err.Error() != "channel 2 (nope): unsupported service" {
		t.Errorf("err = %q, want it to name the entry and nothing more", err)
	}
	if _, err := notify.NewChannels([]string{"no-scheme"}); err == nil || !strings.Contains(err.Error(), "no scheme") {
		t.Errorf("a schemeless entry: %v", err)
	}
	// A port net/url refuses: its parse error would quote it.
	_, err = notify.NewChannels([]string{"generic+http://x:p4ssw0rd/"})
	if err == nil || strings.Contains(err.Error(), "p4ssw0rd") {
		t.Errorf("an unparsable URL: %v", err)
	}
}

func TestUnsupportedServices(t *testing.T) {
	for in, want := range map[string]string{
		"mqtt://u:s3cretpw@broker:1883/topic":    "channel 1 (mqtt): unsupported service",
		"mqtts://u:s3cretpw@broker/topic":        "channel 1 (mqtts): unsupported service",
		"xmpp://u:s3cretpw@example.com?to=a@b.c": "channel 1 (xmpp): unsupported service",
		"logger://":                              "channel 1 (logger): unsupported service",
		"nope://x:s3cretpw@y":                    "channel 1 (nope): unsupported service",
		"ntfy+https://s3cretpw@ntfy.sh/t":        "channel 1 (ntfy+https): invalid URL", // no custom form
		"ntfy://ntfy.sh/t?s3cretpw#":             "channel 1 (ntfy): invalid URL",       // the "#" would vanish
	} {
		_, err := notify.NewChannels([]string{in})
		if err == nil || err.Error() != want {
			t.Errorf("%s: err = %v, want %q", in, err, want)
		}
	}
	schemes := notify.Schemes()
	if !slices.IsSorted(schemes) || slices.Contains(schemes, "mqtt") || !slices.Contains(schemes, "smtp") {
		t.Errorf("Schemes() = %q", schemes)
	}
	if _, err := notify.NewChannels([]string{"NTFY://ntfy.example.com/topic"}); err != nil {
		t.Errorf("an upper-case scheme: %v", err)
	}
}

func TestScheme(t *testing.T) {
	for in, want := range map[string]string{
		"smtp://u:p@mail:587/":        "smtp",
		"Generic+HTTPS://x/hook":      "generic+https",
		"ntfy://ntfy.sh/topic":        "ntfy",
		"no-scheme":                   "no scheme",
		"":                            "no scheme",
		"tok:s3cret@host://x":         "invalid scheme",
		"https token://x":             "invalid scheme",
		"://x":                        "invalid scheme",
		"telegram://123:ABC@telegram": "telegram",
	} {
		if got := notify.Scheme(in); got != want {
			t.Errorf("Scheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func hook(s *httptest.Server) string { return "generic+" + s.URL + "/hook" }

func ntfyURL(s *httptest.Server, query string) string {
	return "ntfy://" + strings.TrimPrefix(s.URL, "http://") + "/topic?scheme=http" + query
}

func TestChannelsSend(t *testing.T) {
	var hits atomic.Int32
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()

	all, err := notify.NewChannels([]string{hook(ok)})
	if err != nil {
		t.Fatal(err)
	}
	if err := all.Send("t", "b"); err != nil {
		t.Errorf("send: %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("webhook hit %d times", hits.Load())
	}

	some, err := notify.NewChannels([]string{hook(ok), hook(down)})
	if err != nil {
		t.Fatal(err)
	}
	if got := some.Labels(); len(got) != 2 || got[0] != "channel 1 (generic+http)" || got[1] != "channel 2 (generic+http)" {
		t.Errorf("labels = %q", got)
	}
	err = some.Send("t", "b")
	var sendErr *notify.SendError
	if !errors.As(err, &sendErr) || !sendErr.Partial ||
		len(sendErr.Failed) != 1 || sendErr.Failed[0] != "channel 2 (generic+http)" {
		t.Errorf("one of two failing: %v, want a partial SendError naming channel 2", err)
	}
	if err != nil && !strings.Contains(err.Error(), "channel 2 (generic+http)") {
		t.Errorf("the failure does not name its channel: %v", err)
	}

	none, err := notify.NewChannels([]string{hook(down)})
	if err != nil {
		t.Fatal(err)
	}
	err = none.Send("t", "b")
	if !errors.As(err, &sendErr) || sendErr.Partial || len(sendErr.Failed) != 1 {
		t.Errorf("all failing: %v, want a SendError that is not partial", err)
	}
}

func TestNilChannels(t *testing.T) {
	var none *notify.Channels
	if got := none.Labels(); got == nil || len(got) != 0 {
		t.Errorf("labels = %#v, want empty", got)
	}
	if none.Timeout() != notify.SendTimeout {
		t.Errorf("timeout = %v", none.Timeout())
	}
	out, done := none.Deliver(context.Background(), "t", "b")
	if len(out) != 0 {
		t.Errorf("nil channels delivered %+v", out)
	}
	<-done
}

// Several messages through one channel at once share no service state: each
// request carries its own title. ntfy: one of the services that, in v0.8,
// wrote the params into its own config.
func TestChannelsConcurrentSendsKeepTheirTitles(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies = map[string]string{}
	)
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies[string(b)] = r.Header.Get("Title")
		mu.Unlock()
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	defer ok.Close()
	c, err := notify.NewChannels([]string{ntfyURL(ok, "")})
	if err != nil {
		t.Fatal(err)
	}
	const n = 16
	done := make(chan error, n)
	for i := range n {
		go func() { done <- c.Send(fmt.Sprintf("title %d", i), fmt.Sprintf("body %d", i)) }()
	}
	for range n {
		if err := <-done; err != nil {
			t.Errorf("send: %v", err)
		}
	}
	if len(bodies) != n {
		t.Fatalf("server saw %d messages, want %d", len(bodies), n)
	}
	for body, title := range bodies {
		if strings.TrimPrefix(body, "body ") != strings.TrimPrefix(title, "title ") {
			t.Errorf("%q went out titled %q", body, title)
		}
	}
}

// hanging answers nothing until release closes or the client goes away;
// arrived gets one value per request.
func hanging(t *testing.T) (srv *httptest.Server, arrived chan struct{}, release chan struct{}) {
	arrived = make(chan struct{}, 8)
	release = make(chan struct{})
	srv = httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		srv.Close()
	})
	return srv, arrived, release
}

// The fork's services take the context: a caller that goes away cancels the
// send itself, and done closes while the server still holds the request.
func TestChannelsDeliverCancelsWithContext(t *testing.T) {
	srv, arrived, _ := hanging(t)
	c, err := notify.NewChannels([]string{hook(srv)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-arrived
		cancel()
	}()
	out, done := c.Deliver(ctx, "t", "b")
	if len(out) != 1 || out[0].Err == nil || out[0].Err.Error() != "cancelled: context canceled" {
		t.Fatalf("deliveries = %+v, want the one channel cancelled", out)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the send outlived its cancelled context")
	}
}

// A channel that never answers is a timeout, and the send ends with it.
func TestChannelsTimeout(t *testing.T) {
	srv, _, _ := hanging(t)
	slow, err := notify.NewChannels([]string{hook(srv)})
	if err != nil {
		t.Fatal(err)
	}
	slow.SetTimeout(100 * time.Millisecond)
	if slow.Timeout() != 100*time.Millisecond {
		t.Errorf("timeout = %v", slow.Timeout())
	}
	start := time.Now()
	out, done := slow.Deliver(context.Background(), "t", "b")
	if len(out) != 1 || out[0].Err == nil || out[0].Err.Error() != "timed out after 100ms" {
		t.Errorf("hanging channel: %+v", out)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Deliver waited %v on a hanging channel", d)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the send outlived its timeout")
	}

	err = slow.Send("t", "b")
	if err == nil || err.Error() != "channel 1 (generic+http): timed out after 100ms" {
		t.Errorf("Send on a hanging channel: %v", err)
	}
}

// What reaches the log carries no credential from the URL, in either
// spelling, whether the transport or the server quotes it.
func TestChannelsScrub(t *testing.T) {
	// Nothing listens here: v0.8's transport error quoted the URL, token and all.
	gone := httptest.NewServer(http.NotFoundHandler())
	addr := gone.URL
	gone.Close()
	leaky, err := notify.NewChannels([]string{"generic+" + addr + "/bot123456:SECRETTOKEN/send?apikey=hunter2hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	err = leaky.Send("t", "b")
	if err == nil {
		t.Fatal("a closed port accepted the message")
	}
	for _, secret := range []string{"SECRETTOKEN", "hunter2hunter2"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error leaks %q: %v", secret, err)
		}
	}

	// A server that echoes the credential, raw and path-escaped.
	const password = "pa ss wörd/x"
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, p, _ := r.BasicAuth()
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 40101, "http": 401, "error": "bad password " + p + " (" + url.PathEscape(p) + ")",
		})
	}))
	defer echo.Close()
	u := "ntfy://user:" + url.PathEscape(password) + "@" + strings.TrimPrefix(echo.URL, "http://") + "/topic?scheme=http"
	c, err := notify.NewChannels([]string{u})
	if err != nil {
		t.Fatal(err)
	}
	err = c.Send("t", "b")
	if err == nil {
		t.Fatal("a refused password was accepted")
	}
	if !strings.Contains(err.Error(), "bad password *** (***)") {
		t.Errorf("err = %v, want both spellings scrubbed", err)
	}
}

func TestSeverity(t *testing.T) {
	type seen struct{ priority, body string }
	record := func(reply string) (*httptest.Server, chan seen) {
		got := make(chan seen, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			got <- seen{r.Header.Get("Priority"), string(b)}
			_, _ = w.Write([]byte(reply))
		}))
		t.Cleanup(srv.Close)
		return srv, got
	}
	send := func(t *testing.T, u string, sev notify.Severity) {
		t.Helper()
		c, err := notify.NewChannels([]string{u})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.SendMessage(notify.Message{Title: "t", Body: "b", Severity: sev}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("ntfy", func(t *testing.T) {
		srv, got := record(`{"id":"x"}`)
		for sev, want := range map[notify.Severity]string{
			"": "default", notify.Normal: "default", "bogus": "default",
			notify.Low: "low", notify.High: "max",
		} {
			send(t, ntfyURL(srv, ""), sev)
			if p := (<-got).priority; !strings.EqualFold(p, want) {
				t.Errorf("%q: Priority = %q, want %q", sev, p, want)
			}
		}
		// The URL's own priority wins.
		send(t, ntfyURL(srv, "&priority=min"), notify.High)
		if p := (<-got).priority; !strings.EqualFold(p, "min") {
			t.Errorf("URL priority min, High: Priority = %q", p)
		}
	})

	t.Run("gotify", func(t *testing.T) {
		srv, got := record(`{"id":1}`)
		u := "gotify://" + strings.TrimPrefix(srv.URL, "http://") + "/Abcdefghijklmno?disabletls=yes"
		for sev, want := range map[notify.Severity]float64{notify.Normal: 0, notify.Low: 2, notify.High: 8} {
			send(t, u, sev)
			var body struct {
				Priority float64 `json:"priority"`
			}
			if err := json.Unmarshal([]byte((<-got).body), &body); err != nil {
				t.Fatal(err)
			}
			if body.Priority != want {
				t.Errorf("%q: priority = %v, want %v", sev, body.Priority, want)
			}
		}
	})

	// Elsewhere the severity changes nothing: generic would put it in its body.
	t.Run("generic", func(t *testing.T) {
		srv, got := record("")
		send(t, hook(srv), notify.Normal)
		normal := (<-got).body
		send(t, hook(srv), notify.High)
		if high := (<-got).body; high != normal {
			t.Errorf("High changed the webhook body: %q, Normal sent %q", high, normal)
		}
	})
}
