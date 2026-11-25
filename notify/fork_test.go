package notify_test

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nicholas-fedor/shoutrrr/pkg/types"

	"github.com/trick77/toolkit/notify"
)

// These pin what notify relies on, or works around, in shoutrrr itself, so a
// version bump that changes it fails here rather than in a channel.

func locate(t *testing.T, u string) types.Service {
	t.Helper()
	s, err := notify.Locate(u)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Every scheme of ours is still one of the fork's: services are opted in, so
// a fork upgrade that renames or drops one fails here, one that adds a
// service does not. Read from the router's source: importing the router
// would build every service again.
func TestForkServiceList(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/nicholas-fedor/shoutrrr").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	file := filepath.Join(strings.TrimSpace(string(out)), "pkg", "router", "servicemap.go")
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fork []string
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "serviceMap" || len(spec.Values) != 1 {
			return true
		}
		// Any other shape reads as fewer schemes and fails below.
		lit, ok := spec.Values[0].(*ast.CompositeLit)
		if !ok {
			return false
		}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.BasicLit)
			if !ok {
				continue
			}
			if s, err := strconv.Unquote(key.Value); err == nil {
				fork = append(fork, s)
			}
		}
		return false
	})
	if len(fork) < 10 {
		t.Fatalf("read %d schemes from %s: the fork moved its service map", len(fork), file)
	}
	for _, s := range notify.Schemes() {
		if !slices.Contains(fork, s) {
			t.Errorf("%q is gone from the fork", s)
		}
	}
}

// Channel URLs written for containrrr v0.8 (netra's live settings) still
// parse. ntfy's scheme=http is deprecated, read as disabletls=yes.
func TestForkReadsV08URLs(t *testing.T) {
	for _, u := range []string{
		"smtp://user:pass@mail.example.com:587/?fromaddress=a@example.com&toaddresses=b@example.com,c@example.com&usestarttls=yes",
		"ntfy://ntfy.example.com/alerts?scheme=http&priority=high",
		"pushover://shoutrrr:aTokenToken12345@uUserKey12345678/?devices=phone&priority=1",
		"gotify://gotify.example.com/sub/Abcdefghijklmno",
		"telegram://123456789:AAbbCCddEEff@telegram?chats=@channel,-1001234&parsemode=HTML",
		"generic+https://hooks.example.com/notify?token=abc",
	} {
		if _, err := notify.NewChannels([]string{u}); err != nil {
			t.Errorf("%s: %v", strings.SplitN(u, ":", 2)[0], err)
		}
	}
}

// v0.8's ntfy wrote a send's params into its own config: concurrent sends
// through one service crossed titles. notify builds a service per send but
// for a URL that skips TLS verification, which shares one (see below); this
// says whether the per-send rule still has to hold.
func TestForkServiceSendsConcurrently(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies = map[string]string{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies[string(b)] = r.Header.Get("Title")
		mu.Unlock()
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	defer srv.Close()
	s := locate(t, ntfyURL(srv, "")).(types.ContextSender)
	const n = 16
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			p := types.Params{types.TitleKey: fmt.Sprintf("title %d", i)}
			if err := s.SendContext(context.Background(), fmt.Sprintf("body %d", i), &p); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if len(bodies) != n {
		t.Fatalf("server saw %d messages, want %d", len(bodies), n)
	}
	for body, title := range bodies {
		if strings.TrimPrefix(body, "body ") != strings.TrimPrefix(title, "title ") {
			t.Errorf("%q went out titled %q", body, title)
		}
	}
}

// A URL that skips TLS verification shares one service (and its insecure
// client) across sends: concurrent sends through it, in every service that
// speaks HTTP, keep their own title and body. Run with -race.
func TestForkSharedServiceSendsConcurrently(t *testing.T) {
	numbered := regexp.MustCompile(`(title|body) (\d+)`)
	var (
		mu       sync.Mutex
		requests []string
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, r.Header.Get("Title")+" "+string(b))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true,"id":1,"result":{"message_id":1,"chat":{"id":1}}}`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	for name, u := range map[string]string{
		"ntfy":     "ntfy://" + host + "/topic?skiptlsverify=yes",
		"gotify":   "gotify://" + host + "/Abcdefghijklmno?skiptlsverify=yes",
		"generic":  "generic+https://" + host + "/hook?skiptlsverify=yes",
		"telegram": "telegram://123456789:AAbbCCddEEff@telegram?chats=1&skiptlsverify=yes&apiurl=" + url.QueryEscape(srv.URL),
	} {
		t.Run(name, func(t *testing.T) {
			mu.Lock()
			requests = nil
			mu.Unlock()
			c, err := notify.NewChannels([]string{u})
			if err != nil {
				t.Fatal(err)
			}
			const n = 8
			var wg sync.WaitGroup
			for i := range n {
				wg.Go(func() {
					if err := c.Send(fmt.Sprintf("title %d", i), fmt.Sprintf("body %d", i)); err != nil {
						t.Error(err)
					}
				})
			}
			wg.Wait()
			mu.Lock()
			defer mu.Unlock()
			if len(requests) != n {
				t.Fatalf("server saw %d messages, want %d", len(requests), n)
			}
			for _, req := range requests {
				seen := map[string]string{}
				for _, m := range numbered.FindAllStringSubmatch(req, -1) {
					seen[m[1]] = m[2]
				}
				if seen["body"] == "" || (seen["title"] != "" && seen["title"] != seen["body"]) {
					t.Errorf("crossed: %q", req)
				}
			}
		})
	}
}

// v0.8's transport errors quoted the request URL, a token in its path. The
// fork cuts it to scheme and host; notify scrubs regardless.
func TestForkErrorsOmitTheURL(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	addr := gone.URL
	gone.Close()
	for name, u := range map[string]string{
		"generic":  "generic+" + addr + "/bot123456:SECRETTOKEN/send?apikey=hunter2hunter2",
		"telegram": "telegram://123456:SECRETTOKEN@telegram?chats=1&apiurl=" + url.QueryEscape(addr),
	} {
		s := locate(t, u)
		err := s.(types.ContextSender).SendContext(context.Background(), "b", &types.Params{})
		if err == nil {
			t.Fatalf("%s: a closed port accepted the message", name)
		}
		t.Logf("%s: %v", name, err)
		for _, secret := range []string{"SECRETTOKEN", "hunter2hunter2"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the raw error quotes %q: %v", name, secret, err)
			}
		}
	}
}
