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

// excluded are the fork's schemes notify leaves out on purpose.
var excluded = []string{
	"mqtt", "mqtts", // paho, gorilla/websocket
	"xmpp", "xmpps", // mellium
	"logger", // writes to a log, not to a person
}

// Every scheme in the fork's router is in Schemes or excluded, so a fork
// upgrade that adds a service cannot leave it out unnoticed. Read from the
// router's source: importing the router would build every service again.
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
		for _, el := range spec.Values[0].(*ast.CompositeLit).Elts {
			key, _ := strconv.Unquote(el.(*ast.KeyValueExpr).Key.(*ast.BasicLit).Value)
			fork = append(fork, key)
		}
		return false
	})
	if len(fork) < 10 {
		t.Fatalf("read %d schemes from %s: the fork moved its service map", len(fork), file)
	}
	ours := notify.Schemes()
	for _, s := range fork {
		if !slices.Contains(ours, s) && !slices.Contains(excluded, s) {
			t.Errorf("the fork's %q is neither supported nor excluded", s)
		}
	}
	for _, s := range append(slices.Clone(ours), excluded...) {
		if !slices.Contains(fork, s) {
			t.Errorf("%q is gone from the fork", s)
		}
	}
	for _, s := range excluded {
		if slices.Contains(ours, s) {
			t.Errorf("%q is both supported and excluded", s)
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
		"discord://token@123456789012345678",
		"slack://T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
	} {
		if _, err := notify.NewChannels([]string{u}); err != nil {
			t.Errorf("%s: %v", strings.SplitN(u, ":", 2)[0], err)
		}
	}
}

// v0.8's ntfy wrote a send's params into its own config: concurrent sends
// through one service crossed titles. notify still builds a service per send;
// this says whether it still has to.
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
