package stakeout

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeFeed struct {
	mu  sync.Mutex
	evs []Event
}

func (f *fakeFeed) Enqueue(ev Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evs = append(f.evs, ev)
}

func (f *fakeFeed) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.evs)
}

func (f *fakeFeed) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evs = nil
}

func (f *fakeFeed) one(t *testing.T) Event {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.evs) != 1 {
		t.Fatalf("feed got %d events, want 1: %+v", len(f.evs), f.evs)
	}
	return f.evs[0]
}

// statusWriter is an access log's writer, as kit's is: it keeps the status and hands ReadFrom and Unwrap on.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) ReadFrom(src io.Reader) (int64, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(w.ResponseWriter, src)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// accessLog stands in for the app's access log: it hands every finished request to the feed, a panic as a 500
// (Recover sits inside it, as in the apps).
func accessLog(feed Feed, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		func() {
			defer func() {
				if recover() != nil {
					sw.WriteHeader(http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(sw, r)
		}()
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		feed.Enqueue(EventFrom(r, ip, sw.status, time.Since(start)))
	})
}

// feedChain is the apps' order: Recorder, the access log, the route recorder, the mux.
func feedChain(feed Feed, mux http.Handler, catchAll ...string) http.Handler {
	return Recorder(accessLog(feed, RecordRoute(mux, catchAll...)))
}

// Every contract field comes from where it should; the query, cookies, credentials and every other header stay in
// the app.
func TestFeedEventFields(t *testing.T) {
	feed := &fakeFeed{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/as/{asn}", func(w http.ResponseWriter, r *http.Request) {
		SetAccount(r.Context(), "acc_8f3a")
		SetError(r.Context(), "upstream_error")
		SetOp(r.Context(), "whois")
		SetError(r.Context(), "invalid_params")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "hello")
	})
	req := httptest.NewRequest("GET", "/api/v1/as/15169?q=secret-query", nil)
	req.RemoteAddr = "203.0.113.42:5555"
	for k, v := range map[string]string{
		"User-Agent":      "Mozilla/5.0 test",
		"Referer":         "https://search.example/results?q=private#frag",
		"Accept-Language": "de-CH",
		"Sec-Fetch-Site":  "none",
		"Sec-Fetch-Mode":  "navigate",
		"Sec-Fetch-Dest":  "document",
		"Sec-CH-UA":       `"Chromium";v="130"`,
		"Signature-Agent": `"https://chatgpt.com"`,
		"X-Request-ID":    "totp-credential",
		"Cookie":          "session=cookie-secret",
		"Authorization":   "Bearer auth-secret",
		"X-Admin-Token":   "admin-secret",
	} {
		req.Header.Set(k, v)
	}
	feedChain(feed, mux).ServeHTTP(httptest.NewRecorder(), req)

	ev := feed.one(t)
	want := Event{T: ev.T, IP: "203.0.113.42", UA: "Mozilla/5.0 test", Method: "GET", Path: "/api/v1/as/15169",
		Route: "GET /api/v1/as/{asn}", Status: 201, DurMS: ev.DurMS, Bytes: 5, Ref: "https://search.example/results",
		Lang: "de-CH", SFSite: "none", SFMode: "navigate", SFDest: "document", CHUA: `"Chromium";v="130"`,
		SigAgent: `"https://chatgpt.com"`, Account: "acc_8f3a", Op: "whois", Err: "invalid_params"}
	if ev != want {
		t.Errorf("event\n got %+v\nwant %+v", ev, want)
	}
	if ev.T <= 0 || ev.DurMS < 0 {
		t.Errorf("t %d, dur_ms %d", ev.T, ev.DurMS)
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-query", "private", "frag", "totp-credential", "cookie-secret",
		"auth-secret", "admin-secret"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("event carries %q: %s", secret, b)
		}
	}
}

// A panic is fed as the 500 it became, with the route it hit.
func TestFeedEventPanic(t *testing.T) {
	feed := &fakeFeed{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	feedChain(feed, mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/boom", nil))
	if ev := feed.one(t); ev.Status != 500 || ev.Route != "GET /boom" {
		t.Errorf("event %+v, want status 500, route GET /boom", ev)
	}
}

// No pattern matched (the mux's own 404/405), or a catch-all answered: the route stays empty.
func TestFeedEventNoRoute(t *testing.T) {
	feed := &fakeFeed{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /x", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	h := feedChain(feed, mux, "GET /")

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/x", nil))
	if ev := feed.one(t); ev.Route != "" || ev.Status != http.StatusMethodNotAllowed {
		t.Errorf("event %+v, want no route, 405", ev)
	}
	feed.reset()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/.env", nil))
	if ev := feed.one(t); ev.Route != "" || ev.Status != http.StatusNotFound {
		t.Errorf("event %+v, want no route (catch-all), 404", ev)
	}
	feed.reset()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	if ev := feed.one(t); ev.Route != "GET /x" {
		t.Errorf("event %+v, want route GET /x", ev)
	}
}

// Without Recorder outside, SetAccount, SetOp, SetError and RecordRoute do nothing and EventFrom still maps the request.
func TestFeedWithoutRecorder(t *testing.T) {
	feed := &fakeFeed{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /x", func(_ http.ResponseWriter, r *http.Request) {
		SetAccount(r.Context(), "acc")
		SetOp(r.Context(), "op")
		SetError(r.Context(), "code")
	})
	accessLog(feed, RecordRoute(mux)).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	if ev := feed.one(t); ev.Route != "" || ev.Account != "" || ev.Op != "" || ev.Err != "" || ev.Path != "/x" {
		t.Errorf("event %+v, want no route, no account, no op, no err, path /x", ev)
	}
}

// readFromRecorder is a ResponseWriter whose ReadFrom (net/http's: sendfile) records that it was used.
type readFromRecorder struct {
	*httptest.ResponseRecorder
	readFrom int64
}

func (w *readFromRecorder) ReadFrom(src io.Reader) (int64, error) {
	n, err := io.Copy(w.ResponseRecorder, src)
	w.readFrom += n
	return n, err
}

// A copy into the response reaches the real writer's ReadFrom through the access log's writer and the counter, so
// http.ServeFile keeps sendfile, and the counter still counts it.
func TestFeedCountingWriterKeepsReadFrom(t *testing.T) {
	feed := &fakeFeed{}
	mux := http.NewServeMux()
	const body = 5000
	mux.HandleFunc("GET /file", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		// A LimitedReader has no WriteTo: io.Copy goes to the writer's ReadFrom, as http.ServeContent's CopyN does.
		_, _ = io.Copy(w, io.LimitReader(strings.NewReader(strings.Repeat("x", body)), body))
	})
	rec := &readFromRecorder{ResponseRecorder: httptest.NewRecorder()}
	feedChain(feed, mux).ServeHTTP(rec, httptest.NewRequest("GET", "/file", nil))
	if rec.readFrom != body {
		t.Errorf("the writer's ReadFrom took %d bytes, want %d: sendfile lost", rec.readFrom, body)
	}
	if ev := feed.one(t); ev.Bytes != body {
		t.Errorf("bytes %d, want %d", ev.Bytes, body)
	}
}

// A file served over a real connection: the feed reports what the client received, flushes still work, and a HEAD
// counts none.
func TestFeedEventBytesServeFile(t *testing.T) {
	dir := t.TempDir()
	content := strings.Repeat("feed", 5000)
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	feed := &fakeFeed{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /f.txt", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(dir, "f.txt"))
	})
	mux.HandleFunc("GET /flush", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "a")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("Flush through the counting writer: %v", err)
		}
		_, _ = io.WriteString(w, "b")
	})
	srv := httptest.NewServer(feedChain(feed, mux))
	defer srv.Close()

	for _, tc := range []struct{ method, path string }{{"GET", "/f.txt"}, {"HEAD", "/f.txt"}, {"GET", "/flush"}} {
		feed.reset()
		req, _ := http.NewRequest(tc.method, srv.URL+tc.path, nil)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		received, _ := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		// The client can hold the whole body before the server's handler (and the access log) returns.
		deadline := time.Now().Add(5 * time.Second)
		for feed.count() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if ev := feed.one(t); ev.Bytes != received || ev.Status != 200 {
			t.Errorf("%s %s: bytes %d, status %d; want %d (received), 200", tc.method, tc.path, ev.Bytes, ev.Status,
				received)
		}
	}
}

func TestReferrer(t *testing.T) {
	for in, want := range map[string]string{
		"":                              "",
		"https://a.example/":            "https://a.example/",
		"https://a.example/p?q=1":       "https://a.example/p",
		"https://a.example/p#x":         "https://a.example/p",
		"https://a.example/p?q=1#x?y":   "https://a.example/p",
		"android-app://com.google.app/": "android-app://com.google.app/",
	} {
		if got := referrer(in); got != want {
			t.Errorf("referrer(%q) = %q, want %q", in, got, want)
		}
	}
}
