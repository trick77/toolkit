package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCollector is Trakk's feed endpoint as a RoundTripper: it records every request and answers with respond.
type fakeCollector struct {
	mu      sync.Mutex
	reqs    []captured
	respond func(n int, r *http.Request) (*http.Response, error) // n counts from 0; nil answers 204
}

type captured struct {
	method, url string
	header      http.Header
	body        []byte
}

func (f *fakeCollector) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	n := len(f.reqs)
	f.reqs = append(f.reqs, captured{r.Method, r.URL.String(), r.Header.Clone(), body})
	respond := f.respond
	f.mu.Unlock()
	if respond == nil {
		return answer(http.StatusNoContent, nil), nil
	}
	return respond(n, r)
}

func (f *fakeCollector) requests() []captured {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reqs)
}

func answer(status int, h http.Header) *http.Response {
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(""))}
}

// clock is a settable time for the back-off.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

var testCfg = Config{Endpoint: "https://analytics.example/api/feed", Key: "feed-key-123"}

const testIP = "192.0.2.1"

// testTuning sends nothing on a timer unless a test asks for it.
func testTuning() tuning {
	t := defaults()
	t.flushInterval, t.statsInterval = time.Hour, time.Hour
	return t
}

func startTest(t *testing.T, tun tuning, f *fakeCollector) *Emitter {
	t.Helper()
	e := start(testCfg, slog.New(slog.DiscardHandler), tun, f)
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })
	return e
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func shutdown(t *testing.T, e *Emitter) {
	t.Helper()
	if err := e.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

type body struct {
	V      int              `json:"v"`
	Events []map[string]any `json:"events"`
}

func decode(t *testing.T, b []byte) body {
	t.Helper()
	var out body
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("body %q: %v", b, err)
	}
	return out
}

// contractFields is Trakk's field list: every event carries exactly these.
var contractFields = []string{"t", "ip", "ua", "method", "path", "route", "status", "dur_ms", "bytes", "ref", "lang",
	"sf_site", "sf_mode", "sf_dest", "ch_ua", "sig_agent", "account", "op", "err"}

func TestEmitterSendsTheContract(t *testing.T) {
	f := &fakeCollector{}
	e := startTest(t, testTuning(), f)
	ev := Event{T: 1795338999000, IP: "203.0.113.42", UA: "Mozilla/5.0", Method: "GET", Path: "/AS15169",
		Route: "GET /", Status: 200, DurMS: 12, Bytes: 5120, Ref: "https://example.com/", Lang: "de-CH",
		SFSite: "none", SFMode: "navigate", SFDest: "document", CHUA: `"Chromium";v="130"`,
		SigAgent: `"https://chatgpt.com"`, Account: "acc_8f3a", Op: "whois", Err: "invalid_params"}
	e.Enqueue(ev)
	shutdown(t, e)

	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests, want 1", len(reqs))
	}
	r := reqs[0]
	if r.method != "POST" || r.url != testCfg.Endpoint {
		t.Errorf("%s %s, want POST %s", r.method, r.url, testCfg.Endpoint)
	}
	if got := r.header.Get("Authorization"); got != "Bearer feed-key-123" {
		t.Errorf("Authorization = %q", got)
	}
	if got := r.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	b := decode(t, r.body)
	if b.V != 1 || len(b.Events) != 1 {
		t.Fatalf("body = %+v", b)
	}
	if !bytes.HasPrefix(r.body, []byte(`{"v":1,"events":[{`)) {
		t.Errorf("body %s: want no site, the key says it", r.body)
	}
	got := b.Events[0]
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	want := slices.Sorted(slices.Values(contractFields))
	if !slices.Equal(keys, want) {
		t.Errorf("event fields %v, want exactly %v", keys, want)
	}
	for k, v := range map[string]any{"t": 1795338999000.0, "ip": "203.0.113.42", "path": "/AS15169", "route": "GET /",
		"status": 200.0, "dur_ms": 12.0, "bytes": 5120.0, "lang": "de-CH", "sf_mode": "navigate",
		"ch_ua": `"Chromium";v="130"`, "sig_agent": `"https://chatgpt.com"`, "account": "acc_8f3a", "op": "whois", "err": "invalid_params"} {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if s := e.Stats(); s.Sent != 1 || s.Dropped != 0 || s.Failed != 0 {
		t.Errorf("stats %+v, want 1 sent", s)
	}
}

// A batch goes out when it is full, the rest on shutdown.
func TestEmitterBatchesByCount(t *testing.T) {
	f := &fakeCollector{}
	tun := testTuning()
	tun.maxBatch = 3
	e := startTest(t, tun, f)
	for i := range 7 {
		e.Enqueue(Event{IP: testIP, Path: "/" + strings.Repeat("x", i)})
	}
	waitFor(t, "two full batches", func() bool { return len(f.requests()) == 2 })
	shutdown(t, e)
	var sizes []int
	for _, r := range f.requests() {
		sizes = append(sizes, len(decode(t, r.body).Events))
	}
	if !slices.Equal(sizes, []int{3, 3, 1}) {
		t.Errorf("batch sizes %v, want [3 3 1]", sizes)
	}
	if s := e.Stats(); s.Sent != 7 {
		t.Errorf("stats %+v, want 7 sent", s)
	}
}

// No body exceeds the byte limit, however the events add up; none is lost to the split.
func TestEmitterBatchesByBytes(t *testing.T) {
	f := &fakeCollector{}
	tun := testTuning()
	tun.maxBody = 2048
	e := startTest(t, tun, f)
	for range 20 {
		e.Enqueue(Event{IP: testIP, UA: strings.Repeat("u", 400), Ref: strings.Repeat("\x01", 50)}) // escaped: 300 B
	}
	shutdown(t, e)
	total := 0
	for _, r := range f.requests() {
		if len(r.body) > tun.maxBody {
			t.Errorf("body of %d bytes, limit %d", len(r.body), tun.maxBody)
		}
		total += len(decode(t, r.body).Events)
	}
	if total != 20 || len(f.requests()) < 2 {
		t.Errorf("%d events in %d requests, want 20 in several", total, len(f.requests()))
	}
}

// The real limits hold for the largest event a request can produce.
func TestEmitterLimitsFitTheContract(t *testing.T) {
	huge := strings.Repeat("\x01", 100_000) // a control character escapes to six bytes
	ev, ok := Event{IP: testIP, UA: huge, Method: huge, Path: huge, Route: huge, Ref: huge, Lang: huge, SFSite: huge,
		SFMode: huge, SFDest: huge, CHUA: huge, SigAgent: huge, Account: huge, Op: huge, Err: huge}.sanitized()
	if !ok {
		t.Fatal("sanitized refused a valid ip")
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > maxBody/4 {
		t.Errorf("largest event %d bytes, want far below the %d body limit", len(b), maxBody)
	}
	if maxBatch > 500 || maxBody > 256<<10 {
		t.Errorf("limits %d events / %d bytes exceed Trakk's 500 / 256 KiB", maxBatch, maxBody)
	}
}

// A timer sends a partial batch.
func TestEmitterFlushesOnTimer(t *testing.T) {
	f := &fakeCollector{}
	tun := testTuning()
	tun.flushInterval = 10 * time.Millisecond
	e := startTest(t, tun, f)
	e.Enqueue(Event{IP: testIP, Path: "/"})
	waitFor(t, "the timer's send", func() bool { return e.Stats().Sent == 1 })
	if n := len(f.requests()); n != 1 {
		t.Errorf("%d requests, want 1", n)
	}
}

// Enqueue never blocks: with the sender stuck in a send, a full queue drops and counts.
func TestEmitterDropsWhenFull(t *testing.T) {
	release := make(chan struct{})
	f := &fakeCollector{respond: func(_ int, r *http.Request) (*http.Response, error) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		return answer(http.StatusNoContent, nil), nil
	}}
	tun := testTuning()
	tun.bufferSize, tun.maxBatch = 4, 1
	e := startTest(t, tun, f)
	e.Enqueue(Event{IP: testIP, Path: "/first"})
	waitFor(t, "the stuck send", func() bool { return len(f.requests()) == 1 })

	done := make(chan struct{})
	go func() {
		for range 100 {
			e.Enqueue(Event{IP: testIP, Path: "/more"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Enqueue blocked")
	}
	if s := e.Stats(); s.Dropped != 100-4 {
		t.Errorf("dropped %d, want %d (the queue holds 4)", s.Dropped, 100-4)
	}
	close(release)
	shutdown(t, e)
	if s := e.Stats(); s.Sent != 5 || s.Dropped != 96 {
		t.Errorf("stats %+v, want 5 sent, 96 dropped", s)
	}
}

// countSends counts the sends whose outcome (pause, backlog, counters) is in place: a test moves the clock only after
// that, or the pause would start from the moved clock.
func countSends(tun *tuning) *atomic.Int64 {
	var n atomic.Int64
	tun.onSend = func() { n.Add(1) }
	return &n
}

// countAdds counts the events in the backlog once the sender has done with them: a test moves the clock only then, or
// they would count as arrived after the pause.
func countAdds(tun *tuning) *atomic.Int64 {
	var n atomic.Int64
	tun.onTurn = n.Store
	return &n
}

// paths lists the events' paths of every request, in order.
func paths(t *testing.T, reqs []captured) [][]string {
	t.Helper()
	var out [][]string
	for _, r := range reqs {
		var ps []string
		for _, ev := range decode(t, r.body).Events {
			ps = append(ps, ev["path"].(string))
		}
		out = append(out, ps)
	}
	return out
}

// A 429 holds the batch for Retry-After and sends it again; what arrives meanwhile waits behind it, however much.
func TestEmitterRetriesAfter429(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	f := &fakeCollector{respond: func(n int, _ *http.Request) (*http.Response, error) {
		if n == 0 {
			return answer(http.StatusTooManyRequests, http.Header{"Retry-After": {"30"}}), nil
		}
		return answer(http.StatusNoContent, nil), nil
	}}
	tun := testTuning()
	tun.maxBatch, tun.now = 2, c.now
	sends, adds := countSends(&tun), countAdds(&tun)
	e := startTest(t, tun, f)

	e.Enqueue(Event{IP: testIP, Path: "/1"})
	e.Enqueue(Event{IP: testIP, Path: "/2"})
	waitFor(t, "the 429", func() bool { return sends.Load() == 1 })
	c.add(29 * time.Second)
	for _, p := range []string{"/3", "/4", "/5"} {
		e.Enqueue(Event{IP: testIP, Path: p})
	}
	waitFor(t, "the events behind the held batch", func() bool { return adds.Load() == 5 })
	if n := len(f.requests()); n != 1 {
		t.Fatalf("%d requests during the pause, want only the refused one", n)
	}
	if s := e.Stats(); s.Failed != 0 || s.Dropped != 0 {
		t.Errorf("stats %+v: nothing is lost yet", s)
	}
	c.add(2 * time.Second)
	e.Enqueue(Event{IP: testIP, Path: "/6"}) // the pause is over: the held batch first, then what waits behind it
	waitFor(t, "everything", func() bool { return e.Stats().Sent == 6 })
	shutdown(t, e)
	got := paths(t, f.requests())
	want := [][]string{{"/1", "/2"}, {"/1", "/2"}, {"/3", "/4"}, {"/5", "/6"}}
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("requests %v, want %v", got, want)
	}
	if s := e.Stats(); s.Sent != 6 || s.Dropped != 0 || s.Failed != 0 {
		t.Errorf("stats %+v, want 6 sent", s)
	}
}

// Any other failure holds the batch too (a proxy's 404 while Trakk is being recreated, a redirect, never followed), the
// pause doubling per failure; a success sends it and ends the pause.
func TestEmitterRetriesOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		respond func(int, *http.Request) (*http.Response, error)
	}{
		{"503", func(int, *http.Request) (*http.Response, error) {
			return answer(http.StatusServiceUnavailable, nil), nil
		}},
		{"408", func(int, *http.Request) (*http.Response, error) { return answer(http.StatusRequestTimeout, nil), nil }},
		{"404", func(int, *http.Request) (*http.Response, error) { return answer(http.StatusNotFound, nil), nil }},
		{"redirect", func(int, *http.Request) (*http.Response, error) {
			return answer(http.StatusFound, http.Header{"Location": {"https://elsewhere.example/"}}), nil
		}},
		{"network", func(int, *http.Request) (*http.Response, error) { return nil, errors.New("connection refused") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &clock{t: time.Unix(1_800_000_000, 0)}
			var mu sync.Mutex
			fail := true
			f := &fakeCollector{respond: func(n int, r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if fail {
					return tc.respond(n, r)
				}
				return answer(http.StatusNoContent, nil), nil
			}}
			tun := testTuning()
			tun.maxBatch, tun.now, tun.backoffMin = 1, c.now, time.Minute
			sends, adds := countSends(&tun), countAdds(&tun)
			e := startTest(t, tun, f)

			e.Enqueue(Event{IP: testIP, Path: "/1"})
			waitFor(t, "the failure", func() bool { return sends.Load() == 1 })
			c.add(time.Minute)
			e.Enqueue(Event{IP: testIP, Path: "/2"}) // the retry, failing again; /2 waits behind it
			waitFor(t, "the second failure", func() bool { return sends.Load() == 2 })
			c.add(time.Minute) // the pause doubled: still on
			e.Enqueue(Event{IP: testIP, Path: "/3"})
			waitFor(t, "/3 in the backlog", func() bool { return adds.Load() == 3 })
			mu.Lock()
			fail = false
			mu.Unlock()
			c.add(time.Minute)
			e.Enqueue(Event{IP: testIP, Path: "/4"})
			waitFor(t, "the recovery", func() bool { return e.Stats().Sent == 4 })
			shutdown(t, e)
			got := paths(t, f.requests())
			want := [][]string{{"/1"}, {"/1"}, {"/1"}, {"/2"}, {"/3"}, {"/4"}}
			if !slices.EqualFunc(got, want, slices.Equal) {
				t.Errorf("requests %v, want %v", got, want)
			}
			if s := e.Stats(); s.Sent != 4 || s.Dropped != 0 || s.Failed != 0 {
				t.Errorf("stats %+v, want 4 sent", s)
			}
		})
	}
}

// An event is given up at its own age, whenever its batch was first sent: one that would reach Trakk over an hour old
// would be dated at receipt. One old when it arrived (a stream that ran for hours) goes out all the same.
func TestEmitterGivesUpByAge(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	var mu sync.Mutex
	fail := true
	f := &fakeCollector{respond: func(int, *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return answer(http.StatusServiceUnavailable, nil), nil
		}
		return answer(http.StatusNoContent, nil), nil
	}}
	tun := testTuning()
	tun.maxBatch, tun.now, tun.backoffMin, tun.backoffMax = 1, c.now, 20*time.Minute, 20*time.Minute
	sends, adds := countSends(&tun), countAdds(&tun)
	e := startTest(t, tun, f)
	at := func(ago time.Duration, path string) Event {
		return Event{IP: testIP, Path: path, T: c.now().Add(-ago).UnixMilli()}
	}
	e.Enqueue(at(0, "/tried"))
	waitFor(t, "the failure", func() bool { return sends.Load() == 1 })
	c.add(10 * time.Minute)
	e.Enqueue(at(30*time.Minute, "/long")) // 30 minutes old when it ended: 25 left, its batch never sent
	e.Enqueue(at(3*time.Hour, "/stream"))
	e.Enqueue(at(0, "/fresh"))
	waitFor(t, "the events", func() bool { return adds.Load() == 4 })
	mu.Lock()
	fail = false
	mu.Unlock()
	c.add(45 * time.Minute) // /tried is 55 minutes old now, /long 75
	e.Enqueue(at(0, "/new"))
	waitFor(t, "the recovery", func() bool { return e.Stats().Sent == 3 })
	shutdown(t, e)
	got := paths(t, f.requests())
	want := [][]string{{"/tried"}, {"/stream"}, {"/fresh"}, {"/new"}}
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("requests %v, want %v", got, want)
	}
	if s := e.Stats(); s.Failed != 1 || s.Dropped != 1 {
		t.Errorf("stats %+v, want 1 failed (tried), 1 dropped (never sent)", s)
	}
}

// How long an event lives, by its age on arrival: never less than minLife, or a request nearly maxAge long would be
// given up before its first send.
func TestExpires(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	tun := defaults()
	tun.now = c.now
	e := newEmitter(testCfg, nil, tun, &fakeCollector{})
	for age, want := range map[time.Duration]time.Duration{0: maxAge, 30 * time.Minute: 25 * time.Minute,
		54 * time.Minute: minLife, maxAge - time.Second: minLife, maxAge: maxAge, 5 * time.Hour: maxAge} {
		if got := e.expires(Event{T: c.now().Add(-age).UnixMilli()}).Sub(c.now()); got != want {
			t.Errorf("an event %v old on arrival lives %v, want %v", age, got, want)
		}
	}
}

// What arrives during a flush waits for its own turn: steady traffic is batched, and the flush ends.
func TestFlushEndsUnderSteadyTraffic(t *testing.T) {
	tun := testTuning()
	f := &fakeCollector{}
	e := newEmitter(testCfg, slog.New(slog.DiscardHandler), tun, f)
	f.respond = func(int, *http.Request) (*http.Response, error) {
		e.Enqueue(Event{IP: testIP, Path: "/meanwhile"})
		return answer(http.StatusNoContent, nil), nil
	}
	e.add(Event{IP: testIP, Path: "/1"})
	e.add(Event{IP: testIP, Path: "/2"})
	e.flush(true)
	if got, want := paths(t, f.requests()), [][]string{{"/1", "/2"}}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("requests %v, want %v", got, want)
	}
	if len(e.backlog) != 1 {
		t.Errorf("%d events wait, want the one that arrived meanwhile", len(e.backlog))
	}
}

// A 400 after an outage is an answer: the pause is over, and events are batched again rather than sent one by one.
func TestRefusalEndsThePause(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	tun := testTuning()
	tun.now = c.now
	f := &fakeCollector{respond: func(n int, _ *http.Request) (*http.Response, error) {
		if n == 0 {
			return answer(http.StatusNotFound, nil), nil
		}
		return answer(http.StatusBadRequest, nil), nil
	}}
	e := newEmitter(testCfg, slog.New(slog.DiscardHandler), tun, f)
	e.add(Event{IP: testIP, Path: "/1"})
	e.flush(true)
	if e.backoff == 0 || !e.pausing() {
		t.Fatal("no pause after the 404")
	}
	c.add(time.Minute)
	e.flush(true)
	if e.backoff != 0 || e.pausing() || len(e.backlog) != 0 || e.Stats().Failed != 1 {
		t.Errorf("backoff %v, pausing %v, %d waiting, stats %+v after the 400", e.backoff, e.pausing(), len(e.backlog), e.Stats())
	}
}

// A batch a firewall refuses for what is in it (403) goes, and what waits behind it gets through.
func TestRefusedBatchDoesNotBlockTheFeed(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	tun := testTuning()
	tun.maxBatch, tun.now = 1, c.now
	f := &fakeCollector{respond: func(n int, _ *http.Request) (*http.Response, error) {
		if n == 0 {
			return answer(http.StatusForbidden, nil), nil
		}
		return answer(http.StatusNoContent, nil), nil
	}}
	e := newEmitter(testCfg, slog.New(slog.DiscardHandler), tun, f)
	e.add(Event{IP: testIP, Path: "/../../etc/passwd"})
	e.add(Event{IP: testIP, Path: "/fine"})
	e.flush(true)
	c.add(time.Minute)
	e.flush(true)
	if s := e.Stats(); s.Sent != 1 || s.Failed != 1 || s.Dropped != 0 {
		t.Errorf("stats %+v, want 1 sent, 1 failed", s)
	}
}

// The backlog is bounded in bytes: the oldest go.
func TestEmitterBoundsTheBacklog(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	f := &fakeCollector{respond: func(n int, _ *http.Request) (*http.Response, error) {
		if n == 0 {
			return answer(http.StatusServiceUnavailable, nil), nil
		}
		return answer(http.StatusNoContent, nil), nil
	}}
	tun := testTuning()
	tun.maxBatch, tun.now = 1, c.now
	one, err := json.Marshal(Event{IP: testIP, Path: "/1"})
	if err != nil {
		t.Fatal(err)
	}
	tun.maxBacklog = 3 * (len(one) + 1)
	sends, adds := countSends(&tun), countAdds(&tun)
	e := startTest(t, tun, f)
	e.Enqueue(Event{IP: testIP, Path: "/1"})
	waitFor(t, "the failure", func() bool { return sends.Load() == 1 })
	for _, p := range []string{"/2", "/3", "/4", "/5"} {
		e.Enqueue(Event{IP: testIP, Path: p})
	}
	waitFor(t, "the events", func() bool { return adds.Load() == 5 })
	if s := e.Stats(); s.Failed != 1 || s.Dropped != 1 {
		t.Errorf("stats %+v, want /1 failed and /2 dropped", s)
	}
	c.add(time.Hour / 2)
	shutdown(t, e)
	if got, want := paths(t, f.requests()), [][]string{{"/1"}, {"/3"}, {"/4"}, {"/5"}}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("requests %v, want %v", got, want)
	}
	if e.size != 0 || len(e.backlog) != 0 {
		t.Errorf("%d events, %d bytes left", len(e.backlog), e.size)
	}
}

// A 401 means Trakk refuses the feed: the batch is dropped, never sent again, and the feed pauses, doubling. What
// arrives meanwhile waits: a success ends the pause and takes it along.
func TestEmitterDropsRefusedFeed(t *testing.T) {
	c := &clock{t: time.Unix(1_800_000_000, 0)}
	var mu sync.Mutex
	fail := true
	f := &fakeCollector{respond: func(int, *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return answer(http.StatusUnauthorized, nil), nil
		}
		return answer(http.StatusNoContent, nil), nil
	}}
	tun := testTuning()
	tun.maxBatch, tun.now, tun.backoffMin = 1, c.now, time.Minute
	adds := countAdds(&tun)
	e := startTest(t, tun, f)

	e.Enqueue(Event{IP: testIP, Path: "/1"})
	waitFor(t, "the failure", func() bool { return e.Stats().Failed == 1 })
	e.Enqueue(Event{IP: testIP, Path: "/2"})
	waitFor(t, "/2 in the backlog", func() bool { return adds.Load() == 2 })
	c.add(time.Minute)
	e.Enqueue(Event{IP: testIP, Path: "/3"})
	waitFor(t, "the second failure", func() bool { return e.Stats().Failed == 2 })
	c.add(time.Minute) // the pause doubled: still on
	e.Enqueue(Event{IP: testIP, Path: "/4"})
	waitFor(t, "/4 in the backlog", func() bool { return adds.Load() == 4 })
	mu.Lock()
	fail = false
	mu.Unlock()
	c.add(time.Minute)
	e.Enqueue(Event{IP: testIP, Path: "/5"})
	waitFor(t, "the recovery", func() bool { return e.Stats().Sent == 3 })
	e.Enqueue(Event{IP: testIP, Path: "/6"}) // the pause is over: no wait
	waitFor(t, "the next send", func() bool { return e.Stats().Sent == 4 })
	shutdown(t, e)
	got := paths(t, f.requests())
	if want := [][]string{{"/1"}, {"/2"}, {"/3"}, {"/4"}, {"/5"}, {"/6"}}; !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("requests %v, want %v", got, want)
	}
	if s := e.Stats(); s.Failed != 2 || s.Dropped != 0 {
		t.Errorf("stats %+v, want 2 failed", s)
	}
}

// Shutdown sends the whole backlog once more, pause or not, and stops at the first failure.
func TestEmitterShutdownSendsTheBacklog(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		ok                    bool
		sent, failed, dropped uint64
	}{{"Trakk back", true, 3, 0, 0}, {"Trakk still away", false, 0, 1, 2}} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeCollector{respond: func(n int, _ *http.Request) (*http.Response, error) {
				if n == 0 || !tc.ok {
					return answer(http.StatusServiceUnavailable, nil), nil
				}
				return answer(http.StatusNoContent, nil), nil
			}}
			tun := testTuning()
			tun.maxBatch, tun.backoffMin = 1, time.Hour
			sends, adds := countSends(&tun), countAdds(&tun)
			e := startTest(t, tun, f)
			e.Enqueue(Event{IP: testIP, Path: "/1"})
			waitFor(t, "the failure", func() bool { return sends.Load() == 1 })
			e.Enqueue(Event{IP: testIP, Path: "/2"})
			e.Enqueue(Event{IP: testIP, Path: "/3"})
			waitFor(t, "the events", func() bool { return adds.Load() == 3 })
			shutdown(t, e)
			if s := e.Stats(); s.Sent != tc.sent || s.Failed != tc.failed || s.Dropped != tc.dropped {
				t.Errorf("stats %+v, want %d sent, %d failed, %d dropped", s, tc.sent, tc.failed, tc.dropped)
			}
		})
	}
}

// The run's first 401 warns even when Trakk was away before it: it needs a hand.
func TestEmitterWarnsOfARefusalAfterAnOutage(t *testing.T) {
	var buf safeBuffer
	f := &fakeCollector{respond: func(n int, _ *http.Request) (*http.Response, error) {
		if n == 0 {
			return answer(http.StatusBadGateway, nil), nil
		}
		return answer(http.StatusUnauthorized, nil), nil
	}}
	tun := testTuning()
	tun.maxBatch, tun.backoffMin, tun.backoffMax = 1, time.Nanosecond, time.Nanosecond
	sends := countSends(&tun)
	e := start(testCfg, slog.New(slog.NewTextHandler(&buf, nil)), tun, f)
	e.Enqueue(Event{IP: testIP, Path: "/1"})
	waitFor(t, "the outage", func() bool { return sends.Load() >= 1 })
	time.Sleep(time.Millisecond)
	e.Enqueue(Event{IP: testIP, Path: "/2"})
	waitFor(t, "the refusals", func() bool { return sends.Load() >= 2 })
	shutdown(t, e)
	if out := buf.String(); strings.Count(out, "status 502") != 1 || strings.Count(out, "status 401") != 1 {
		t.Errorf("want one warning each for the 502 and the 401:\n%s", out)
	}
}

// A refused batch (400, 413) is that batch's fault: dropped, no pause.
func TestEmitterNoPauseOnBadBatch(t *testing.T) {
	f := &fakeCollector{respond: func(n int, _ *http.Request) (*http.Response, error) {
		if n == 0 {
			return answer(http.StatusRequestEntityTooLarge, nil), nil
		}
		return answer(http.StatusNoContent, nil), nil
	}}
	tun := testTuning()
	tun.maxBatch = 1
	e := startTest(t, tun, f)
	e.Enqueue(Event{IP: testIP, Path: "/1"})
	e.Enqueue(Event{IP: testIP, Path: "/2"})
	shutdown(t, e)
	if s := e.Stats(); s.Failed != 1 || s.Sent != 1 || s.Dropped != 0 {
		t.Errorf("stats %+v, want 1 failed, 1 sent", s)
	}
}

func TestPause(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	tun := defaults()
	tun.now = c.now
	e := &Emitter{tun: tun}
	var got []time.Duration
	for range 9 {
		got = append(got, e.pause(0))
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	if !slices.Equal(got, want) {
		t.Errorf("pauses %v, want %v", got, want)
	}
	if d := e.pause(42 * time.Second); d != 42*time.Second {
		t.Errorf("Retry-After 42s: pause %v", d)
	}
	if d := e.pause(3 * time.Hour); d != backoffMax {
		t.Errorf("Retry-After 3h: pause %v, want the cap %v", d, backoffMax)
	}
	if !e.resumeAt.Equal(c.now().Add(backoffMax)) {
		t.Errorf("resumeAt %v", e.resumeAt)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		v    string
		want time.Duration
	}{
		{"", 0}, {"junk", 0}, {"-5", 0}, {"0", 0}, {"30", 30 * time.Second},
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0},
	} {
		if got := parseRetryAfter(tc.v, now); got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

// Shutdown sends what is queued, even with the timer far off, and stops the sender: no goroutine outlives it.
func TestEmitterShutdownFlushesAndLeavesNoGoroutine(t *testing.T) {
	before := runtime.NumGoroutine()
	f := &fakeCollector{}
	e := start(testCfg, slog.New(slog.DiscardHandler), testTuning(), f)
	e.Enqueue(Event{IP: testIP, Path: "/a"})
	e.Enqueue(Event{IP: testIP, Path: "/b"})
	shutdown(t, e)
	reqs := f.requests()
	if len(reqs) != 1 || len(decode(t, reqs[0].body).Events) != 2 {
		t.Fatalf("requests %d, want one with both events", len(reqs))
	}
	select {
	case <-e.done:
	default:
		t.Fatal("sender still running after Shutdown")
	}
	waitFor(t, "the goroutine count to settle", func() bool { return runtime.NumGoroutine() <= before })

	e.Enqueue(Event{IP: testIP, Path: "/late"}) // after shutdown: counted, never sent, no panic
	if s := e.Stats(); s.Dropped != 1 || s.Sent != 2 {
		t.Errorf("stats %+v, want the late event dropped", s)
	}
	shutdown(t, e) // twice is fine
}

// A shutdown deadline cuts the send in flight; Shutdown still returns only after the sender is gone.
func TestEmitterShutdownDeadline(t *testing.T) {
	f := &fakeCollector{respond: func(_ int, r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	}}
	tun := testTuning()
	tun.sendTimeout = time.Hour
	e := start(testCfg, slog.New(slog.DiscardHandler), tun, f)
	e.Enqueue(Event{IP: testIP, Path: "/stuck"})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := e.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Shutdown = %v, want the deadline", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Shutdown took %v", d)
	}
	select {
	case <-e.done:
	default:
		t.Fatal("sender still running after Shutdown")
	}
	if s := e.Stats(); s.Failed != 1 {
		t.Errorf("stats %+v, want the cut send failed", s)
	}
}

func TestNilEmitterTakesNothing(*testing.T) {
	var e *Emitter
	e.Enqueue(Event{}) // no panic
}

// The counters reach the log; the key never does, not even when Trakk refuses it.
func TestEmitterLogs(t *testing.T) {
	var buf safeBuffer
	f := &fakeCollector{respond: func(n int, _ *http.Request) (*http.Response, error) {
		if n == 0 {
			return answer(http.StatusUnauthorized, nil), nil
		}
		return answer(http.StatusNoContent, nil), nil
	}}
	tun := testTuning()
	tun.maxBatch, tun.backoffMin = 1, time.Nanosecond
	e := start(testCfg, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), tun, f)
	e.Enqueue(Event{IP: testIP, Path: "/1"})
	waitFor(t, "the failure", func() bool { return e.Stats().Failed == 1 })
	time.Sleep(time.Millisecond)
	e.Enqueue(Event{IP: testIP, Path: "/2"})
	waitFor(t, "the recovery", func() bool { return e.Stats().Sent == 1 })
	shutdown(t, e)
	out := buf.String()
	for _, want := range []string{"analytics feed send failed", "status 401", "analytics feed recovered",
		"analytics feed stopped", "sent=1", "failed=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, testCfg.Key) {
		t.Errorf("log carries the key:\n%s", out)
	}
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
