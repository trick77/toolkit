package stakeout

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// The feed's limits (Stakeout's contract) and the emitter's own.
const (
	maxBatch = 500       // events per request, Stakeout's limit
	maxBody  = 256 << 10 // request body bytes, Stakeout's limit

	bufferSize    = 4096             // events queued (a few KiB each at most); a full queue drops, never blocks a request
	flushInterval = 5 * time.Second  // a partial batch waits at most this long
	sendTimeout   = 5 * time.Second  // one POST, connect to last byte
	backoffMin    = 5 * time.Second  // first pause after a failed send, doubling per failure
	backoffMax    = 5 * time.Minute  // longest pause, Retry-After included
	statsInterval = 10 * time.Minute // the counters' log line
	// retryWindow is how long a batch is offered again after its first failure. Stakeout files an event whose t is
	// over an hour behind at the receive time instead, so an older batch would land at the wrong time: 45 minutes
	// leaves room for the batch's own age (up to flushInterval) and the last send.
	retryWindow = 45 * time.Minute
)

// Config says where the feed goes. Endpoint is Stakeout's origin + FeedPath.
type Config struct {
	Endpoint string
	Key      string
	Site     string
}

// tuning holds the limits; tests shrink them.
type tuning struct {
	bufferSize, maxBatch, maxBody                      int
	flushInterval, sendTimeout, backoffMin, backoffMax time.Duration
	statsInterval, retryWindow                         time.Duration
	now                                                func() time.Time
	onSend                                             func() // after a send's outcome is in place; tests only
}

func defaults() tuning {
	return tuning{
		bufferSize: bufferSize, maxBatch: maxBatch, maxBody: maxBody,
		flushInterval: flushInterval, sendTimeout: sendTimeout, backoffMin: backoffMin, backoffMax: backoffMax,
		statsInterval: statsInterval, retryWindow: retryWindow, now: time.Now,
	}
}

// Stats are the emitter's counters since start, in events.
type Stats struct {
	Sent    uint64 // accepted by Stakeout (2xx), on the first send or a later one
	Dropped uint64 // never sent: queue full, during a back-off, after shutdown, or no valid ip
	Failed  uint64 // sent and given up on: refused, or still failing when the retry window or shutdown ends it
}

// held is a batch that failed in a way Stakeout's contract says to send again (a network error, 408, 429, 5xx).
type held struct {
	body  []byte
	n     uint64
	until time.Time // the end of its retry window
}

// Emitter batches events to Stakeout's feed from one background goroutine. Enqueue never blocks. A batch that
// failed on the way (a network error, 408, 429, 5xx) is held and sent again after the pause (Retry-After, else a
// doubling back-off) for up to retryWindow; one Stakeout refused (400, 401, 413, anything else) is dropped. While a
// batch is held, one more batch fills behind it and what arrives past that is dropped: a struggling Stakeout gets
// the same traffic later, not more.
type Emitter struct {
	cfg    Config
	tun    tuning
	client *http.Client
	log    *slog.Logger
	prefix []byte // the body up to the events array

	ch       chan Event
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	stopped  atomic.Bool
	// hard cancels an in-flight send when Shutdown's deadline passes.
	hard       context.Context
	cancelHard context.CancelFunc

	sent, dropped, failed atomic.Uint64

	// Sender goroutine only.
	pending     [][]byte // encoded events
	pendingSize int      // their bytes, commas included
	retry       *held    // the batch to send again once the pause is over; pending waits behind it
	backoff     time.Duration
	resumeAt    time.Time
	failing     bool  // the last send failed: logged once, until one succeeds
	lastLogged  Stats // the counters at the last stats line
}

// Start runs the sender until Shutdown.
func Start(cfg Config, log *slog.Logger) *Emitter {
	return start(cfg, log, defaults(), nil)
}

func start(cfg Config, log *slog.Logger, tun tuning, transport http.RoundTripper) *Emitter {
	if log == nil {
		log = slog.Default()
	}
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	prefix, _ := json.Marshal(cfg.Site)
	hard, cancel := context.WithCancel(context.Background())
	e := &Emitter{
		cfg: cfg,
		tun: tun,
		client: &http.Client{
			Transport: transport,
			Timeout:   tun.sendTimeout,
			// A redirect is a misconfiguration, and following one would hand the key to wherever it points.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		log:        log,
		prefix:     append(append([]byte(`{"v":1,"site":`), prefix...), `,"events":[`...),
		ch:         make(chan Event, tun.bufferSize),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
		hard:       hard,
		cancelHard: cancel,
	}
	go e.run()
	return e
}

// Enqueue hands ev to the sender without blocking: a full queue, a stopped emitter, or an event Stakeout would refuse
// (an ip that is no address) drops it and counts the drop. What is queued is a sanitized copy: within Stakeout's field
// limits, sharing no memory with the request. A nil Emitter takes nothing.
func (e *Emitter) Enqueue(ev Event) {
	if e == nil {
		return
	}
	if e.stopped.Load() {
		e.dropped.Add(1)
		return
	}
	ev, ok := ev.sanitized()
	if !ok {
		e.dropped.Add(1)
		return
	}
	select {
	case e.ch <- ev:
	default:
		e.dropped.Add(1)
	}
}

// Stats reads the counters.
func (e *Emitter) Stats() Stats {
	return Stats{Sent: e.sent.Load(), Dropped: e.dropped.Load(), Failed: e.failed.Load()}
}

// Shutdown sends what is queued and stops the sender. When ctx ends first, the send in flight is cancelled and the
// rest dropped; Shutdown returns once the sender has exited either way.
func (e *Emitter) Shutdown(ctx context.Context) error {
	e.stopOnce.Do(func() {
		e.stopped.Store(true)
		close(e.stop)
	})
	select {
	case <-e.done:
		return nil
	case <-ctx.Done():
		e.cancelHard()
		<-e.done
		return ctx.Err()
	}
}

func (e *Emitter) run() {
	defer close(e.done)
	defer e.cancelHard()
	defer e.client.CloseIdleConnections()
	flush := time.NewTicker(e.tun.flushInterval)
	defer flush.Stop()
	stats := time.NewTicker(e.tun.statsInterval)
	defer stats.Stop()
	for {
		select {
		case ev := <-e.ch:
			e.add(ev)
		case <-flush.C:
			e.flush(false)
		case <-stats.C:
			e.logStats(false)
		case <-e.stop:
			// What was queued before the stop; an Enqueue racing it counts itself as dropped or lands here.
			for range len(e.ch) {
				e.add(<-e.ch)
			}
			e.flush(true)
			// Anything that slipped in after the drain: never sent.
			e.dropped.Add(uint64(len(e.ch)))
			e.logStats(true)
			return
		}
	}
}

// pausing reports whether a back-off is running.
func (e *Emitter) pausing() bool { return e.tun.now().Before(e.resumeAt) }

// add appends ev to the batch, sending first when ev would push it over a limit, and after when it fills it. With a
// batch held for a retry, the pending batch only fills: a full one drops what comes next until the held one is out.
func (e *Emitter) add(ev Event) {
	if e.retry != nil && !e.pausing() {
		e.flush(false) // the pause is over: the held batch goes first
	}
	if e.retry == nil && e.pausing() {
		e.dropped.Add(1)
		return
	}
	b, err := json.Marshal(ev)
	if err != nil { // cannot happen for Event's field types; counted all the same
		e.dropped.Add(1)
		return
	}
	envelope := len(e.prefix) + len("]}")
	if envelope+len(b) > e.tun.maxBody { // the field limits keep an event far below it; never send one Stakeout refuses
		e.dropped.Add(1)
		return
	}
	if len(e.pending) >= e.tun.maxBatch || len(e.pending) > 0 && envelope+e.pendingSize+1+len(b) > e.tun.maxBody {
		if e.retry != nil {
			e.dropped.Add(1)
			return
		}
		e.flush(false)
		if e.retry == nil && e.pausing() {
			e.dropped.Add(1)
			return
		}
	}
	if len(e.pending) > 0 {
		e.pendingSize++ // the comma
	}
	e.pending = append(e.pending, b)
	e.pendingSize += len(b)
	if len(e.pending) >= e.tun.maxBatch && e.retry == nil {
		e.flush(false)
	}
}

// flush sends the held batch when its pause is over, then the pending one. A pause without a held batch (Stakeout
// refused the feed) drops the pending batch. final (shutdown) sends each once, pause or not, and holds nothing.
func (e *Emitter) flush(final bool) {
	if r := e.retry; r != nil {
		if !final && e.pausing() {
			return
		}
		e.retry = nil
		if !e.send(r.body, r.n, r.until, final) {
			if final {
				e.dropPending()
			}
			return
		}
	}
	n := uint64(len(e.pending))
	if n == 0 {
		return
	}
	body := make([]byte, 0, len(e.prefix)+e.pendingSize+2)
	body = append(body, e.prefix...)
	body = append(body, bytes.Join(e.pending, []byte(","))...)
	body = append(body, "]}"...)
	clear(e.pending)
	e.pending, e.pendingSize = e.pending[:0], 0
	if !final && e.pausing() {
		e.dropped.Add(n)
		return
	}
	e.send(body, n, time.Time{}, final)
}

func (e *Emitter) dropPending() {
	e.dropped.Add(uint64(len(e.pending)))
	clear(e.pending)
	e.pending, e.pendingSize = e.pending[:0], 0
}

// send posts one batch of n events. until is the end of its retry window, zero for a first send. ok reports
// whether the next batch may go right after it: a success, or a refusal of this batch alone (400, 413).
func (e *Emitter) send(body []byte, n uint64, until time.Time, final bool) (ok bool) {
	if e.tun.onSend != nil {
		defer e.tun.onSend()
	}
	status, retryAfter, err := e.post(body)
	if err == nil && status >= 200 && status < 300 {
		e.backoff, e.resumeAt = 0, time.Time{}
		if e.failing {
			e.failing = false
			e.log.Info("stakeout feed recovered", "status", status)
		}
		e.sent.Add(n)
		return true
	}
	if err == nil {
		err = fmt.Errorf("status %d", status)
	}
	switch {
	case status == http.StatusBadRequest || status == http.StatusRequestEntityTooLarge:
		// This batch was refused, not the feed: dropped, no pause.
		e.noteFailure(err, "batch dropped", 0)
		e.failed.Add(n)
		return true
	case retryable(status):
		// The pause is in place before a counter moves: whoever sees the counter sees the pause.
		pause := e.pause(retryAfter)
		if until.IsZero() {
			until = e.tun.now().Add(e.tun.retryWindow)
		}
		if !final && e.resumeAt.Before(until) {
			e.retry = &held{body: body, n: n, until: until}
			e.noteFailure(err, "batch held for a retry", pause)
			return false
		}
		e.noteFailure(err, "batch dropped", pause)
	default:
		// 401 and the rest: Stakeout refuses the feed and will again, so the batch goes and the feed pauses.
		e.noteFailure(err, "batch dropped", e.pause(0))
	}
	e.failed.Add(n)
	return false
}

// retryable is the contract's "send the same batch again": no answer (status 0), 408, 429 or a 5xx.
func retryable(status int) bool {
	return status == 0 || status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500
}

// pause is the next back-off: Retry-After when the answer gave one, else doubling from backoffMin; capped.
func (e *Emitter) pause(retryAfter time.Duration) time.Duration {
	if e.backoff == 0 {
		e.backoff = e.tun.backoffMin
	} else {
		e.backoff = min(2*e.backoff, e.tun.backoffMax)
	}
	d := e.backoff
	if retryAfter > 0 {
		d = min(retryAfter, e.tun.backoffMax)
	}
	e.resumeAt = e.tun.now().Add(d)
	return d
}

// noteFailure logs the first failure of a run at warn and the rest at debug: a dead Stakeout must not flood the app's
// log.
func (e *Emitter) noteFailure(err error, what string, pause time.Duration) {
	lvl := slog.LevelDebug
	if !e.failing {
		e.failing = true
		lvl = slog.LevelWarn
	}
	e.log.Log(context.Background(), lvl, "stakeout feed send failed, "+what, "err", err, "pause", pause)
}

// post sends one batch. It returns the status and the Retry-After the answer asked for, if any.
func (e *Emitter) post(body []byte) (int, time.Duration, error) {
	ctx, cancel := context.WithTimeout(e.hard, e.tun.sendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+e.cfg.Key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, 0, err // names the URL, never the key (it travels in a header)
	}
	// Drain a little so the connection can be reused; Stakeout's answers are empty.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
	var retryAfter time.Duration
	if retryable(resp.StatusCode) {
		retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), e.tun.now())
	}
	return resp.StatusCode, retryAfter, nil
}

// parseRetryAfter reads delta-seconds or an HTTP date; 0 when absent or unreadable.
func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil {
		if s <= 0 {
			return 0
		}
		return time.Duration(min(s, 24*3600)) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// logStats writes the counters when they moved since the last line (always on the final one).
func (e *Emitter) logStats(final bool) {
	s := e.Stats()
	if !final && s == e.lastLogged {
		return
	}
	e.lastLogged = s
	msg := "stakeout feed"
	if final {
		msg = "stakeout feed stopped"
	}
	e.log.Info(msg, "sent", s.Sent, "dropped", s.Dropped, "failed", s.Failed)
}
