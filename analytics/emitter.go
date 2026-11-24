package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// The feed's limits (Trakk's contract) and the emitter's own.
const (
	maxBatch = 500       // events per request, Trakk's limit
	maxBody  = 256 << 10 // request body bytes, Trakk's limit

	bufferSize    = 4096            // events queued (a few KiB each at most); a full queue drops, never blocks a request
	flushInterval = 5 * time.Second // a partial batch waits at most this long
	// sendTimeout is one POST, connect to last byte: the contract's 30 s, Trakk's own body timeout. Shorter, a
	// batch Trakk is still committing times out and goes again, and Trakk keeps both copies (no dedup).
	// Meanwhile the queue takes what arrives; Shutdown's context bounds the last send, not this.
	sendTimeout   = 30 * time.Second
	backoffMin    = 5 * time.Second  // first pause after a failed send, doubling per failure
	backoffMax    = 5 * time.Minute  // longest pause, Retry-After included
	statsInterval = 10 * time.Minute // the counters' log line
	// maxBacklog bounds the encoded events waiting to be sent, in bytes (an event's size is the client's doing: JSON
	// escapes a byte to six): past it the oldest go, so a long outage costs history, never memory.
	maxBacklog = 4 << 20
	// maxAge is when an event is given up. Trakk files one whose t is over an hour behind at the receive time instead,
	// so it would land at the wrong time: 55 minutes leave room for the last send. A request nearly that old when it
	// ended (a stream) gets minLife all the same: dated a little late beats lost.
	maxAge  = 55 * time.Minute
	minLife = 2 * backoffMax
)

// Config says where the feed goes. Endpoint is Trakk's origin + FeedPath.
type Config struct {
	Endpoint string
	Key      string
	Site     string
}

// tuning holds the limits; tests shrink them.
type tuning struct {
	bufferSize, maxBatch, maxBody, maxBacklog          int
	flushInterval, sendTimeout, backoffMin, backoffMax time.Duration
	statsInterval, maxAge, minLife                     time.Duration
	now                                                func() time.Time
	onSend                                             func()            // after a send's outcome is in place; tests only
	onTurn                                             func(added int64) // after a turn of run's loop, its flush included; tests only
}

func defaults() tuning {
	return tuning{
		bufferSize: bufferSize, maxBatch: maxBatch, maxBody: maxBody, maxBacklog: maxBacklog,
		flushInterval: flushInterval, sendTimeout: sendTimeout, backoffMin: backoffMin, backoffMax: backoffMax,
		statsInterval: statsInterval, maxAge: maxAge, minLife: minLife, now: time.Now,
	}
}

// Stats are the emitter's counters since start, in events.
type Stats struct {
	Sent    uint64 // accepted by Trakk (2xx), on the first send or a later one
	Dropped uint64 // never sent: queue or backlog full, too old, after shutdown, or no valid ip
	Failed  uint64 // sent and given up on: refused, or still failing when its age, the backlog's bound or shutdown ends it
}

// item is an encoded event in the backlog.
type item struct {
	b       []byte
	expires time.Time
	tried   bool // sent at least once
}

// Emitter batches events to Trakk's feed from one background goroutine. Enqueue never blocks. Events wait in one
// bounded backlog, oldest first out. A batch that failed because Trakk is away (retryable) stays and goes again after
// the pause (Retry-After, else a doubling back-off), each event until maxAge. One that was refused is dropped: a 400 or
// 413 is that batch's fault, anything else (401, a firewall's 403) pauses the feed too, the events behind it waiting.
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
	backlog        []item
	size           int           // the backlog's bytes, a comma per event included
	added, removed int64         // events into and out of the backlog since start
	backoff        time.Duration // the last pause; 0 once Trakk answers
	resumeAt       time.Time
	failing        bool  // the last send failed: logged once, until one succeeds
	refused        int   // the refusal this run warned of last, a status
	lastLogged     Stats // the counters at the last stats line
}

// Start runs the sender until Shutdown.
func Start(cfg Config, log *slog.Logger) *Emitter {
	return start(cfg, log, defaults(), nil)
}

func start(cfg Config, log *slog.Logger, tun tuning, transport http.RoundTripper) *Emitter {
	e := newEmitter(cfg, log, tun, transport)
	go e.run()
	return e
}

func newEmitter(cfg Config, log *slog.Logger, tun tuning, transport http.RoundTripper) *Emitter {
	if log == nil {
		log = slog.Default()
	}
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	prefix, _ := json.Marshal(cfg.Site)
	hard, cancel := context.WithCancel(context.Background())
	return &Emitter{
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
}

// Enqueue hands ev to the sender without blocking: a full queue, a stopped emitter, or an event Trakk would refuse
// (an ip that is no address) drops it and counts the drop. What is queued is a sanitized copy: within Trakk's field
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
			// A full batch goes at once, and what waited out a pause as soon as it is over.
			if e.backoff > 0 {
				e.flush(true)
			} else if e.full() {
				e.flush(false)
			}
		case <-flush.C:
			e.flush(true)
		case <-stats.C:
			e.logStats(false)
		case <-e.stop:
			// What was queued before the stop; an Enqueue racing it counts itself as dropped or lands here.
			e.drain()
			e.finish()
			// Anything that slipped in after the drain: never sent.
			e.dropped.Add(uint64(len(e.ch)))
			e.logStats(true)
			return
		}
		if e.tun.onTurn != nil {
			e.tun.onTurn(e.added)
		}
	}
}

// pausing reports whether a back-off is running.
func (e *Emitter) pausing() bool { return e.tun.now().Before(e.resumeAt) }

// add puts ev into the backlog, the oldest making room for it.
func (e *Emitter) add(ev Event) {
	b, err := json.Marshal(ev)
	if err != nil || e.envelope()+len(b) > e.tun.maxBody { // neither happens within the field limits; counted all the same
		e.dropped.Add(1)
		return
	}
	n := 0
	for size := e.size; n < len(e.backlog) && size+len(b)+1 > e.tun.maxBacklog; n++ {
		size -= len(e.backlog[n].b) + 1
	}
	e.giveUp(n)
	e.backlog = append(e.backlog, item{b: b, expires: e.expires(ev)})
	e.size += len(b) + 1
	e.added++
}

// expires is when ev, just arrived, is given up.
func (e *Emitter) expires(ev Event) time.Time {
	now := e.tun.now()
	t := time.UnixMilli(ev.T).Add(e.tun.maxAge)
	if !now.Before(t) { // a long stream, only now over: Trakk dates it at receipt whatever we do
		return now.Add(e.tun.maxAge)
	}
	if least := now.Add(e.tun.minLife); t.Before(least) {
		return least
	}
	return t
}

// drain takes what is queued right now.
func (e *Emitter) drain() {
	for range len(e.ch) {
		e.add(<-e.ch)
	}
}

// take removes the n oldest events.
func (e *Emitter) take(n int) {
	for i := range n {
		e.size -= len(e.backlog[i].b) + 1
		e.removed++
	}
	clear(e.backlog[:n]) // the array lives on under the rest
	e.backlog = e.backlog[n:]
}

// giveUp removes the n oldest events and counts them.
func (e *Emitter) giveUp(n int) {
	for _, it := range e.backlog[:n] {
		e.countLost(it)
	}
	e.take(n)
}

func (e *Emitter) countLost(it item) {
	if it.tried {
		e.failed.Add(1)
	} else {
		e.dropped.Add(1)
	}
}

// expire gives up the events past their age. They are not in order of age: a long request is old when it ends.
func (e *Emitter) expire() {
	now := e.tun.now()
	e.backlog = slices.DeleteFunc(e.backlog, func(it item) bool {
		if now.Before(it.expires) {
			return false
		}
		e.size -= len(it.b) + 1
		e.removed++
		e.countLost(it)
		return true
	})
}

// envelope is the body's bytes around the events.
func (e *Emitter) envelope() int { return len(e.prefix) + len("]}") }

// full reports whether the backlog holds a whole batch.
func (e *Emitter) full() bool {
	return len(e.backlog) >= e.tun.maxBatch || e.envelope()+e.size > e.tun.maxBody
}

// batch is the next body and the events it holds: the oldest that fit.
func (e *Emitter) batch() ([]byte, []item) {
	body := append(make([]byte, 0, min(e.tun.maxBody, e.envelope()+e.size)), e.prefix...)
	n := 0
	for ; n < len(e.backlog) && n < e.tun.maxBatch; n++ {
		b := e.backlog[n].b
		if n > 0 {
			if len(body)+1+len(b)+len("]}") > e.tun.maxBody {
				break
			}
			body = append(body, ',')
		}
		body = append(body, b...)
	}
	return append(body, "]}"...), e.backlog[:n]
}

// flush sends batch after batch: with all what is there now, and full ones. What arrives meanwhile waits for its own
// turn, or steady traffic would go out an event a POST, without end. Nothing during a pause, and a failure or Shutdown
// (which sends the rest itself) ends it.
func (e *Emitter) flush(all bool) {
	until := e.removed
	if all {
		until = e.added
	}
	for !e.pausing() && !e.stopped.Load() {
		e.expire()
		if len(e.backlog) == 0 || e.removed >= until && !e.full() || !e.send(false) {
			return
		}
		e.drain() // a long backlog must not let the queue run full
	}
}

// finish is shutdown's flush: batch after batch, pause or not, until one fails. The rest is lost.
func (e *Emitter) finish() {
	for e.expire(); len(e.backlog) > 0 && e.send(true); {
	}
	e.giveUp(len(e.backlog))
}

// retryable reports whether a failure says Trakk is away, not that it refuses: no answer (status 0), the contract's
// "send again" (408, 429, 5xx), and what a proxy answers in its place (a 404 while its container is recreated, a
// redirect to a maintenance page; never followed).
func retryable(status int) bool {
	return status < 400 || status == http.StatusNotFound || status == http.StatusRequestTimeout ||
		status == http.StatusTooManyRequests || status >= 500
}

// send posts the next batch. ok reports whether another may go right after it: a success, or a refusal of this batch
// alone (400, 413). final: there is no later one.
func (e *Emitter) send(final bool) (ok bool) {
	if e.tun.onSend != nil {
		defer e.tun.onSend()
	}
	body, events := e.batch()
	n := len(events)
	status, retryAfter, err := e.post(body)
	if err == nil && status >= 200 && status < 300 {
		e.take(n)
		e.backoff, e.resumeAt = 0, time.Time{}
		if e.failing {
			e.failing, e.refused = false, 0
			e.log.Info("analytics feed recovered", "status", status)
		}
		e.sent.Add(uint64(len(events)))
		return true
	}
	if err == nil {
		err = fmt.Errorf("status %d", status)
	}
	switch {
	case status == http.StatusBadRequest || status == http.StatusRequestEntityTooLarge:
		// Trakk answered and refused this batch, not the feed: no pause.
		e.backoff, e.resumeAt = 0, time.Time{}
		e.noteFailure(err, "batch dropped", status, 0)
		e.take(n)
		e.failed.Add(uint64(len(events)))
		return true
	case retryable(status):
		what := "batch held for a retry"
		if final {
			what = "batch dropped"
		}
		e.noteFailure(err, what, 0, e.pause(retryAfter))
		for i := range events {
			events[i].tried = true
		}
	default:
		// The pause is in place before a counter moves: whoever sees the counter sees the pause.
		e.noteFailure(err, "batch dropped", status, e.pause(0))
		e.take(n)
		e.failed.Add(uint64(len(events)))
	}
	return false
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

// noteFailure logs the first failure of a run at warn and the rest at debug: a dead Trakk must not flood the app's
// log. A refusal (its status; 0 for none) warns the first time too: it needs a hand, and Trakk may have been away
// before it.
func (e *Emitter) noteFailure(err error, what string, refusal int, pause time.Duration) {
	lvl := slog.LevelDebug
	if !e.failing || refusal != 0 && refusal != e.refused {
		lvl = slog.LevelWarn
	}
	e.failing = true
	if refusal != 0 {
		e.refused = refusal
	}
	e.log.Log(context.Background(), lvl, "analytics feed send failed, "+what, "err", err, "pause", pause)
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
	// Drain a little so the connection can be reused; Trakk's answers are empty.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
	return resp.StatusCode, parseRetryAfter(resp.Header.Get("Retry-After"), e.tun.now()), nil
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
	msg := "analytics feed"
	if final {
		msg = "analytics feed stopped"
	}
	e.log.Info(msg, "sent", s.Sent, "dropped", s.Dropped, "failed", s.Failed)
}
