package stakeout

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Feed takes one event per served request; *Emitter is the real one. Enqueue must not block.
type Feed interface {
	Enqueue(Event)
}

// record carries what the access log's request cannot tell: the route the mux matched (set on the request the mux
// was handed, which may be a copy), what a handler said of the request (the account, the operation, the failure), and
// the body bytes only a writer sees.
type record struct {
	route   string
	account string
	op, err string
	bytes   int64
}

type recordKey struct{}

// Recorder puts the request's record into its context and counts the response body. It goes outside the app's access
// log, so the access log's request carries the record and EventFrom can read it. Mount it only with a feed: without
// one there is nothing to record, and the response writer stays the one net/http handed in.
func Recorder(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &record{}
		next.ServeHTTP(&countingWriter{ResponseWriter: w, rec: rec},
			r.WithContext(context.WithValue(r.Context(), recordKey{}, rec)))
	})
}

// RecordRoute notes the pattern the mux inside matched (r.Pattern, which the mux sets on the request it is handed).
// catchAll names the mux's fallback patterns ("GET /", "/"): a request they answer is no route of the app's, so its
// route stays empty and Stakeout names the path by the site's rules. Without Recorder outside it only passes the
// request on. Panics too: the deferred copy runs before a Recover outside answers.
func RecordRoute(next http.Handler, catchAll ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec, ok := r.Context().Value(recordKey{}).(*record); ok {
			defer func() {
				if !slices.Contains(catchAll, r.Pattern) {
					rec.route = r.Pattern
				}
			}()
		}
		next.ServeHTTP(w, r)
	})
}

// SetAccount names the account the request acted as: an opaque id, never an email or a name. A request without
// Recorder outside ignores it. Call it, like SetOp and SetError, before the handler returns: the access log reads the
// record then.
func SetAccount(ctx context.Context, id string) {
	if rec, ok := ctx.Value(recordKey{}).(*record); ok {
		rec.account = id
	}
}

// SetOp names what the request did inside its route, where one route serves several things (an MCP tool): a name from
// the app's own fixed list, never text a client chose, which Stakeout would list. ASCII letters, digits and _ . / : -
// only (Stakeout stores the rest as _), at most 64 bytes. A request without Recorder outside ignores it.
func SetOp(ctx context.Context, op string) {
	if rec, ok := ctx.Value(recordKey{}).(*record); ok {
		rec.op = op
	}
}

// SetError says the request failed where its status does not (a JSON-RPC error answered 200): the app's own code, from
// a fixed list like SetOp's. The last one set counts; "" takes it back. A request without Recorder outside ignores it.
func SetError(ctx context.Context, code string) {
	if rec, ok := ctx.Value(recordKey{}).(*record); ok {
		rec.err = code
	}
}

// EventFrom maps a finished request to Stakeout's fields, and only those: the query, cookies, credentials and every
// other header stay in the app. ip is the client as the app resolves it (after its trusted proxies), status and dur
// what the access log measured; route, bytes, account, operation and failure come from Recorder's record.
func EventFrom(r *http.Request, ip string, status int, dur time.Duration) Event {
	ev := Event{
		T:        time.Now().Add(-dur).UnixMilli(),
		IP:       ip,
		UA:       r.UserAgent(),
		Method:   r.Method,
		Path:     r.URL.Path,
		Status:   status,
		DurMS:    dur.Milliseconds(),
		Ref:      referrer(r.Referer()),
		Lang:     r.Header.Get("Accept-Language"),
		SFSite:   r.Header.Get("Sec-Fetch-Site"),
		SFMode:   r.Header.Get("Sec-Fetch-Mode"),
		SFDest:   r.Header.Get("Sec-Fetch-Dest"),
		CHUA:     r.Header.Get("Sec-CH-UA"),
		SigAgent: r.Header.Get("Signature-Agent"),
	}
	if rec, ok := r.Context().Value(recordKey{}).(*record); ok {
		ev.Route, ev.Bytes, ev.Account = rec.route, rec.bytes, rec.account
		ev.Op, ev.Err = rec.op, rec.err
	}
	if r.Method == http.MethodHead { // net/http discards a HEAD's body writes: none went out
		ev.Bytes = 0
	}
	return ev
}

// referrer is the Referer without its query and fragment: another site's query can carry a token, and Stakeout needs
// where a visitor came from, not what they carried.
func referrer(ref string) string {
	if i := strings.IndexAny(ref, "?#"); i >= 0 {
		return ref[:i]
	}
	return ref
}

// countingWriter counts the body bytes for the feed. Its ReadFrom forwards to the writer below, so http.ServeFile
// keeps sendfile when the writers above it hand ReadFrom on. Flush, Hijack and deadlines go through Unwrap
// (http.ResponseController).
type countingWriter struct {
	http.ResponseWriter
	rec *record
}

func (w *countingWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.rec.bytes += int64(n)
	return n, err
}

func (w *countingWriter) ReadFrom(src io.Reader) (int64, error) {
	var n int64
	var err error
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(src)
	} else {
		n, err = io.Copy(w.ResponseWriter, src)
	}
	w.rec.bytes += n
	return n, err
}

func (w *countingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
