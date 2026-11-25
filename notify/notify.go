// Package notify sends outbound notifications through shoutrrr service URLs
// (github.com/nicholas-fedor/shoutrrr), one URL per channel.
package notify

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/nicholas-fedor/shoutrrr/pkg/format"
	"github.com/nicholas-fedor/shoutrrr/pkg/types"
)

// SendTimeout is how long the channels of one message may take, together.
// Long enough for a sluggish mail server, short enough that a caller's pass
// stays near its minute.
const SendTimeout = 45 * time.Second

// Severity is how urgent a message is. ntfy, Pushover and Gotify send at the
// matching priority, unless the URL sets one; the other services ignore it.
type Severity string

// The severities. Any other value, the empty one included, is Normal.
const (
	Low    Severity = "low"
	Normal Severity = "normal"
	High   Severity = "high"
)

// levels maps a Severity onto shoutrrr's level param, which those services
// turn into their own priority. Normal sets none, so a message without a
// severity is sent exactly as before: ntfy default, Pushover 0, Gotify the
// application's default. High is Error: ntfy max, Pushover 1, Gotify 8.
var levels = map[Severity]types.MessageLevel{
	Low:  types.Debug,
	High: types.Error,
}

// leveled are the services whose level param sets a priority. Elsewhere the
// param is not ignored: generic adds it to its JSON body.
var leveled = map[string]bool{"ntfy": true, "pushover": true, "gotify": true}

// Message is one notification. The zero Severity is Normal.
type Message struct {
	Title    string
	Body     string
	Severity Severity
}

// channel is one configured URL and what is safe to say about it.
//
// The URL, not a service built from it once, except where the URL skips TLS
// verification (see shared): shoutrrr's Service interface does not promise
// concurrent Sends are safe. v0.8 services (ntfy, gotify, pushover, bark,
// mattermost) wrote the message's params into their own config, so one
// message went out under another's title. The fork copies the config per
// send in every service read at v0.25.1, but a service per send has no state
// to share whatever a later version does.
type channel struct {
	url string
	// label is "channel 2 (smtp)": the position and the scheme, never more.
	label string
	// service is the shoutrrr service ID.
	service string
	// shared is the channel's one service when its URL skips TLS
	// verification. Sent through concurrently: the fork copies the config per
	// send and guards its HTTP client holder with a mutex; its tests run
	// concurrent sends on one service.
	shared types.Service
}

// insecureKeys skip TLS verification. The fork builds the insecure HTTP
// client once per service: a service per send left a transport, its idle
// connections and their goroutines behind for every message. smtp's OAuth2
// token cache is per service too, so a channel without a shared service
// makes one token request per message; left so.
var insecureKeys = []string{"skiptlsverify", "insecureskipverify", "disabletlsverification"}

// skipsVerify says whether the URL turns TLS verification off, read as the
// fork reads it: the first value of a repeated key, as a bool.
func skipsVerify(q url.Values) bool {
	for k, vs := range q {
		if slices.Contains(insecureKeys, strings.ToLower(k)) && len(vs) > 0 {
			if on, ok := format.ParseBool(vs[0], false); ok && on {
				return true
			}
		}
	}
	return false
}

// Channels sends to every configured channel at once.
//
// Not shoutrrr's router: it imports every service (see services), holds one
// service per URL across sends (see channel for when notify does), and
// returns only once every
// service has, with no way to answer at the timeout while a send still winds
// down.
type Channels struct {
	channels []*channel
	// secrets are the credential-bearing parts of every URL, scrubbed from
	// any error before it can reach a log line.
	secrets []string
	timeout time.Duration
}

// NewChannels parses the channel URLs. A bad URL is an error at startup, not
// a silence at the first problem.
//
// The error never quotes the URL: it carries credentials (an SMTP password,
// a bot token), and this error is logged. The caller names where the URLs
// came from. A service outside Schemes is "unsupported service".
func NewChannels(urls []string) (*Channels, error) {
	c := &Channels{timeout: SendTimeout}
	for i, u := range urls {
		label := fmt.Sprintf("channel %d (%s)", i+1, Scheme(u))
		service, err := locate(u)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		ch := &channel{url: u, label: label, service: service.GetID()}
		var query url.Values
		if parsed, err := url.Parse(u); err == nil {
			query = parsed.Query()
		}
		if skipsVerify(query) {
			ch.shared = service
		}
		c.channels = append(c.channels, ch)
		c.secrets = append(c.secrets, secretsOf(u, ch.service)...)
	}
	c.secrets = spellings(c.secrets)
	return c, nil
}

// SetTimeout replaces SendTimeout. Call it before the first send. A
// non-positive d is ignored: every send would fail at once.
func (c *Channels) SetTimeout(d time.Duration) {
	if c != nil && d > 0 {
		c.timeout = d
	}
}

// Send delivers to every channel at Normal severity. See SendMessage.
func (c *Channels) Send(title, body string) error {
	return c.SendMessage(Message{Title: title, Body: body})
}

// SendMessage delivers to every channel at once. Any failure comes back as a
// *SendError naming the channels that failed. With Partial set another
// channel took the message: count it as sent, as retrying the whole message
// because one of three channels is down would repeat it on the other two.
//
// Every error names its channel and is scrubbed of the URLs' credentials.
func (c *Channels) SendMessage(m Message) error {
	var (
		failed []error
		labels []string
	)
	deliveries, _ := c.DeliverMessage(context.Background(), m)
	for _, d := range deliveries {
		if d.Err != nil {
			// %v, not %w: what reaches a log is the scrubbed text, never an
			// error a caller could unwrap back to shoutrrr's own.
			failed = append(failed, fmt.Errorf("%s: %s", d.Channel, d.Err.Error()))
			labels = append(labels, d.Channel)
		}
	}
	if len(failed) == 0 {
		return nil
	}
	return &SendError{
		Failed:  labels,
		Partial: len(failed) < len(c.channels),
		Err:     &joined{errs: failed},
	}
}

// joined is errors.Join on one line: the text reaches a log line, and a
// newline in it starts a forged one. A pointer, so the error compares.
type joined struct{ errs []error }

func (j *joined) Error() string {
	parts := make([]string, len(j.errs))
	for i, err := range j.errs {
		parts[i] = err.Error()
	}
	return strings.Join(parts, "; ")
}

func (j *joined) Unwrap() []error { return j.errs }

// oneLine turns the control characters of a server's text (a CR/LF, a
// right-to-left override) into spaces: it goes into a log line.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return ' '
		}
		return r
	}, s)
}

// Delivery is what became of a message on one channel.
type Delivery struct {
	// Channel is the label, "channel 2 (smtp)".
	Channel string
	// Err is nil when the channel accepted the message. Scrubbed.
	Err error
}

// Labels names the channels, in configuration order. Nil-safe: a nil
// *Channels has none.
func (c *Channels) Labels() []string {
	if c == nil {
		return []string{}
	}
	out := make([]string, len(c.channels))
	for i, ch := range c.channels {
		out[i] = ch.label
	}
	return out
}

// Timeout is how long Deliver waits for the channels, together.
func (c *Channels) Timeout() time.Duration {
	if c == nil {
		return SendTimeout
	}
	return c.timeout
}

// Deliver sends to every channel at Normal severity. See DeliverMessage.
func (c *Channels) Deliver(ctx context.Context, title, body string) ([]Delivery, <-chan struct{}) {
	return c.DeliverMessage(ctx, Message{Title: title, Body: body})
}

// DeliverMessage sends to every channel at once and reports each, in
// configuration order.
//
// It returns after Timeout or when ctx ends, whichever is first, and cancels
// the sends still out, which report it as their error. done closes once
// every send has really returned: a cancelled send may already have handed
// the server its message.
func (c *Channels) DeliverMessage(ctx context.Context, m Message) (out []Delivery, done <-chan struct{}) {
	finished := make(chan struct{})
	if c == nil || len(c.channels) == 0 {
		close(finished)
		return []Delivery{}, finished
	}

	sendCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	deadline, _ := sendCtx.Deadline()

	type result struct {
		i   int
		err error
	}
	// Buffered for every channel, so a send that returns after the wait has
	// ended can still hand over its result and end rather than block forever.
	results := make(chan result, len(c.channels))
	var wg sync.WaitGroup
	for i, ch := range c.channels {
		wg.Go(func() { results <- result{i, c.sendOne(sendCtx, ch, m)} })
	}
	go func() {
		wg.Wait()
		close(finished)
	}()

	errs := make([]error, len(c.channels))
	answered := make([]bool, len(c.channels))
	// early: the send ended before sendCtx did, so a deadline in its error
	// was its own (a client timeout), not the wait's.
	early := make([]bool, len(c.channels))
	record := func(r result) {
		answered[r.i] = true
		errs[r.i] = r.err
		// A connection deadline (SMTP's) can fire a moment before the
		// context's own timer.
		early[r.i] = sendCtx.Err() == nil && time.Now().Before(deadline)
	}
wait:
	for left := len(c.channels); left > 0; left-- {
		select {
		case r := <-results:
			record(r)
		case <-sendCtx.Done():
			break wait
		}
	}
	// Results that came in with the deadline: those sends finished.
	for drained := false; !drained; {
		select {
		case r := <-results:
			record(r)
		default:
			drained = true
		}
	}

	stopped := ""
	switch {
	case ctx.Err() != nil:
		stopped = "cancelled: " + ctx.Err().Error()
	case sendCtx.Err() != nil:
		stopped = fmt.Sprintf("timed out after %s", c.timeout)
	}
	out = make([]Delivery, len(c.channels))
	for i, ch := range c.channels {
		out[i] = Delivery{Channel: ch.label, Err: c.report(errs[i], answered[i], early[i], stopped)}
	}
	return out, finished
}

// report words one channel's outcome: stopped (why the wait ended, "" if it
// did not) for a send still out or one that ended with the wait, its own
// scrubbed error otherwise.
func (c *Channels) report(err error, answered, early bool, stopped string) error {
	switch {
	case !answered:
		return errors.New(stopped)
	case err == nil:
		return nil
	case !early && stopped != "" && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)):
		// The service saw the same end of sendCtx a moment earlier: one
		// wording, whichever side noticed first.
		return errors.New(stopped)
	}
	return errors.New(oneLine(c.scrub(err.Error())))
}

// sendOne sends through the channel's shared service where it has one (a
// URL that skips TLS verification), else through one built afresh. See
// channel for why it is not built once otherwise.
//
// The fork's services take a context and end the send when it does (SMTP
// included: its connection carries the deadline), so a timeout cancels
// rather than abandons; v0.8 took none and a send outlived its timeout.
func (c *Channels) sendOne(ctx context.Context, ch *channel, m Message) error {
	service := ch.shared
	if service == nil {
		var err error
		if service, err = locate(ch.url); err != nil {
			// Parsed at startup, so this is not a bad URL.
			return errors.New("could not set up the channel")
		}
	}
	params := ch.params(m)
	if s, ok := service.(types.ContextSender); ok {
		return s.SendContext(ctx, m.Body, &params)
	}
	return service.Send(m.Body, &params)
}

// params are one send's, a map per send: generic writes into the params it
// is handed.
func (ch *channel) params(m Message) types.Params {
	p := types.Params{}
	// An empty title would replace the URL's own title=.
	if m.Title != "" {
		p[types.TitleKey] = m.Title
	}
	if level, ok := levels[m.Severity]; ok && leveled[ch.service] {
		p.SetLevel(level)
	}
	return p
}

// SendError reports the channels a message failed on. Partial says another
// channel delivered it, and the message then counts as sent.
type SendError struct {
	// Failed are the failing channels' labels, safe to store.
	Failed  []string
	Partial bool
	Err     error
}

func (e *SendError) Error() string {
	if e.Partial {
		return "some channels failed: " + e.Err.Error()
	}
	return e.Err.Error()
}

func (e *SendError) Unwrap() error { return e.Err }

var schemeRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*$`)

// Scheme is the service a channel URL names ("smtp", "generic+https"), safe
// to show and log: "no scheme" or "invalid scheme" when the text before
// "://" is not one, as it may then be a pasted credential.
func Scheme(u string) string {
	s, _, ok := strings.Cut(u, "://")
	switch {
	case !ok:
		return "no scheme"
	case !schemeRE.MatchString(s):
		return "invalid scheme"
	}
	return strings.ToLower(s)
}
