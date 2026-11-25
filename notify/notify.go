// Package notify sends outbound notifications through shoutrrr service URLs
// (github.com/nicholas-fedor/shoutrrr), one URL per channel.
package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nicholas-fedor/shoutrrr/pkg/router"
	"github.com/nicholas-fedor/shoutrrr/pkg/types"
)

// SendTimeout is how long the channels of one message may take, together.
// Long enough for a sluggish mail server, short enough that a caller's pass
// stays near its minute.
const SendTimeout = 45 * time.Second

// Severity is how urgent a message is. A service with a priority of its own
// (ntfy, Pushover, Gotify, Opsgenie, PagerDuty, Signalgrid) sends at the
// matching priority, unless its URL sets one; every other service ignores it.
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
// param is not ignored: generic adds it to its JSON body, Discord recolours
// the embed.
var leveled = map[string]bool{
	"ntfy": true, "pushover": true, "gotify": true,
	"opsgenie": true, "pagerduty": true, "signalgrid": true,
}

// Message is one notification. The zero Severity is Normal.
type Message struct {
	Title    string
	Body     string
	Severity Severity
}

// channel is one configured URL and what is safe to say about it.
//
// The URL, not a service built from it once: shoutrrr's Service interface
// does not promise concurrent Sends are safe. v0.8 services (ntfy, gotify,
// pushover, bark, mattermost) wrote the message's params into their own
// config, so one message went out under another's title. The fork copies
// the config per send in every service read at v0.25.1, but a service per
// send has no state to share whatever a later version does.
type channel struct {
	url string
	// label is "channel 2 (smtp)": the position and the scheme, never more.
	label string
}

// Channels sends to every configured channel at once.
//
// Not shoutrrr's router.SendContext: it holds one service per URL across
// sends (see channel), and returns only once every service has, with no
// way to answer at the timeout while a send still winds down.
type Channels struct {
	channels []channel
	// secrets are the credential-bearing parts of every URL, scrubbed from
	// any error before it can reach a log line.
	secrets []string
	timeout time.Duration
	// router builds a service per send; locate serialises it, as nothing in
	// shoutrrr promises Locate is safe for concurrent use.
	router *router.ServiceRouter
	locate sync.Mutex
}

// NewChannels parses the channel URLs. A bad URL is an error at startup, not
// a silence at the first problem.
//
// The error never quotes the URL: it carries credentials (an SMTP password,
// a bot token), and this error is logged. The caller names where the URLs
// came from.
func NewChannels(urls []string) (*Channels, error) {
	// Discarded: services log their deprecation and TLS warnings here, once
	// per service, and a service per send would repeat them on every message.
	r, err := router.NewWithOptions(log.New(io.Discard, "", 0), types.SenderOptions{})
	if err != nil {
		return nil, err
	}
	c := &Channels{timeout: SendTimeout, router: r}
	for i, u := range urls {
		label := fmt.Sprintf("channel %d (%s)", i+1, Scheme(u))
		if _, err := r.Locate(u); err != nil {
			return nil, fmt.Errorf("%s: invalid URL", label)
		}
		c.channels = append(c.channels, channel{url: u, label: label})
		c.secrets = append(c.secrets, secretsOf(u)...)
	}
	// Longest first, so a token containing a shorter secret is scrubbed
	// whole rather than leaving its tail behind.
	sort.Slice(c.secrets, func(i, j int) bool { return len(c.secrets[i]) > len(c.secrets[j]) })
	return c, nil
}

// SetTimeout replaces SendTimeout. Call it before the first send.
func (c *Channels) SetTimeout(d time.Duration) { c.timeout = d }

// Send delivers to every channel at Normal severity. See SendMessage.
func (c *Channels) Send(title, body string) error {
	return c.SendMessage(Message{Title: title, Body: body})
}

// SendMessage delivers to every channel at once. It succeeds when at least
// one channel accepted the message: retrying the whole message because one
// of three channels is down would repeat it on the other two. A failure
// comes back as a SendError naming the channels that failed.
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
		Err:     errors.Join(failed...),
	}
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
	record := func(r result) {
		answered[r.i] = true
		errs[r.i] = r.err
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
		out[i].Channel = ch.label
		switch {
		case !answered[i]:
			out[i].Err = errors.New(stopped)
		case errs[i] == nil:
		case stopped != "" && (errors.Is(errs[i], context.Canceled) || errors.Is(errs[i], context.DeadlineExceeded)):
			// The service saw the same end of sendCtx a moment earlier:
			// one wording, whichever side noticed first.
			out[i].Err = errors.New(stopped)
		default:
			out[i].Err = errors.New(c.scrub(errs[i].Error()))
		}
	}
	return out, finished
}

// sendOne builds the channel's service afresh and sends through it. See
// channel for why it is not built once.
//
// The fork's services take a context and end the send when it does (SMTP
// included: its connection carries the deadline), so a timeout cancels
// rather than abandons; v0.8 took none and a send outlived its timeout.
func (c *Channels) sendOne(ctx context.Context, ch channel, m Message) error {
	c.locate.Lock()
	service, err := c.router.Locate(ch.url)
	c.locate.Unlock()
	if err != nil {
		// Parsed at startup, so this is not a bad URL; and its error is
		// never quoted, for the reason NewChannels gives.
		return errors.New("could not set up the channel")
	}
	// MQTT keeps its broker connection open after a send, for the next one
	// through the same service; there is none.
	if closer, ok := service.(io.Closer); ok {
		defer func() { _ = closer.Close() }()
	}
	// A map per send: generic writes into the params it is handed.
	params := types.Params{types.TitleKey: m.Title}
	if level, ok := levels[m.Severity]; ok && leveled[service.GetID()] {
		params.SetLevel(level)
	}
	if s, ok := service.(types.ContextSender); ok {
		return s.SendContext(ctx, m.Body, &params)
	}
	return service.Send(m.Body, &params)
}

// scrub removes the URLs' credentials from an error text. The fork reduces
// a request URL in its errors to scheme and host, but a server's answer
// quoted back (a webhook echoing its path) is not covered.
func (c *Channels) scrub(s string) string {
	for _, secret := range c.secrets {
		s = strings.ReplaceAll(s, secret, "***")
		// net/http quotes a URL escaped, so scrub that spelling too.
		if esc := url.PathEscape(secret); esc != secret {
			s = strings.ReplaceAll(s, esc, "***")
		}
	}
	return s
}

// secretsOf is every part of a channel URL that may be a credential: the
// user and password, every path segment and every query value. The host is
// left alone: it is not a secret and it is what makes an error readable.
// Short parts (a port, "yes") are left too: scrubbing them would mangle the
// message and they protect nothing.
func secretsOf(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var out []string
	add := func(s string) {
		if len(s) >= 6 {
			out = append(out, s)
		}
	}
	if u.User != nil {
		add(u.User.Username())
		if p, ok := u.User.Password(); ok {
			add(p)
		}
	}
	for _, seg := range strings.Split(u.Path, "/") {
		add(seg)
	}
	for _, vs := range u.Query() {
		for _, v := range vs {
			add(v)
			for _, part := range strings.Split(v, ",") {
				add(part)
			}
		}
	}
	return out
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
