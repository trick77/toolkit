package notify

import (
	"errors"
	"io"
	"log"
	"net/url"
	"sort"
	"strings"

	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/telegram"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/email/smtp"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/gotify"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/ntfy"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/pushover"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/specialized/generic"
	"github.com/nicholas-fedor/shoutrrr/pkg/types"
)

// services are the ones the apps use (owner): each is build weight in every
// app that notifies. Not the fork's router: it imports every service, MQTT
// (paho, gorilla/websocket) and XMPP (mellium) included. Adding one is a
// line here and its package import, plus its entries where they apply:
// hostSecrets, placeholderUsers and settingKeys (secrets.go), leveled and
// insecureKeys (notify.go).
var services = map[string]func() types.Service{
	"generic":  func() types.Service { return &generic.Service{} },
	"gotify":   func() types.Service { return &gotify.Service{} },
	"ntfy":     func() types.Service { return &ntfy.Service{} },
	"pushover": func() types.Service { return &pushover.Service{} },
	"smtp":     func() types.Service { return &smtp.Service{} },
	"telegram": func() types.Service { return &telegram.Service{} },
}

// Schemes are the services a channel URL may name, sorted. A composite
// scheme ("generic+https") names its first part.
func Schemes() []string {
	out := make([]string, 0, len(services))
	for s := range services {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

var (
	errUnsupported = errors.New("unsupported service")
	errInvalid     = errors.New("invalid URL")
)

// discard takes what the services log (deprecation and TLS warnings): a
// library writes no log lines of its own.
var discard = log.New(io.Discard, "", 0)

// locate builds and initialises the service a URL names, as the fork's
// router.Locate does. Its errors never carry the URL's text, nor the
// service's own: a parse error quotes the part it refused.
func locate(raw string) (types.Service, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errInvalid
	}
	// A trailing empty fragment parses as none, so a "#" that belongs to the
	// value would silently vanish.
	if _, frag, ok := strings.Cut(raw, "#"); ok && frag == "" {
		return nil, errInvalid
	}
	scheme, _, custom := strings.Cut(u.Scheme, "+")
	newService, ok := services[strings.ToLower(scheme)]
	if !ok {
		return nil, errUnsupported
	}
	service := newService()
	if custom {
		c, ok := service.(types.CustomURLService)
		if !ok {
			return nil, errInvalid
		}
		if u, err = c.GetServiceURLFromCustom(u); err != nil || u == nil {
			return nil, errInvalid
		}
	}
	if err := service.Initialize(u, discard); err != nil {
		return nil, errInvalid
	}
	return service, nil
}
