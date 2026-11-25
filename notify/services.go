package notify

import (
	"errors"
	"io"
	"log"
	"net/url"
	"sort"
	"strings"

	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/discord"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/googlechat"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/lark"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/matrix"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/mattermost"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/rocketchat"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/signal"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/slack"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/teams"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/telegram"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/wecom"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/chat/zulip"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/email/smtp"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/incident/opsgenie"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/incident/pagerduty"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/bark"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/gotify"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/homeassistant"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/ifttt"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/join"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/ntfy"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/pushbullet"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/pushover"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/push/signalgrid"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/sms/twilio"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/specialized/generic"
	"github.com/nicholas-fedor/shoutrrr/pkg/services/specialized/notifiarr"
	"github.com/nicholas-fedor/shoutrrr/pkg/types"
)

// services is the fork's router service map without MQTT (paho pulls in
// gorilla/websocket, GO-2026-6278, no tag with the fix) and XMPP (mellium):
// the router imports every service, so every consumer built them. The
// logger pseudo-service writes to a log, not to a person. fork_test.go fails
// when the fork adds a scheme that is neither here nor in excluded.
var services = map[string]func() types.Service{
	"bark":          func() types.Service { return &bark.Service{} },
	"discord":       func() types.Service { return &discord.Service{} },
	"generic":       func() types.Service { return &generic.Service{} },
	"gotify":        func() types.Service { return &gotify.Service{} },
	"googlechat":    func() types.Service { return &googlechat.Service{} },
	"hangouts":      func() types.Service { return &googlechat.Service{} },
	"homeassistant": func() types.Service { return &homeassistant.Service{} },
	"ifttt":         func() types.Service { return &ifttt.Service{} },
	"join":          func() types.Service { return &join.Service{} },
	"lark":          func() types.Service { return &lark.Service{} },
	"matrix":        func() types.Service { return &matrix.Service{} },
	"mattermost":    func() types.Service { return &mattermost.Service{} },
	"notifiarr":     func() types.Service { return &notifiarr.Service{} },
	"ntfy":          func() types.Service { return &ntfy.Service{} },
	"opsgenie":      func() types.Service { return &opsgenie.Service{} },
	"pagerduty":     func() types.Service { return &pagerduty.Service{} },
	"pushbullet":    func() types.Service { return &pushbullet.Service{} },
	"pushover":      func() types.Service { return &pushover.Service{} },
	"rocketchat":    func() types.Service { return &rocketchat.Service{} },
	"signal":        func() types.Service { return &signal.Service{} },
	"signalgrid":    func() types.Service { return &signalgrid.Service{} },
	"slack":         func() types.Service { return &slack.Service{} },
	"smtp":          func() types.Service { return &smtp.Service{} },
	"teams":         func() types.Service { return &teams.Service{} },
	"telegram":      func() types.Service { return &telegram.Service{} },
	"twilio":        func() types.Service { return &twilio.Service{} },
	"wecom":         func() types.Service { return &wecom.Service{} },
	"zulip":         func() types.Service { return &zulip.Service{} },
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
	// value (an unescaped wildcard) would silently vanish.
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
