# toolkit

Shared Go libraries for the trick77 apps that are not base plumbing: the pieces through which an app talks to
the outside world, one package each. Base functionality (HTTP server, auth, SQLite, logging, SSE) lives in
[ship's kit](https://github.com/trick77/ship/tree/master/kit); a library only one app needs stays in that app.

```sh
go get github.com/trick77/toolkit@latest
```

One module, one version line. v0.x: a minor release may break callers, its release note says how.

## Packages

| Package | What |
|---|---|
| [`analytics`](analytics) | An app's side of [Trakk](https://github.com/trick77/trakk)'s integration: the tracker's origin for the script tag and the CSP, and the server feed (middleware that records each request, a non-blocking emitter that batches them to `/api/feed`). |
| [`applemusic`](applemusic) | Apple Music API the way the music.apple.com web player reads it: the player's developer token (scraped from its bundle), the user's media-user-token for library calls. Catalog (songs by ISRC, search, album tracks) and the user's library, history and recommendations. Read-only, unofficial. |
| [`llmwire`](llmwire) | OpenAI-compatible inference (and Claude over Anthropic's protocol): chat, tools, vision, embeddings, each model's quirks kept as data in `profiles.yaml`. See [its README](llmwire/README.md). Was `github.com/trick77/llmwire`. |
| [`mcpserver`](mcpserver) | Stateless [MCP](https://modelcontextprotocol.io) server over streamable HTTP, JSON responses only. Answers the 2026-07-28 revision and the initialize-era ones (2025-11-25, 2025-06-18, 2025-03-26). |
| [`notify`](notify) | Notifications through [shoutrrr](https://github.com/nicholas-fedor/shoutrrr) service URLs (mail, ntfy, Pushover, Gotify, Telegram, webhooks): every channel at once, each one's result, credentials scrubbed from errors, a severity for the services with a priority. `Plain` makes request text safe to put in a message. |
| [`webfetch`](webfetch) | In-process Go port of the reference `mcp-server-fetch`: fetch a URL, extract the main content as Markdown, honour robots.txt, SSRF-guarded. See [its README](webfetch/README.md). Was `github.com/trick77/webfetch`. |

## mcpserver

Describe the endpoint and its tools in a `Server`, mount the handler. The protocol, the caps and the result shape
are the package's; the tools are yours.

```go
import "github.com/trick77/toolkit/mcpserver"

h := mcpserver.New(mcpserver.Server{
	Name:    "example",
	Version: version,
	Instructions: "Echoes text back.",
	Tools: []mcpserver.Tool{{
		Name: "echo", Title: "Echo", Description: "Returns the text it was given.", ReadOnly: true,
		Schema: mcpserver.ObjectSchema(map[string]any{"text": map[string]any{"type": "string"}}, "text"),
		Run: func(ctx context.Context, args json.RawMessage) mcpserver.Result {
			var a struct {
				Text string `json:"text"`
			}
			if err := mcpserver.DecodeArgs(args, &a); err != nil {
				return mcpserver.ErrorResult(err.Error()) // the model reads it and explains
			}
			return mcpserver.Result{Text: a.Text}
		},
	}},
})
mux.Handle("/mcp", h)
```

What `Server` covers beyond the tools:

- **Per-request text**: `InstructionsFunc` and a tool's `DescriptionFunc` are built per request, e.g. a hint naming
  the user's own data; `ToolsTTL` tells clients how long to cache the list (default 1 h).
- **Origin and auth**: a request with an `Origin` header is refused unless it matches `AllowedOrigin`; `Auth` wraps
  the handler after that check, so a foreign page learns nothing about the token.
- **Caller identity**: `UserHeader` names a trusted header whose value tools read with `mcpserver.User(ctx)`.
- **Result shape**: text capped at a line (`MaxTextBytes`, default 24 KiB), citable `Sources` in
  `structuredContent`, `Files` as embedded resources within a 3 MiB budget.
- **Retired names**: `Aliases` keep old tool names answering without listing them.

Not covered: sessions, the GET stream, server-initiated requests, resources and prompts. Tools only, stateless.

## analytics

`ANALYTICS_URL` alone loads the tracker, `ANALYTICS_FEED_KEY` adds the feed, `ANALYTICS_SITE` names the site the key
belongs to. All empty: the app runs as without Trakk. A value that does not work turns its part off with a
warning, never the app.

```go
import "github.com/trick77/toolkit/analytics"

set, warns := analytics.Resolve(os.Getenv("ANALYTICS_URL"), os.Getenv("ANALYTICS_FEED_KEY"),
	os.Getenv("ANALYTICS_SITE"), "")
// set.Origin: add it to script-src and connect-src, load set.Origin + analytics.ScriptPath on every page.
var feed *analytics.Emitter
if set.Feed != nil {
	feed = analytics.Start(*set.Feed, nil)
	defer feed.Shutdown(ctx) // after the server drained: sends what is queued
}
// With a feed: analytics.Recorder outside the access log, analytics.RecordRoute(mux, "GET /") around the mux,
// and in the access log's per-request hook feed.Enqueue(analytics.EventFrom(r, clientIP, status, dur)).
// A handler that knows the account: analytics.SetAccount(r.Context(), opaqueID).
// One route serving several things (an MCP tool), a failure answered 200: analytics.SetOp and analytics.SetError, names
// from fixed lists of the app. What mcpserver refuses itself (an unknown tool) reaches neither.
```

The emitter never blocks a request: a full queue drops. A batch that failed because Trakk is away (network, 408, 429, 5xx,
a proxy's 404 while its container is recreated) goes again after `Retry-After` or a doubling back-off; a refused one
(400, 401, 413, any other 4xx) is dropped and logged. Meanwhile up to 4 MiB of events wait, each until it is 55 minutes
old (Trakk dates older ones at receipt).

## notify

```go
import "github.com/trick77/toolkit/notify"

ch, err := notify.NewChannels(urls) // an error names the entry, never quotes the URL
err = ch.SendMessage(notify.Message{
	Title:    "disk nearly full",
	Body:     "path " + notify.Plain(r.URL.Path, 200), // untrusted text: no mention, link or markup
	Severity: notify.High,
})
var sendErr *notify.SendError
if errors.As(err, &sendErr) && sendErr.Partial {
	// Another channel took it: sent. Log sendErr.Failed, do not retry the whole message.
} else if err != nil {
	// No channel took it.
}
// Deliver/DeliverMessage answer per channel (a settings page's test button).
```

A message takes at most `SendTimeout` (45 s) over all channels; what is still out then is cancelled. A severity
sets the priority on ntfy, Pushover and Gotify unless the URL sets one, and changes nothing elsewhere.

Six services: `smtp`, `ntfy`, `pushover`, `gotify`, `telegram` and `generic` (webhooks, `generic+https://…`);
`notify.Schemes()` lists them for a config error to show. Another of shoutrrr's is a line in the `services` map of
`notify/services.go` plus its package import.

## Development

The gate is [ship](https://github.com/trick77/ship): `ship check` locally, and the pre-push hook runs it on every
push. MIT licensed.
