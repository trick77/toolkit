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
| [`applemusic`](applemusic) | Apple Music API the way the music.apple.com web player reads it: the player's developer token (scraped from its bundle), the user's media-user-token for library calls. Catalog (songs by ISRC, search, album tracks) and the user's library, history and recommendations. Read-only, unofficial. |
| [`llmwire`](llmwire) | OpenAI-compatible inference (and Claude over Anthropic's protocol): chat, tools, vision, embeddings, each model's quirks kept as data in `profiles.yaml`. See [its README](llmwire/README.md). Was `github.com/trick77/llmwire`. |
| [`mcpserver`](mcpserver) | Stateless [MCP](https://modelcontextprotocol.io) server over streamable HTTP, JSON responses only. Answers the 2026-07-28 revision and the initialize-era ones (2025-11-25, 2025-06-18, 2025-03-26). |
| [`stakeout`](stakeout) | An app's side of [Stakeout](https://github.com/trick77/stakeout)'s integration: the tracker's origin for the script tag and the CSP, and the server feed (middleware that records each request, a non-blocking emitter that batches them to `/api/feed`). |
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

## stakeout

`ANALYTICS_URL` alone loads the tracker, `ANALYTICS_FEED_KEY` adds the feed, `ANALYTICS_SITE` names the site the key
belongs to. All empty: the app runs as without Stakeout. A value that does not work turns its part off with a
warning, never the app.

```go
import "github.com/trick77/toolkit/stakeout"

set, warns := stakeout.Resolve(os.Getenv("ANALYTICS_URL"), os.Getenv("ANALYTICS_FEED_KEY"),
	os.Getenv("ANALYTICS_SITE"), "")
// set.Origin: add it to script-src and connect-src, load set.Origin + stakeout.ScriptPath on every page.
var feed *stakeout.Emitter
if set.Feed != nil {
	feed = stakeout.Start(*set.Feed, nil)
	defer feed.Shutdown(ctx) // after the server drained: sends what is queued
}
// With a feed: stakeout.Recorder outside the access log, stakeout.RecordRoute(mux, "GET /") around the mux,
// and in the access log's per-request hook feed.Enqueue(stakeout.EventFrom(r, clientIP, status, dur)).
// A handler that knows the account: stakeout.SetAccount(r.Context(), opaqueID).
// One route serving several things (an MCP tool), a failure answered 200: stakeout.SetOp and stakeout.SetError, names
// from fixed lists of the app. What mcpserver refuses itself (an unknown tool) reaches neither.
```

The emitter never blocks a request: a full queue drops. A batch that failed on the way (network, 408, 429, 5xx) is
sent again after `Retry-After` or a doubling back-off, for up to 45 minutes (Stakeout dates older events at receipt);
one Stakeout refused (400, 401, 413, …) is dropped and logged.

## Development

The gate is [ship](https://github.com/trick77/ship): `ship check` locally, and the pre-push hook runs it on every
push. MIT licensed.
