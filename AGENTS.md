# AGENTS.md

- What lives here: shared libraries that are not base plumbing (integrations with the outside: mcpserver, llmwire,
  webfetch, applemusic, analytics, notify). Base functionality goes to ship's kit; a library for
  one app stays in that app. User: kit "is more about common base functionality"; a repo per library "is totally
  overblown". llmwire and webfetch were own repos (archived after the move); their rules are their dir's AGENTS.md.
- One module, one version line, a package per library. No nested go.mod: every new module costs release wiring.
  A library's dependencies land in every consumer's module graph (go.sum lines, not builds): keep them few, pure Go.
- Consumers are the trick77 apps; a v0.x minor may break them. Breaking change = minor, say so in the release note.
- applemusic: one Client, two policies. loom's tunewire answers a user (Tries 1, RateLimitWait 5 s); reworm's import
  is a batch (Tries 4, no 429 wait: Apple's 429 window lasted ~3.5 h on 2026-11-04, retrying only prolongs it).
  Keep both callers' behavior when changing get.
- mcpserver: protocol only. App concepts stay in the app (loom's X-Loom-User is loom's `internal/loomuser`, named via
  `Server.UserHeader`; peeq's channel hint rides `InstructionsFunc`/`DescriptionFunc`).
- analytics: named after the `ANALYTICS_*` settings it reads, never after the product (user: no import may change with
  a product's name). The contract is trick77/trakk's INTEGRATION.md; `Event` carries exactly its fields, never more (raw
  headers carry cookies and credentials). Consumers: ipverse lens, lens-console, lens-gateway, ismimodown.
  A 404 is retried: Traefik answers it while the collector's container is recreated, and each deploy of it lost every
  app's batches. Another 4xx drops the batch: kept, one a firewall refuses for its probe paths blocks the feed. `maxAge` < 1 h: Trakk files an event over an hour old at
  the receive time.
- notify: shoutrrr is the nicholas-fedor fork, not containrrr (owner's call, an exception to the 1k-star rule).
  Consumers: netra, trakk. containrrr v0.8, measured in netra: services wrote a send's params into their own
  config (one message went out under another's title), took no context (a timed-out send ran on; router.Send leaked
  a goroutine per timeout), transport errors quoted the URL with its token. The fork fixed all three (fork_test.go pins
  it); a service per send and the scrub stay, as no interface promises it. Matrix keeps one service per channel,
  sends serialised: per send it logged in with the password for every message.
- notify: no shoutrrr `router`, our own service map (owner): the router imports every service, so every consumer
  built MQTT (paho, gorilla/websocket with GO-2026-6278, no tag with the fix) and XMPP (mellium). Both stay out,
  and the `logger` pseudo-service; a fork scheme in neither list fails TestForkServiceList. Never import the router,
  not even from a test: it puts them back in go.mod. go.sum keeps their lines: the fork's pushbullet test imports the router.

## Git & CI

- Gate: `ship check` (`ship` is the `ship()` from ship's README).
- Fresh clone: `ship hooks` before the first push (check, conform and init install it too); without the pre-push hook a push skips the gate.
- Branch + PR, never push to `master`.
- Release by hand (`gh workflow run Release -f bump=auto`), except a merged Dependabot go.mod/go.sum bump: that one
  releases itself (release.yaml, a ship.yaml `scaffold` allow). User: dependabot "auto-releases", the rest stays manual.
  A Dependabot release also ships whatever was merged since the last tag, at the bump its `Release:` lines ask for.
- Commit subjects + PR titles: Go style `area: what` (`mcpserver: …`, `llmwire: …`, `webfetch: …`), gated by ship; release notes list them by area.
- `.yaml`, never `.yml`.
