package llmwire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Probes for the Responses protocol (wire_api: responses). The typed ones run
// through FromEnv, so they reach whatever an application would: the vendor
// host with LLMWIRE_OPENAI_API_KEY, or a gateway route when
// LLMWIRE_LITELLM_MODELS lists the model. The raw ones post hand-built bodies
// to api.openai.com below plan, to read what plan refuses.

// responsesModels are the profiles the per-model Responses probes run
// against, one subtest each.
var responsesModels = []string{"gpt-6.2-sol"}

func eachResponsesModel(t *testing.T, fn func(t *testing.T, model string)) {
	t.Helper()
	for _, model := range responsesModels {
		t.Run(model, func(t *testing.T) { fn(t, model) })
	}
}

// responsesClient is a FromEnv client for one Responses profile, or a skip.
// A gateway without the catalog alias fakes the stream (responses.go head
// comment): the first byte is the whole answer, so the header bound covers
// the call.
func responsesClient(t *testing.T, model string) *Client {
	t.Helper()
	evalGate(t)
	c, err := FromEnv(model, Config{
		HeaderTimeout: 3 * time.Minute,
		IdleTimeout:   90 * time.Second,
		CallTimeout:   3 * time.Minute,
	})
	if err != nil {
		t.Skipf("live probe: %v", err)
	}
	return c
}

// responsesChat is one metered typed call.
func responsesChat(t *testing.T, c *Client, model string, req ChatRequest) (*ChatResponse, []Warning, error) {
	t.Helper()
	req.Model = model
	theMeter.reserve(t, model)
	resp, warnings, err := c.Chat(context.Background(), req)
	if resp != nil {
		theMeter.record(model, resp.Usage)
	}
	return resp, warnings, err
}

// openaiRaw posts a hand-built body to route on api.openai.com, metered, and
// returns the 200 body or the APIError.
func openaiRaw(t *testing.T, route, model string, b body) (json.RawMessage, *APIError) {
	t.Helper()
	c := openaiEndpoint.client(t)
	b["model"] = model
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	theMeter.reserve(t, model)
	resp, _, err := c.RawPost(context.Background(), route, raw)
	if err != nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("FINDING transport failure: %v", err)
		}
		return nil, apiErr
	}
	var w struct {
		Usage json.RawMessage `json:"usage"`
	}
	_ = json.Unmarshal(resp, &w)
	theMeter.record(model, parseUsage(w.Usage))
	return resp, nil
}

// responsesRaw is openaiRaw on /responses, stateless as the library sends it.
func responsesRaw(t *testing.T, model string, b body) (json.RawMessage, *APIError) {
	t.Helper()
	b["store"] = false
	if _, ok := b["max_output_tokens"]; !ok {
		b["max_output_tokens"] = 256
	}
	return openaiRaw(t, routeResponses, model, b)
}

// rawSummary is the status, the reasoning count and the usage of a raw
// response, for the log.
func rawSummary(raw json.RawMessage) (status string, reasoning int64, usage json.RawMessage) {
	var w wireResponse
	_ = json.Unmarshal(raw, &w)
	u := parseUsage(w.Usage)
	status = w.Status
	if w.IncompleteDetails != nil {
		status += "/" + w.IncompleteDetails.Reason
	}
	return status, Tokens(u.Output.Reasoning), w.Usage
}

// TestProbe_ResponsesEffortLadder: every level on effortLadder plus an unknown
// one, raw, so the endpoint's accepted set is read rather than plan's; then a
// request with no reasoning knob, whose reasoning count says whether the
// model thinks unasked.
func TestProbe_ResponsesEffortLadder(t *testing.T) {
	eachResponsesModel(t, func(t *testing.T, model string) {
		var accepted []string
		for _, level := range append(append([]string(nil), effortLadder...), "bogus") {
			raw, apiErr := responsesRaw(t, model, body{"input": "Reply with the single word: ok",
				"reasoning": map[string]any{"effort": level}})
			if apiErr != nil {
				t.Logf("effort %s: REFUSED status %d code %q param %q message %q", level, apiErr.StatusCode,
					apiErr.Code, apiErr.Param, apiErr.Message)
				continue
			}
			accepted = append(accepted, level)
			status, reasoning, usage := rawSummary(raw)
			t.Logf("effort %s: ACCEPTED status %s reasoning %d usage %s", level, status, reasoning, usage)
		}
		t.Logf("FINDING accepted effort set: %v", accepted)

		raw, apiErr := responsesRaw(t, model, body{"max_output_tokens": 2000, "input": "What is 17 * 23 - 186? " +
			"Answer with the number only."})
		if apiErr != nil {
			t.Fatalf("FINDING no-knob call REFUSED: %v", apiErr)
		}
		status, reasoning, usage := rawSummary(raw)
		var w struct {
			Reasoning json.RawMessage `json:"reasoning"`
		}
		_ = json.Unmarshal(raw, &w)
		t.Logf("FINDING no knob: status %s reasoning tokens %d, echoed reasoning %s, usage %s", status, reasoning, w.Reasoning, usage)
	})
}

// TestProbe_ResponsesOutputCap: max_output_tokens 16 on a prompt that wants
// hundreds. Honoured reads as status incomplete/max_output_tokens with at
// most 16 output tokens; acceptance alone proves nothing (glm accepted and
// ignored the wrong spelling).
func TestProbe_ResponsesOutputCap(t *testing.T) {
	eachResponsesModel(t, func(t *testing.T, model string) {
		raw, apiErr := responsesRaw(t, model, body{"max_output_tokens": 16, "reasoning": map[string]any{"effort": "low"},
			"input": "Write a 300-word story about a lighthouse keeper."})
		if apiErr != nil {
			t.Fatalf("FINDING max_output_tokens 16 REFUSED: %v", apiErr)
		}
		var w wireResponse
		_ = json.Unmarshal(raw, &w)
		status, _, usage := rawSummary(raw)
		out := Tokens(parseUsage(w.Usage).Output.Total)
		t.Logf("FINDING max_output_tokens 16: status %s, output tokens %d, usage %s", status, out, usage)
		if out > 16 {
			t.Errorf("FINDING cap IGNORED: %d output tokens against 16", out)
		}
	})
}

// TestProbe_ResponsesSampling: temperature and top_p, raw. A refusal of a
// non-default value is followed by 1.0, which reads the forced_value shape.
func TestProbe_ResponsesSampling(t *testing.T) {
	eachResponsesModel(t, func(t *testing.T, model string) {
		for _, param := range []string{"temperature", "top_p"} {
			for _, v := range []float64{0.5, 1.0} {
				raw, apiErr := responsesRaw(t, model, body{"input": "Reply with the single word: ok", param: v,
					"reasoning": map[string]any{"effort": "low"}})
				if apiErr != nil {
					t.Logf("FINDING %s %.1f: REFUSED status %d code %q param %q message %q", param, v,
						apiErr.StatusCode, apiErr.Code, apiErr.Param, apiErr.Message)
					continue
				}
				var echo map[string]any
				_ = json.Unmarshal(raw, &echo)
				t.Logf("FINDING %s %.1f: ACCEPTED, echoed temperature %v top_p %v", param, v, echo["temperature"], echo["top_p"])
				break
			}
		}
	})
}

// TestProbe_ResponsesToolLoop is the protocol end to end, per model, through
// FromEnv: a tool round that makes the model think, the round that replays
// its reasoning, and the first round streamed.
func TestProbe_ResponsesToolLoop(t *testing.T) {
	eachResponsesModel(t, func(t *testing.T, model string) {
		responsesToolLoop(t, model, responsesClient(t, model), 2000, digitSumPrompt)
	})
}

// TestProbe_SolResponsesToolLoop is the same loop on gpt-6.1-sol, which is
// reached only through a deployment's gateway route: LLMWIRE_LITELLM_BASE_URL,
// LLMWIRE_LITELLM_API_KEY and LLMWIRE_LITELLM_MODELS listing gpt-6.1-sol.
// It keeps the cantons prompt that ran there by hand on 2026-10-19
// (responses.go head comment), so a failure reads against those facts.
func TestProbe_SolResponsesToolLoop(t *testing.T) {
	const model = "gpt-6.1-sol"
	responsesToolLoop(t, model, responsesClient(t, model), 4000, cantonsPrompt)
}

// The tool-loop prompts: arithmetic, so the model reasons. A trivial prompt
// reported reasoning_tokens 0 on gpt-6.1-sol even at effort high, and
// gpt-6.2-sol answered cantonsPrompt with 0 too (2026-11-20); the digit sum
// makes it work.
const (
	cantonsPrompt = "Think carefully first: take the number of cantons in Switzerland, multiply by the number of " +
		"letters in its capital, subtract 70. If the result is even, the city is Bern, otherwise Basel. Then call " +
		"get_weather for that city. Do not answer in prose."
	digitSumPrompt = "Think carefully first: take the sum of the decimal digits of 2^20, multiply it by the number " +
		"of cantons in Switzerland, subtract 700. If the result is even, the city is Bern, otherwise Basel. Then " +
		"call get_weather for that city. Do not answer in prose."
)

func responsesToolLoop(t *testing.T, model string, c *Client, maxTokens int, prompt string) {
	t.Helper()
	req := ChatRequest{
		Model: model,
		// A system turn first, as noergler's mention loop opens.
		Messages:   []Message{System("You are a terse assistant. Use tools when asked."), User(prompt)},
		Tools:      []Tool{weatherTool},
		ToolChoice: ToolChoice{Mode: ToolChoiceAuto},
		Reasoning:  ReasoningEffort("high"),
		MaxTokens:  ptr(maxTokens),
	}

	r1, _, err := responsesChat(t, c, model, req)
	if err != nil {
		t.Fatalf("FINDING round 1 REJECTED: %v", err)
	}
	t.Logf("round 1: calls %+v, items %d, usage in %d out %d reasoning %d, cost %+v, gateway %s, timing %+v",
		r1.ToolCalls, len(r1.ResponseItems), Tokens(r1.Usage.Input.Total), Tokens(r1.Usage.Output.Total),
		Tokens(r1.Usage.Output.Reasoning), r1.Usage.Cost, r1.Gateway.ModelName, r1.Timing)
	if len(r1.ToolCalls) != 1 || r1.FinishReason != "tool_calls" {
		t.Fatalf("FINDING round 1: no single tool call, finish %q", r1.FinishReason)
	}
	if Tokens(r1.Usage.Output.Reasoning) == 0 || len(r1.ResponseItems) < 2 {
		t.Errorf("FINDING round 1: no reasoning to replay (reasoning_tokens %d, items %d)",
			Tokens(r1.Usage.Output.Reasoning), len(r1.ResponseItems))
	}

	req.Messages = append(req.Messages, r1.Assistant(),
		ToolResult(r1.ToolCalls[0].ID, `{"temp_c":14,"sky":"overcast"}`))
	r2, _, err := responsesChat(t, c, model, req)
	if err != nil {
		t.Fatalf("FINDING round 2 (reasoning replay) REJECTED: %v", err)
	}
	t.Logf("round 2: content %q, finish %q, usage in %d out %d reasoning %d, cost %+v",
		r2.Content, r2.FinishReason, Tokens(r2.Usage.Input.Total), Tokens(r2.Usage.Output.Total),
		Tokens(r2.Usage.Output.Reasoning), r2.Usage.Cost)
	if r2.Content == "" || Tokens(r2.Usage.Input.Total) <= Tokens(r1.Usage.Input.Total) {
		t.Errorf("FINDING round 2: content %q, input tokens %d after %d; the replay did not land",
			r2.Content, Tokens(r2.Usage.Input.Total), Tokens(r1.Usage.Input.Total))
	}
	// Reported behind a gateway, FromTable on the vendor. Exact, not merely
	// priced: a gateway call priced FromTable means the gateway was not
	// recognised and the proxy's figure was skipped.
	p, err := c.registry.Lookup(model)
	if err != nil {
		t.Fatal(err)
	}
	want := FromTable
	if p.Gateway != "" {
		want = Reported
	}
	if r1.Usage.Cost.Provenance != want || r2.Usage.Cost.Provenance != want {
		t.Errorf("FINDING non-streamed calls priced %v / %v, want %v", r1.Usage.Cost.Provenance,
			r2.Usage.Cost.Provenance, want)
	}

	req.Messages = req.Messages[:2]
	theMeter.reserve(t, model)
	s, _, err := c.ChatStream(context.Background(), req)
	if err != nil {
		t.Fatalf("FINDING stream REJECTED: %v", err)
	}
	defer func() { _ = s.Close() }()
	res, err := s.Collect(nil)
	theMeter.record(model, res.Usage)
	if err != nil {
		t.Fatalf("FINDING stream failed: %v", err)
	}
	// FirstData close to Total on a long answer is a gateway faking the
	// stream (catalog alias missing, responses.go head comment); far below it
	// is native. Logged, not asserted: a short tool-call answer is close on a
	// native stream too.
	t.Logf("stream: calls %+v, items %d, first data %s of %s total, events %d, max data gap %s, cost %+v",
		res.ToolCalls, len(res.ResponseItems), res.Timing.FirstData, res.Timing.Total, res.Events,
		res.MaxDataGap, res.Usage.Cost)
	var args map[string]any
	if len(res.ToolCalls) != 1 || json.Unmarshal([]byte(res.ToolCalls[0].Arguments), &args) != nil {
		t.Errorf("FINDING stream: tool call %+v does not carry one JSON argument object", res.ToolCalls)
	}
	if res.Usage.Cost.Provenance != want {
		t.Errorf("FINDING stream priced %v, want %v: behind a gateway, is include_cost_in_streaming_usage still set?",
			res.Usage.Cost.Provenance, want)
	}
}

var timeTool = Tool{Name: "get_time", Description: "Current local time in a city",
	Parameters: map[string]any{"type": "object", "properties": map[string]any{"city": map[string]any{"type": "string"}},
		"required": []any{"city"}}}

// TestProbe_ResponsesToolChoice: each tool_choice value with a prompt that
// would not pick it on its own, and two independent questions for parallel
// calls.
func TestProbe_ResponsesToolChoice(t *testing.T) {
	eachResponsesModel(t, func(t *testing.T, model string) {
		c := responsesClient(t, model)
		for _, tc := range []struct {
			name   string
			prompt string
			tools  []Tool
			choice ToolChoice
		}{
			{"required", "Say hello.", []Tool{weatherTool}, ToolChoice{Mode: ToolChoiceRequired}},
			{"forced get_weather", "Say hello.", []Tool{weatherTool}, ToolChoice{Mode: ToolChoiceFunction, Name: "get_weather"}},
			{"none", "Call get_weather for Bern.", []Tool{weatherTool}, ToolChoice{Mode: ToolChoiceNone}},
			{"parallel", "What is the weather in Bern and the local time in Zurich? Use the tools, both at once.",
				[]Tool{weatherTool, timeTool}, ToolChoice{Mode: ToolChoiceAuto}},
		} {
			resp, _, err := responsesChat(t, c, model, ChatRequest{Messages: []Message{User(tc.prompt)}, Tools: tc.tools,
				ToolChoice: tc.choice, Reasoning: ReasoningEffort("low"), MaxTokens: ptr(1000)})
			if err != nil {
				t.Errorf("FINDING %s REJECTED: %v", tc.name, err)
				continue
			}
			names := make([]string, 0, len(resp.ToolCalls))
			for _, call := range resp.ToolCalls {
				names = append(names, call.Name)
			}
			t.Logf("FINDING %s: calls %v, finish %q, content %q", tc.name, names, resp.FinishReason, Truncate(resp.Content, 120))
		}
	})
}

// TestProbe_ResponsesStructuredOutput: text.format json_schema strict, then
// json_object.
func TestProbe_ResponsesStructuredOutput(t *testing.T) {
	eachResponsesModel(t, func(t *testing.T, model string) {
		c := responsesClient(t, model)
		for _, f := range []ResponseFormat{
			{Kind: FormatJSONSchema, Name: "capital", Strict: true, Schema: map[string]any{
				"type": "object", "additionalProperties": false, "required": []any{"city", "canton"},
				"properties": map[string]any{"city": map[string]any{"type": "string"}, "canton": map[string]any{"type": "string"}}}},
			{Kind: FormatJSONObject},
		} {
			resp, _, err := responsesChat(t, c, model, ChatRequest{
				Messages:       []Message{User("Name the capital of Switzerland and its canton, as JSON with keys city and canton.")},
				ResponseFormat: f, Reasoning: ReasoningEffort("low"), MaxTokens: ptr(1000),
			})
			if err != nil {
				t.Errorf("FINDING %s REJECTED: %v", f.Kind, err)
				continue
			}
			var v map[string]any
			if err := json.Unmarshal([]byte(resp.Content), &v); err != nil {
				t.Errorf("FINDING %s content %q does not parse: %v", f.Kind, resp.Content, err)
				continue
			}
			t.Logf("FINDING %s: ACCEPTED, parsed %s", f.Kind, resp.Content)
		}
	})
}

// TestProbe_ResponsesCacheContainment: two identical prompts past the
// automatic cache minimum, cold thanks to the per-process nonce. Reads where
// cached_tokens sits against input_tokens, and whether a write lane is
// reported at all.
func TestProbe_ResponsesCacheContainment(t *testing.T) {
	eachResponsesModel(t, func(t *testing.T, model string) {
		c := responsesClient(t, model)
		long := fmt.Sprintf("Run %d. ", cacheProbeNonce) +
			strings.Repeat("The quick brown fox jumps over the lazy dog near the riverbank at dawn. ", 400)
		req := ChatRequest{Messages: []Message{System(long), User("Reply with the single word: ok")},
			Reasoning: ReasoningEffort("low"), MaxTokens: ptr(500)}
		var got [2]*ChatResponse
		for i := range got {
			resp, _, err := responsesChat(t, c, model, req)
			if err != nil {
				t.Fatalf("FINDING call %d REJECTED: %v", i+1, err)
			}
			got[i] = resp
			u := resp.Usage
			t.Logf("call %d: raw %s; total %d nocache %d read %d write %d; cost %+v", i+1, u.Raw,
				Tokens(u.Input.Total), Tokens(u.Input.NoCache), Tokens(u.Input.CacheRead), Tokens(u.Input.CacheWrite), u.Cost)
		}
		a, b := got[0].Usage, got[1].Usage
		if Tokens(b.Input.CacheRead) == 0 {
			t.Skipf("INCONCLUSIVE: no cache hit on the second call (raw %s)", b.Raw)
		}
		switch {
		case Tokens(a.Input.Total) == Tokens(b.Input.Total):
			t.Logf("FINDING INSIDE: input_tokens %d on both calls, %d of them cached on the second", Tokens(b.Input.Total),
				Tokens(b.Input.CacheRead))
		default:
			t.Logf("FINDING BESIDE or moved: input_tokens %d then %d with %d cached", Tokens(a.Input.Total),
				Tokens(b.Input.Total), Tokens(b.Input.CacheRead))
		}
		// The write lane on its own, from the cold call: a prompt this long
		// written beside input_tokens leaves the total at a handful of tokens
		// under a write of thousands.
		switch w := Tokens(a.Input.CacheWrite); {
		case a.Input.CacheWrite == nil:
			t.Logf("FINDING WRITE NOT REPORTED: no cache_write_tokens on the cold call")
		case w <= Tokens(a.Input.Total):
			t.Logf("FINDING WRITE INSIDE: cache_write_tokens %d within input_tokens %d", w, Tokens(a.Input.Total))
		default:
			t.Errorf("FINDING WRITE BESIDE: cache_write_tokens %d above input_tokens %d; parseUsage subtracts it",
				w, Tokens(a.Input.Total))
		}
	})
}

// TestProbe_ResponsesChatCompletionsTools: a function tool with a reasoning
// effort on /chat/completions, raw. gpt-6.1-sol behind Azure refused the
// pair there; whether the vendor host does decides only a finding, the
// profile speaks Responses either way.
func TestProbe_ResponsesChatCompletionsTools(t *testing.T) {
	eachResponsesModel(t, func(t *testing.T, model string) {
		raw, apiErr := openaiRaw(t, routeChat, model, body{
			"messages":              []any{map[string]any{"role": "user", "content": "Call get_weather for Bern."}},
			"tools":                 []any{map[string]any{"type": "function", "function": map[string]any{"name": "get_weather", "description": "Current weather for a city", "parameters": weatherTool.Parameters}}},
			"reasoning_effort":      "low",
			"max_completion_tokens": 500,
		})
		if apiErr != nil {
			t.Logf("FINDING chat completions tools+reasoning: REFUSED status %d code %q param %q message %q",
				apiErr.StatusCode, apiErr.Code, apiErr.Param, apiErr.Message)
			return
		}
		t.Logf("FINDING chat completions tools+reasoning: ACCEPTED %s", Truncate(string(raw), 600))
	})
}
