package llmwire

import (
	"encoding/json"
	"testing"
)

// "Not reported" and "reported as zero" are different facts. Collapsing them
// makes a missing field indistinguishable from a genuinely free call, which is
// how a cost column fills with zeros nobody can explain later.
func TestParseUsage_AbsentIsNotZero(t *testing.T) {
	u := parseUsage(nil)
	if u.Input.Total != nil {
		t.Errorf("input total = %v, want nil for an absent usage object", *u.Input.Total)
	}
	if u.Output.Total != nil {
		t.Errorf("output total = %v, want nil", *u.Output.Total)
	}
	if u.Raw != nil {
		t.Errorf("raw = %s, want nil", u.Raw)
	}
}

func TestParseUsage_ReportedZeroIsDistinctFromAbsent(t *testing.T) {
	u := parseUsage(json.RawMessage(`{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}`))
	if u.Input.Total == nil {
		t.Fatal("input total is nil, want a reported 0")
	}
	if *u.Input.Total != 0 {
		t.Errorf("input total = %d, want 0", *u.Input.Total)
	}
}

// prompt_tokens INCLUDES cached_tokens, so the full-rate lane is the difference.
// Adding instead of subtracting overcharges every cached call.
func TestParseUsage_CacheLaneIsSubtractedNotAdded(t *testing.T) {
	u := parseUsage(json.RawMessage(`{"prompt_tokens":100,"prompt_tokens_details":{"cached_tokens":30}}`))
	if got := *u.Input.CacheRead; got != 30 {
		t.Errorf("cache read = %d, want 30", got)
	}
	if got := *u.Input.NoCache; got != 70 {
		t.Errorf("no-cache lane = %d, want 70 (100 total includes the 30 cached)", got)
	}
}

// The measured gpt-6.2-sol pair (usage.go head comment): input_tokens holds
// the write as it holds the read, so both come out of the full-rate lane, and
// the pair prices on the 30-minute write rate, then the read rate.
func TestParseUsage_CacheWriteIsInsideThePrompt(t *testing.T) {
	write := parseUsage(json.RawMessage(`{"input_tokens":6428,"input_tokens_details":{"cache_write_tokens":6425,` +
		`"cache_write_tokens_details":{"ttl_12h_tokens":0,"ttl_30m_tokens":6425},"cached_tokens":0},"output_tokens":5}`))
	if Tokens(write.Input.Total) != 6428 || Tokens(write.Input.NoCache) != 3 || Tokens(write.Input.CacheWrite) != 6425 {
		t.Errorf("write = %+v", write.Input)
	}
	read := parseUsage(json.RawMessage(`{"input_tokens":6428,"input_tokens_details":{"cache_write_tokens":0,` +
		`"cached_tokens":6425},"output_tokens":5}`))
	if Tokens(read.Input.NoCache) != 3 || Tokens(read.Input.CacheRead) != 6425 {
		t.Errorf("read = %+v", read.Input)
	}

	p := mustLookup(t, Default(), "gpt-6.2-sol")
	// 3 x 2.00 + 6425 x 2.50 + 5 x 10.00 per million.
	if cost, w := priceCall(p, write, nil, 200, testStart); cost.Provenance != FromTable || cost.NanoUSD != 16_118_500 {
		t.Errorf("write cost = %+v %v", cost, w)
	}
	// 3 x 2.00 + 6425 x 0.10 + 5 x 10.00 per million.
	if cost, w := priceCall(p, read, nil, 200, testStart); cost.Provenance != FromTable || cost.NanoUSD != 698_500 {
		t.Errorf("read cost = %+v %v", cost, w)
	}

	// A 12-hour write bills at 5.00, above the lane: unpriced, not under-priced.
	long := parseUsage(json.RawMessage(`{"input_tokens":200,"input_tokens_details":{"cache_write_tokens":100,` +
		`"cache_write_tokens_details":{"ttl_12h_tokens":100}},"output_tokens":5}`))
	if cost, w := priceCall(p, long, nil, 200, testStart); cost.Provenance != Unpriced || len(w) != 1 {
		t.Errorf("12h write = %+v %v", cost, w)
	}
}

// completion_tokens INCLUDES reasoning_tokens. Pricing reasoning separately
// double-counts every call these models make.
func TestParseUsage_ReasoningIsInsideCompletion(t *testing.T) {
	u := parseUsage(json.RawMessage(`{"completion_tokens":200,"completion_tokens_details":{"reasoning_tokens":150}}`))
	if got := *u.Output.Reasoning; got != 150 {
		t.Errorf("reasoning = %d, want 150", got)
	}
	if got := *u.Output.Text; got != 50 {
		t.Errorf("text lane = %d, want 50 (200 total includes the 150 reasoning)", got)
	}
}

// An endpoint that reports text_tokens itself must win over the derived value.
func TestParseUsage_ReportedTextLaneWinsOverDerived(t *testing.T) {
	u := parseUsage(json.RawMessage(`{"completion_tokens":200,"completion_tokens_details":{"reasoning_tokens":150,"text_tokens":45}}`))
	if got := *u.Output.Text; got != 45 {
		t.Errorf("text lane = %d, want the reported 45, not the derived 50", got)
	}
}

// Both operands arrive from the wire. A cached count exceeding the prompt count
// would produce a negative input lane, which at pricing time CREDITS the caller
// for tokens actually spent.
func TestParseUsage_NegativeLaneIsClampedToZero(t *testing.T) {
	u := parseUsage(json.RawMessage(`{"prompt_tokens":10,"prompt_tokens_details":{"cached_tokens":9999}}`))
	if got := *u.Input.NoCache; got != 0 {
		t.Errorf("no-cache lane = %d, want 0 — a negative lane would credit the caller", got)
	}
}

// Containment is measured on one model. A vendor reporting writes BESIDE
// prompt_tokens trips the clamp, and its full-rate tokens must not vanish
// without a word: still priced, with a warning. The measured inside shape and
// the Messages lanes (beside by design, Total added) stay quiet.
func TestPrice_CacheOverflowWarns(t *testing.T) {
	p := mustLookup(t, Default(), "gpt-6.2-sol")
	beside := parseUsage(json.RawMessage(`{"input_tokens":100,"input_tokens_details":{"cache_write_tokens":6000,` +
		`"cached_tokens":50},"output_tokens":5}`))
	if Tokens(beside.Input.NoCache) != 0 {
		t.Errorf("no-cache lane = %d, want the clamp's 0", Tokens(beside.Input.NoCache))
	}
	cost, w := priceCall(p, beside, nil, 200, testStart)
	if cost.Provenance != FromTable || cost.NanoUSD == 0 || len(w) != 1 || w[0].Feature != "cost" {
		t.Errorf("beside = %+v %v, want a table price and one cost warning", cost, w)
	}

	inside := parseUsage(json.RawMessage(`{"input_tokens":6428,"input_tokens_details":{"cache_write_tokens":6425,` +
		`"cached_tokens":0},"output_tokens":5}`))
	if _, w := priceCall(p, inside, nil, 200, testStart); len(w) != 0 {
		t.Errorf("measured inside shape warned: %v", w)
	}

	opus := mustLookup(t, Default(), "claude-opus-5-5")
	msgs := parseMessagesUsage(json.RawMessage(`{"input_tokens":4,"cache_creation_input_tokens":11215,` +
		`"cache_read_input_tokens":300,"output_tokens":5}`))
	if _, w := priceCall(opus, msgs, nil, 200, testStart); len(w) != 0 {
		t.Errorf("Messages lanes warned: %v", w)
	}
}

// A lane derived from an unknown total is itself unknown, not zero.
func TestParseUsage_DerivedLaneIsNilWhenTotalIsAbsent(t *testing.T) {
	u := parseUsage(json.RawMessage(`{"prompt_tokens_details":{"cached_tokens":5}}`))
	if u.Input.NoCache != nil {
		t.Errorf("no-cache lane = %d, want nil when the total was never reported", *u.Input.NoCache)
	}
}

// The raw bytes are the evidence for whatever shape an endpoint really sent,
// and the only way to settle whether a zero is an answer or an unread field.
func TestParseUsage_RawIsPreserved(t *testing.T) {
	raw := json.RawMessage(`{"prompt_tokens":1,"image_tokens":42}`)
	u := parseUsage(raw)
	if string(u.Raw) != string(raw) {
		t.Errorf("raw = %s, want it preserved verbatim", u.Raw)
	}
}

// A usage field this package cannot read must not fail a completion the caller
// already received.
func TestParseUsage_MalformedObjectKeepsBytesAndDoesNotPanic(t *testing.T) {
	raw := json.RawMessage(`{"prompt_tokens":"not a number"}`)
	u := parseUsage(raw)
	if u.Input.Total != nil {
		t.Error("input total should be nil for an undecodable object")
	}
	if string(u.Raw) != string(raw) {
		t.Errorf("raw = %s, want the bytes kept as evidence", u.Raw)
	}
}

// The finish_reason chunk commonly carries "usage": null, and the real usage
// arrives later. "Present" must not be confused with "reported", or the parser
// keeps the null and discards the accounting.
// Reported and Total are what every consumer re-derived from the lane
// pointers. Reported follows the wire rule, so the one shape the lanes cannot
// see — a bare total_tokens — still counts; Total is the sum of what arrived.
func TestUsage_ReportedAndTotal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		reported bool
		total    int64
		totalOK  bool
	}{
		{"absent", ``, false, 0, false},
		{"null", `null`, false, 0, false},
		{"empty object", `{}`, false, 0, false},
		{"malformed", `{"prompt_tokens":`, false, 0, false},
		{"both lanes", `{"prompt_tokens":25,"completion_tokens":47,"total_tokens":72}`, true, 72, true},
		{"explicit zeros", `{"prompt_tokens":0,"completion_tokens":0}`, true, 0, true},
		{"completion only", `{"completion_tokens":9}`, true, 9, true},
		{"only total_tokens", `{"total_tokens":5}`, true, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := parseUsage(json.RawMessage(tc.body))
			if got := u.Reported(); got != tc.reported {
				t.Errorf("Reported() = %v, want %v", got, tc.reported)
			}
			total, ok := u.Total()
			if total != tc.total || ok != tc.totalOK {
				t.Errorf("Total() = %d, %v; want %d, %v", total, ok, tc.total, tc.totalOK)
			}
		})
	}
	if (Usage{}).Reported() {
		t.Error("a caller-built zero Usage must not read as reported")
	}
}

func TestTokens_ReadsALaneOrZero(t *testing.T) {
	u := parseUsage(json.RawMessage(`{"prompt_tokens":25,"completion_tokens":47,"prompt_tokens_details":{"cached_tokens":0}}`))
	if got := Tokens(u.Input.Total); got != 25 {
		t.Errorf("Tokens(Input.Total) = %d, want 25", got)
	}
	if got := Tokens(u.Input.CacheRead); got != 0 || u.Input.CacheRead == nil {
		t.Errorf("a reported zero reads 0 and stays reported: got %d, lane nil=%v", got, u.Input.CacheRead == nil)
	}
	if got := Tokens(u.Output.Reasoning); got != 0 || u.Output.Reasoning != nil {
		t.Errorf("an absent lane reads 0 and stays nil: got %d, lane nil=%v", got, u.Output.Reasoning == nil)
	}
}

func TestWireUsage_ReportedDistinguishesNullFromPopulated(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"null", `null`, false},
		{"empty object", `{}`, false},
		{"populated", `{"prompt_tokens":1}`, true},
		{"only details", `{"prompt_tokens_details":{"cached_tokens":0}}`, true},
		{"explicit zeros", `{"total_tokens":0}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var w wireUsage
			if err := json.Unmarshal([]byte(tc.body), &w); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := w.reported(); got != tc.want {
				t.Errorf("reported() = %v, want %v", got, tc.want)
			}
		})
	}
}
