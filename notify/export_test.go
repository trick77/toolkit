package notify

// Locate is locate, for fork_test.go.
var Locate = locate

// SecretsOf is secretsOf.
var SecretsOf = secretsOf

// ParamsFor are the params a message goes out with on the channel u.
func ParamsFor(u string, m Message) (map[string]string, error) {
	c, err := NewChannels([]string{u})
	if err != nil {
		return nil, err
	}
	return c.channels[0].params(m), nil
}

// Report is how DeliverMessage words one channel's outcome, "" for none.
func Report(err error, answered, early bool, stopped string) string {
	if out := (&Channels{}).report(err, answered, early, stopped); out != nil {
		return out.Error()
	}
	return ""
}
