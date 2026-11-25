package notify

// Locate is locate, for fork_test.go.
var Locate = locate

// SecretsOf is secretsOf.
var SecretsOf = secretsOf

// Report is how DeliverMessage words one channel's outcome, "" for none.
func Report(err error, answered, early bool, stopped string) string {
	if out := (&Channels{}).report(err, answered, early, stopped); out != nil {
		return out.Error()
	}
	return ""
}
