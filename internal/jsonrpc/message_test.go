package jsonrpc

import "testing"

func TestClassification(t *testing.T) {
	cases := []struct {
		name                        string
		raw                         string
		req, notification, response bool
	}{
		{"request", `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, true, false, false},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, false, true, false},
		{"response", `{"jsonrpc":"2.0","id":1,"result":{}}`, false, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := Parse([]byte(c.raw))
			if err != nil {
				t.Fatal(err)
			}
			if m.IsRequest() != c.req || m.IsNotification() != c.notification || m.IsResponse() != c.response {
				t.Errorf("got req=%v notif=%v resp=%v", m.IsRequest(), m.IsNotification(), m.IsResponse())
			}
		})
	}
}

func TestToolName(t *testing.T) {
	m, _ := Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{}}}`))
	if got := m.ToolName(); got != "send_email" {
		t.Errorf("ToolName = %q, want send_email", got)
	}
	other, _ := Parse([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if got := other.ToolName(); got != "" {
		t.Errorf("ToolName on non-call = %q, want empty", got)
	}
}
