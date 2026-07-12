package protocol

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestProtocolRegressionCorpus(t *testing.T) {
	content, err := os.ReadFile("testdata/regression.json")
	if err != nil {
		t.Fatalf("read regression corpus: %v", err)
	}
	var cases []struct {
		Name       string     `json:"name"`
		Network    string     `json:"network"`
		Payload    string     `json:"payload"`
		PayloadHex string     `json:"payloadHex"`
		Policy     Policy     `json:"policy"`
		DPI        *DPIResult `json:"dpi"`
		Protocol   string     `json:"protocol"`
		Action     string     `json:"action"`
	}
	if err := json.Unmarshal(content, &cases); err != nil {
		t.Fatalf("decode regression corpus: %v", err)
	}
	if len(cases) < 8 {
		t.Fatalf("regression corpus has only %d cases", len(cases))
	}
	for _, testCase := range cases {
		t.Run(testCase.Name, func(t *testing.T) {
			payload := []byte(testCase.Payload)
			if testCase.PayloadHex != "" {
				payload, err = hex.DecodeString(testCase.PayloadHex)
				if err != nil {
					t.Fatalf("decode payload: %v", err)
				}
			}
			testCase.Policy.Network = testCase.Network
			result := Detect(payload, testCase.Policy)
			if testCase.DPI != nil {
				result = ApplyDPI(result, testCase.Policy, *testCase.DPI)
			}
			if result.Protocol != testCase.Protocol || result.Action != testCase.Action {
				t.Fatalf("result protocol/action = %s/%s, want %s/%s: %#v", result.Protocol, result.Action, testCase.Protocol, testCase.Action, result)
			}
		})
	}
}
