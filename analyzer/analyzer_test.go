package analyzer

import (
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func Test(t *testing.T) {
	path, _ := filepath.Abs("../samples")

	testCases := []struct {
		Name string
	}{
		{"global-var"},
		{"http-response-assigned"},
		{"http-response-ignored"},
		{"http-response-nopcloser"},
		{"http-response-not-assigned"},
		{"http-response-on-defer-statement"},
		{"http-response-on-go-statement"},
		{"multi-assign"},
		{"struct-field"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()
			analysistest.Run(t, path, Analyzer, testCase.Name)
		})
	}
}
