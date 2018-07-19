package main

import (
	"testing"
)

func TestParseCodeRange(t *testing.T) {
	tests := []struct {
		in  string
		out []codeRange
	}{
		{"", []codeRange{}},
		{"10-20", []codeRange{codeRange{10, 20}}},
		{" 10 - 20", []codeRange{codeRange{10, 20}}},
		{" 200- 300; 400 -500;", []codeRange{
			codeRange{200, 300},
			codeRange{400, 500},
		}},
		{"10;20-30", []codeRange{
			codeRange{10, 10},
			codeRange{20, 30},
		}},
	}
	for _, test := range tests {
		want := test.out
		got, err := parseCodeRange(test.in)
		if err != nil {
			t.Errorf("parseCodeRange(%#v) got error: %v. want %v", test.in, err, want)
			return
		}
		if len(got) != len(want) {
			t.Errorf("parseCodeRange(%v) got %v. Want %v", test.in, got, want)
			return
		}
		for i := range got {
			if got[i].lower != want[i].lower || got[i].upper != want[i].upper {
				t.Errorf("parseCodeRange(%v) got %v[%d]. Want %v[%d]", test.in, got, i, want, i)
			}
		}
	}

}

func TestIsCodeInRange(t *testing.T) {
	tests := []struct {
		code  int
		codeRanges []codeRange
		want bool
	}{
		{200, []codeRange{codeRange{200, 300}}, true},
		{300, []codeRange{codeRange{200, 300}}, true},
		{300, []codeRange{codeRange{200, 299}}, false},
		{100, []codeRange{codeRange{200, 300}}, false},
		{400, []codeRange{codeRange{200, 300}}, false},
		{200, []codeRange{codeRange{200, 300}, codeRange{400, 500}}, true},
		{400, []codeRange{codeRange{200, 300}, codeRange{400, 500}}, true},
		{350, []codeRange{codeRange{200, 300}, codeRange{400, 500}}, false},
	}

	for _, test := range tests {
		got := isCodeInRange(test.code, test.codeRanges)
		if got != test.want {
			t.Errorf("isCodeInRange(%v, %#v) got: %v. Want: %v", test.code, test.codeRanges, got, test.want)
		}
	}
}
