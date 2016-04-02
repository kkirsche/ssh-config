package sshConfig

import "testing"

func TestValidAddressFamilyAnswers(t *testing.T) {
	for i, value := range ValidAddressFamilyAnswers() {
		if i == 0 && value != "" {
			t.FailNow()
		}
		if i == 1 && value != "any" {
			t.FailNow()
		}
		if i == 2 && value != "inet" {
			t.FailNow()
		}
		if i == 3 && value != "inet6" {
			t.FailNow()
		}
	}
}

func TestValidYesNoAnswers(t *testing.T) {
	for i, value := range ValidYesOrNo() {
		if i == 0 && value != "" {
			t.FailNow()
		}
		if i == 1 && value != "yes" {
			t.FailNow()
		}
		if i == 2 && value != "no" {
			t.FailNow()
		}
	}
}

func TestBlankValidStringArgs(t *testing.T) {
	if !ValidStringArgs([]string{"", "any", "inet", "inet6"}, "") {
		t.FailNow()
	}
}

func TestAnyValidStringArgs(t *testing.T) {
	if !ValidStringArgs([]string{"", "any", "inet", "inet6"}, "any") {
		t.FailNow()
	}
}

func TestInetValidStringArgs(t *testing.T) {
	if !ValidStringArgs([]string{"", "any", "inet", "inet6"}, "inet") {
		t.FailNow()
	}
}

func TestInet6ValidStringArgs(t *testing.T) {
	if !ValidStringArgs([]string{"", "any", "inet", "inet6"}, "inet6") {
		t.FailNow()
	}
}

func TestInvalidInputValidStringArgs(t *testing.T) {
	if ValidStringArgs([]string{"", "any", "inet", "inet6"}, "WTF BBQ") {
		t.FailNow()
	}
}
