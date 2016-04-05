package sshConfig

import "testing"

func TestIsLineNewHost(t *testing.T) {
	if IsLineNewHost("Host Ghost") != "Ghost" {
		t.FailNow()
	}

	if IsLineNewHost(" Host Ghost ") != "Ghost" {
		t.FailNow()
	}

	if IsLineNewHost(" Host GHOST ") != "GHOST" {
		t.FailNow()
	}

	if IsLineNewHost(" Host ghost ") != "ghost" {
		t.FailNow()
	}
}
