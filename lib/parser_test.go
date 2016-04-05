package sshConfig

import "testing"

func TestIsLineNewHost(t *testing.T) {
	if FindHost("Host Ghost") != "Ghost" {
		t.FailNow()
	}

	if FindHost(" Host Ghost ") != "Ghost" {
		t.FailNow()
	}

	if FindHost(" Host GHOST ") != "GHOST" {
		t.FailNow()
	}

	if FindHost(" Host ghost ") != "ghost" {
		t.FailNow()
	}
}
