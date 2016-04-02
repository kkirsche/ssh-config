package sshConfig

import (
	"os"
	"testing"
)

func TestNewLogger(t *testing.T) {
	logger := New("Prefix String", os.Stdout, os.Stderr, false)

	if logger.Prefix != "Prefix String" {
		t.FailNow()
	}

	if logger.Out != os.Stdout {
		t.FailNow()
	}

	if logger.Err != os.Stderr {
		t.FailNow()
	}

	if logger.Verbose != false {
		t.FailNow()
	}
}

func TestNewLoggerWithDefaults(t *testing.T) {
	logger := NewWithDefaults("Prefix String", false)

	if logger.Prefix != "Prefix String" {
		t.FailNow()
	}

	if logger.Out != os.Stdout {
		t.FailNow()
	}

	if logger.Err != os.Stderr {
		t.FailNow()
	}

	if logger.Verbose != false {
		t.FailNow()
	}
}
