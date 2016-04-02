package sshConfig

import (
	"fmt"
	"io"
	"os"
)

// Logger represents an active logging object that generates lines of output to
// an io.Writer. Each logging operation makes a single call to the Writer's
// Write method. A Logger can be used simultaneously from multiple goroutines;
// it guarantees to serialize access to the Writer.
type Logger struct {
	Prefix  string
	Out     io.Writer
	Err     io.Writer
	Verbose bool
}

// New creates a new Logger. The out variable sets the destination to which log
// data will be written. Errors will be written to Err. The prefix appears
// at the beginning of each generated log line.
func New(prefix string, out, err io.Writer, verbose bool) *Logger {
	return &Logger{
		Prefix:  prefix,
		Out:     out,
		Err:     err,
		Verbose: verbose,
	}
}

// NewWithDefaults creates a new Logger using default outputs. The prefix appears
// at the beginning of each generated log line. In this, Out and Err are set to
// os.Stdout and os.Stderr respectively
func NewWithDefaults(prefix string, verbose bool) *Logger {
	return &Logger{
		Prefix:  prefix,
		Out:     os.Stdout,
		Err:     os.Stderr,
		Verbose: verbose,
	}
}

func (l *Logger) printPrefix() {
	fmt.Fprint(l.Out, l.Prefix)
}

func (l *Logger) printVerbosePrefix() {
	fmt.Fprint(l.Out, l.Prefix)
}

// Println calls fmt's Println to write the formatted message to stdout.
func (l *Logger) Println(v ...interface{}) {
	l.printPrefix()
	fmt.Println(v...)
}

// VerbosePrintln calls fmt's Println to write the formatted message to stdout
// if the logger is in verbose mode.
func (l *Logger) VerbosePrintln(v ...interface{}) {
	if l.Verbose {
		l.printVerbosePrefix()
		fmt.Fprintln(l.Out, v...)
	}
}

// Printf calls fmt's Fprintf to write the formatted message to the provided
// io.Writer output (default: stdout).
func (l *Logger) Printf(format string, v ...interface{}) {
	l.printPrefix()
	fmt.Fprintf(l.Out, format+"\n", v)
}

// VerbosePrintf calls fmt's Fprintf to write the formatted message to the
// provided io.Writer output (default: stdout). This takes into account whether
// the logger is in verbose mode.
func (l *Logger) VerbosePrintf(format string, v ...interface{}) {
	if l.Verbose {
		l.printVerbosePrefix()
		fmt.Fprintf(l.Out, format+"\n", v)
	}
}

// Errorf calls fmt's Fprintf to write the formatted message to the provided
// io.Writer output (default: stderr).
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.printPrefix()
	fmt.Fprintf(l.Err, format+"\n", v)
}

// VerboseErrorf calls fmt's Fprintf to write the formatted message to the
// provided io.Writer error output (default: stderr). This takes into account
// whether the logger is in verbose mode.
func (l *Logger) VerboseErrorf(format string, v ...interface{}) {
	if l.Verbose {
		l.printVerbosePrefix()
		fmt.Fprintf(l.Err, format+"\n", v)
	}
}
