package acmednschallenge

import (
	"strings"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

type logger struct {
	logger clog.P
}

func (l *logger) Print(args ...interface{}) {
	args[0] = stripLogPrefix(args[0].(string))
	l.logger.Info(args...)
}

func (l *logger) Printf(format string, args ...interface{}) {
	format = stripLogPrefix(format)
	l.logger.Infof(format, args...)
}

func (l *logger) Println(args ...any) {
	args[0] = stripLogPrefix(args[0].(string))
	l.logger.Info(args...)
}

func (l *logger) Fatal(args ...interface{}) {
	args[0] = stripLogPrefix(args[0].(string))
	l.logger.Error(args...)
}

func (l *logger) Fatalf(format string, args ...interface{}) {
	format = stripLogPrefix(format)
	l.logger.Errorf(format, args...)
}

func (l *logger) Fatalln(args ...any) {
	args[0] = stripLogPrefix(args[0].(string))
	l.logger.Error(args...)
}

func (l *logger) Error(args ...interface{}) {
	args[0] = stripLogPrefix(args[0].(string))
	l.logger.Error(args...)
}

func (l *logger) Errorf(format string, args ...interface{}) {
	format = stripLogPrefix(format)
	l.logger.Errorf(format, args...)
}

func stripLogPrefix(msg string) string {
	if len(msg) > 0 && msg[0] == '[' {
		if idx := strings.Index(msg, "]"); idx != -1 && idx+1 < len(msg) {
			return strings.TrimSpace(msg[idx+1:])
		}
	}
	return msg
}
