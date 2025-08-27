package acmednschallenge

import (
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

type logger struct {
	logger clog.P
}

func (l *logger) Print(args ...interface{}) {
	l.logger.Info(args...)
}

func (l *logger) Printf(format string, args ...interface{}) {
	l.logger.Infof(format, args...)
}

func (l *logger) Println(args ...any) {
	l.logger.Info(args...)
}

func (l *logger) Fatal(args ...interface{}) {
	l.logger.Fatal(args...)
}

func (l *logger) Fatalf(format string, args ...interface{}) {
	l.logger.Fatalf(format, args...)
}

func (l *logger) Fatalln(args ...any) {
	l.logger.Fatal(args...)
}

func (l *logger) Error(args ...interface{}) {
	l.logger.Error(args...)
}

func (l *logger) Errorf(format string, args ...interface{}) {
	l.logger.Errorf(format, args...)
}
