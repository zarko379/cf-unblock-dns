package main

import (
	"fmt"
	"log"
	"os"
	"strings"
)

type logLevel int

const (
	levelDebug logLevel = iota
	levelInfo
	levelWarning
	levelError
)

var (
	currentLevel = levelInfo
	logger       = log.New(os.Stdout, "", log.Ldate|log.Ltime)
)

// configureLogging omits timestamps under systemd: the journal adds its own.
func configureLogging(level string) error {
	switch strings.ToUpper(level) {
	case "DEBUG":
		currentLevel = levelDebug
	case "INFO":
		currentLevel = levelInfo
	case "WARNING":
		currentLevel = levelWarning
	case "ERROR":
		currentLevel = levelError
	default:
		return fmt.Errorf("nivel de registro desconocido: %s", level)
	}
	if os.Getenv("INVOCATION_ID") != "" {
		logger.SetFlags(0)
	}
	return nil
}

func logAt(level logLevel, name, format string, args ...any) {
	if level < currentLevel {
		return
	}
	logger.Printf(name+" "+format, args...)
}

func debugf(format string, args ...any) { logAt(levelDebug, "DEBUG", format, args...) }
func infof(format string, args ...any)  { logAt(levelInfo, "INFO", format, args...) }
func warnf(format string, args ...any)  { logAt(levelWarning, "WARNING", format, args...) }
func errorf(format string, args ...any) { logAt(levelError, "ERROR", format, args...) }
