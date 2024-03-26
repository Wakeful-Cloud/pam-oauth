package common

import (
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
)

// LogLevel is the log level
type LogLevel string

// LogLevel constants
var DEBUG = LogLevel(slog.LevelDebug.String())
var INFO = LogLevel(slog.LevelInfo.String())
var WARN = LogLevel(slog.LevelWarn.String())
var ERROR = LogLevel(slog.LevelError.String())

// LogOutput is the log output
type LogOutput string

const (
	FILE   LogOutput = "file"
	STDOUT LogOutput = "stdout"
	STDERR LogOutput = "stderr"
)

// ParseLogLevel parses a log level
func ParseLogLevel(rawLevel LogLevel) (slog.Level, error) {
	var level slog.Level
	err := level.UnmarshalText([]byte(rawLevel))

	return level, err
}

// InitLogger intializes a new slog logger, returning a cleanup function and an error (if any)
func InitLogger(rawLevel LogLevel, rawOutput LogOutput, rawFile string, relative string) (func(), error) {
	// Parse the level
	level, err := ParseLogLevel(rawLevel)

	if err != nil {
		return nil, err
	}

	// Initialize the logger
	var file *os.File
	var logger *slog.Logger

	switch rawOutput {
	case FILE:
		// Open the log file
		file, err = SafeOpen(rawFile, relative, PROTECTED_FILE_MODE, PROTECTED_FOLDER_MODE, SAFE_OPEN_MODE_APPEND)

		if err != nil {
			return nil, err
		}

		logger = slog.New(slog.NewTextHandler(file, &slog.HandlerOptions{
			Level: level,
		}))

	case STDOUT:
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		}))

	case STDERR:
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
		}))

	default:
		return nil, fmt.Errorf("invalid log output: %s", rawOutput)
	}

	// Set the logger as the default
	slog.SetDefault(logger)

	// Log
	slog.Debug("logger initialized",
		slog.String("level", level.String()),
		slog.String("output", string(rawOutput)),
		slog.String("file", rawFile),
	)

	return func() {
		// Attempt to recover from a panic
		cause := recover()

		if cause != nil {
			// Log the panic
			slog.Error("panic recovered",
				slog.Any("cause", cause),
				slog.String("stack", string(debug.Stack())),
			)
		}

		// Close the log file
		if file != nil {
			err = file.Sync()

			if err != nil {
				slog.Error("failed to sync log file",
					slog.Any("error", err),
				)

				err = file.Close()

				if err != nil {
					slog.Error("failed to close log file",
						slog.Any("error", err),
					)
				}
			}
		}

		// Panic
		if cause != nil {
			panic(cause)
		}
	}, nil
}
