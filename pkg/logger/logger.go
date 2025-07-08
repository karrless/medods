// Package logger provides logger
package logger

import (
	"context"

	"go.uber.org/zap"
)

type KeyString string

const LoggerKey KeyString = "logger"

// Logger interface
type Logger interface {
	Debug(msg string, fields ...zap.Field)
	Info(msg string, fields ...zap.Field)
	Fatal(msg string, fields ...zap.Field)
}

// logger
type logger struct {
	logger *zap.Logger
}

// Debug message
func (l *logger) Debug(msg string, fields ...zap.Field) {
	l.logger.Debug(msg, fields...)
}

// Info message
func (l *logger) Info(msg string, fields ...zap.Field) {
	l.logger.Info(msg, fields...)
}

func (l *logger) Fatal(msg string, fields ...zap.Field) {
	l.logger.Fatal(msg, fields...)
}

// Create new logger
func New(debug bool) Logger {
	var zapLogger *zap.Logger
	var err error
	if debug {
		zapLogger, err = zap.NewDevelopment()
	} else {
		zapLogger, err = zap.NewProduction()
	}
	if err != nil {
		panic(err)
	}
	defer zapLogger.Sync()

	return &logger{logger: zapLogger}
}

func GetLoggerFromCtx(ctx context.Context) Logger {
	return ctx.Value(LoggerKey).(Logger)
}
