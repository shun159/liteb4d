/* Copyright (C) 2022-present, Eishun Kondoh <dreamdiagnosis@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU GPL as published by
 * the FSF; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logz *zap.Logger

func Init() error {
	logConfig := zap.Config{
		Level:    zap.NewAtomicLevel(),
		Encoding: "console",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "Time",
			LevelKey:       "Level",
			NameKey:        "Name",
			MessageKey:     "Msg",
			StacktraceKey:  "St",
			EncodeLevel:    zapcore.CapitalColorLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	lg, err := logConfig.Build()
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %s", err)
	}
	logz = lg
	return nil
}

func Debug(msg string, fields ...any) {
	s := fmt.Sprintf(msg, fields...)
	logz.Debug(s)
}

func Info(msg string, fields ...any) {
	s := fmt.Sprintf(msg, fields...)
	logz.Info(s)
}

func Warn(msg string, fields ...any) {
	s := fmt.Sprintf(msg, fields...)
	logz.Warn(s)
}

func Error(msg string, fields ...any) {
	s := fmt.Sprintf(msg, fields...)
	logz.Error(s)
}
