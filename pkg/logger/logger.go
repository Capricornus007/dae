/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package logger

import (
	"sync"

	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"gopkg.in/natefinch/lumberjack.v2"
)

// SetLogger 會被重複呼叫（本體＋標準 logger、重載時再跑一次），
// 所以 hook 要冪等，否則每重載一次日誌就被翻譯兩遍。
var hooked sync.Map

func SetLogger(log *logrus.Logger, logLevel string, disableTimestamp bool, logFileOpt *lumberjack.Logger) {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}

	log.SetLevel(level)
	log.SetFormatter(&prefixed.TextFormatter{
		DisableTimestamp: disableTimestamp,
		FullTimestamp:    true,
		ForceFormatting:  true,
		TimestampFormat:  "2006-01-02 15:04:05",
	})
	if _, loaded := hooked.LoadOrStore(log, struct{}{}); !loaded {
		log.AddHook(i18nHook{})
	}
	if logFileOpt != nil {
		log.SetOutput(logFileOpt)
	}
}
