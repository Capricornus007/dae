package logger

import (
	"strings"
	"sync/atomic"

	"github.com/sirupsen/logrus"
)

// 日誌多語言：dae 的訊息字串散在幾百個呼叫點，逐條改寫會跟上游永久分岔，
// 所以改成「出口翻譯」——呼叫點照舊寫英文，寫出檔案前由這個 hook 依前綴換字。
// 代價是翻譯表要跟著訊息走；好處是上游合併零衝突、預設（en）行為完全不變。

var logLanguage atomic.Value // string

func init() {
	logLanguage.Store("en")
}

// SetLanguage 由設定檔驅動；"en" 或沒認得的語言＝完全不改寫。
func SetLanguage(lang string) {
	lang = strings.ToLower(strings.TrimSpace(lang))
	if lang == "" {
		lang = "en"
	}
	logLanguage.Store(lang)
}

func Language() string {
	v, _ := logLanguage.Load().(string)
	return v
}

type i18nHook struct{}

// Entries 只改 Message 與 err 欄位的值，欄位名保持英文：
// 要 grep 日誌的人（還有 CI 的比對）不能被迫記第二套鍵名。
func (i18nHook) Entries(e *logrus.Entry) []*logrus.Entry {
	switch Language() {
	case "zh", "zh-cn", "zh-tw", "zh_hans", "zh_hant":
		e.Message = translateMessage(e.Message)
		if v, ok := e.Data["err"]; ok {
			if s, ok := v.(string); ok {
				e.Data["err"] = translateErr(s)
			}
		}
	}
	return []*logrus.Entry{e}
}

func (i18nHook) Fire(e *logrus.Entry) error {
	i18nHook{}.Entries(e)
	return nil
}

func (i18nHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// translateMessage 用「最長前綴命中」而不是正則：訊息裡常帶動態尾巴
// （`Connectivity Check avg_10=…`、`Group 'proxy' [tcp4]:`），前綴換完把剩下的原樣接回。
func translateMessage(msg string) string {
	if t, ok := messagesZh[msg]; ok {
		return t
	}
	best, bestLen := "", 0
	for prefix := range messagePrefixesZh {
		if len(prefix) > bestLen && strings.HasPrefix(msg, prefix) {
			best, bestLen = prefix, len(prefix)
		}
	}
	if best == "" {
		return msg
	}
	return messagePrefixesZh[best] + msg[bestLen:]
}

// translateErr 處理 Go 自己產生的錯誤字串。找不到就原樣留英文——
// 猜錯的翻譯比英文更糟。
func translateErr(s string) string {
	if t, ok := errsZh[s]; ok {
		return t
	}
	for prefix, t := range errPrefixesZh {
		if strings.HasPrefix(s, prefix) {
			return t + "：" + s[len(prefix):]
		}
	}
	if strings.Contains(s, "EOF") {
		return "對端沒回資料就把線關了（" + s + "）"
	}
	return s
}
