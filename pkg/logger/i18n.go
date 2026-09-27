package logger

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/sirupsen/logrus"
)

// 日誌多語言：dae 的訊息字串散在幾百個呼叫點，逐條改寫會跟上游永久分岔，
// 所以改成「出口翻譯」——呼叫點照舊寫英文，寫出檔案前由這個 hook 查表改寫。
// 代價是翻譯表要跟著訊息走；好處是上游合併零衝突、預設（en）行為完全不變。

type zhCatalog struct {
	exact     map[string]string
	prefix    map[string]string
	errExact  map[string]string
	errPrefix map[string]string
	// eofFallback 是表查不到時的兜底句，也是唯一一處由程式自己拼中文句子的地方，
	// 所以繁簡各一份：寫死一種，另一種模式下就會冒出異體字。
	eofFallback string
}

var catalogs = map[string]zhCatalog{
	"hant": {messagesHant, messagePrefixesHant, errsHant, errPrefixesHant, "對端沒回資料就把線關了（%s）"},
	"hans": {messagesHans, messagePrefixesHans, errsHans, errPrefixesHans, "对端没回数据就把线关了（%s）"},
}

// zhVariant 決定設定值要用哪一份表。
// 只寫 `zh` 時給繁體：這臺機器的設定就是 `zh`，改預設等於動到現況。
func zhVariant(lang string) string {
	lang = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(lang)), "_", "-")
	switch lang {
	case "zh-cn", "zh-sg", "zh-hans", "zh-hans-cn", "zh-hans-sg", "hans", "cn":
		return "hans"
	case "zh", "zh-tw", "zh-hk", "zh-mo", "zh-hant", "zh-hant-tw", "zh-hant-hk", "hant", "tw", "hk":
		return "hant"
	}
	return ""
}

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

// Fire 只改 Message 與 err 欄位的值，欄位名保持英文：
// 要 grep 日誌的人（還有 CI 的比對）不能被迫記第二套鍵名。
func (i18nHook) Fire(e *logrus.Entry) error {
	cat, ok := catalogs[zhVariant(Language())]
	if !ok {
		return nil
	}
	e.Message = translateMessage(cat, e.Message)
	if v, hasErr := e.Data["err"]; hasErr {
		if s, isString := v.(string); isString {
			e.Data["err"] = translateErr(cat, s)
		}
	}
	return nil
}

func (i18nHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// translateMessage 用「最長前綴命中」而不是正則：訊息裡常帶動態尾巴
// （`[StickyIP] Check cycle incremented new_cycle=3`、`Group 'proxy' [tcp4]:`），
// 前綴換完把剩下的原樣接回，否則「哪條節點、第幾週期」這種證據就沒了。
func translateMessage(cat zhCatalog, msg string) string {
	if t, ok := cat.exact[msg]; ok {
		return t
	}
	best, bestLen := "", 0
	for prefix := range cat.prefix {
		if len(prefix) > bestLen && strings.HasPrefix(msg, prefix) {
			best, bestLen = prefix, len(prefix)
		}
	}
	if best == "" {
		return msg
	}
	return cat.prefix[best] + msg[bestLen:]
}

// translateErr 處理 Go 自己產生的錯誤字串。找不到就原樣留英文——猜錯的翻譯比英文更糟。
func translateErr(cat zhCatalog, s string) string {
	if t, ok := cat.errExact[s]; ok {
		return t
	}
	for prefix, t := range cat.errPrefix {
		if strings.HasPrefix(s, prefix) {
			// 表裡的值自帶分隔（尾端的「：」或空格），這裡不再補標點。
			return t + s[len(prefix):]
		}
	}
	if strings.Contains(s, "EOF") {
		return fmt.Sprintf(cat.eofFallback, s)
	}
	return s
}
