package logger

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestTranslateMessage(t *testing.T) {
	if got := translateMessage("Connectivity Check Failed"); got == "Connectivity Check Failed" {
		t.Error("靜態訊息沒被翻譯")
	}
	// 前綴命中要保留動態尾巴，否則「哪條節點掛了」這種證據就沒了。
	msg := "StickyIP: No cache entry found proxy_addr=cfyes.example:443"
	if got := translateMessage(msg); !strings.HasSuffix(got, "proxy_addr=cfyes.example:443") {
		t.Errorf("動態尾巴被吃掉或沒翻: %q", got)
	}
	// 最長前綴優先：這兩條共享前綴，不能翻成同一句。
	a := translateMessage("StickyIP: Cache hit - returning cached IP x")
	b := translateMessage("StickyIP: Cache hit - using cached proxy IP x")
	if a == b {
		t.Errorf("兩條不同的訊息被翻成同一句: %q", a)
	}
	if got := translateMessage("totally unknown message from upstream"); got != "totally unknown message from upstream" {
		t.Errorf("不認識的訊息必須原樣留著，實際: %q", got)
	}
}

func TestTranslateErr(t *testing.T) {
	if got := translateErr("no applicable IP for this network type"); got == "no applicable IP for this network type" {
		t.Error("常見錯誤沒被翻譯")
	}
	got := translateErr(`Head "https://www.youtube.com/generate_204": EOF`)
	if !strings.HasPrefix(got, "對 HEAD 請求沒回應：") {
		t.Errorf("Head 型錯誤應走前綴翻譯，實際: %q", got)
	}
	if !strings.Contains(got, "youtube.com") {
		t.Errorf("翻譯後要把靶子留著，實際: %q", got)
	}
	if got := translateErr("some random Go error"); got != "some random Go error" {
		t.Errorf("不認識的錯誤必須原樣留著，實際: %q", got)
	}
}

// 預設（en）必須完全不改寫——這是「加了設定但沒動到別人」的底線。
func TestDefaultLanguageIsPassthrough(t *testing.T) {
	defer SetLanguage(Language())
	SetLanguage("en")
	e := logrus.NewEntry(logrus.New())
	e.Message = "Connectivity Check Failed"
	e.Data = logrus.Fields{"err": "i/o timeout"}
	if err := (i18nHook{}).Fire(e); err != nil {
		t.Fatal(err)
	}
	if e.Message != "Connectivity Check Failed" || e.Data["err"] != "i/o timeout" {
		t.Errorf("英文模式下內容被改寫: %q / %v", e.Message, e.Data["err"])
	}

	SetLanguage("zh")
	if err := (i18nHook{}).Fire(e); err != nil {
		t.Fatal(err)
	}
	if e.Message == "Connectivity Check Failed" {
		t.Error("中文模式下訊息沒被改寫")
	}
	if e.Data["err"] == "i/o timeout" {
		t.Error("中文模式下 err 欄位沒被改寫")
	}
}
