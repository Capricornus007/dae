package logger

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestTranslateMessage(t *testing.T) {
	cat := catalogs["tc"]
	if got := translateMessage(cat, "Connectivity Check Failed"); got == "Connectivity Check Failed" {
		t.Error("靜態訊息沒被翻譯")
	}
	// 前綴命中要保留動態尾巴，否則「哪條節點掛了」這種證據就沒了。
	msg := "[StickyIP] No cache entry found proxy_addr=cfyes.example:443"
	if got := translateMessage(cat, msg); !strings.HasSuffix(got, "proxy_addr=cfyes.example:443") {
		t.Errorf("動態尾巴被吃掉或沒翻: %q", got)
	}
	// 最長前綴優先：這兩條共享前綴，不能翻成同一句。
	a := translateMessage(cat, "[StickyIP] Cache hit - returning cached IP x")
	b := translateMessage(cat, "[StickyIP] Cache hit - using cached proxy IP x")
	if a == b {
		t.Errorf("兩條不同的訊息被翻成同一句: %q", a)
	}
	// 回歸測試：outbound 那批訊息的**原字串帶方括號**，顯示時才被 formatter 拆成前綴。
	// 用顯示形態（`StickyIP: …`）建表會永遠命中不了——這個坑踩過。
	if got := translateMessage(cat, "[StickyIP] Check cycle incremented new_cycle=3 old_cycle=2"); !strings.HasPrefix(got, "固定出口") {
		t.Errorf("方括號型訊息沒被翻譯: %q", got)
	}
	if got := translateMessage(cat, "Connectivity Check"); got == "Connectivity Check" {
		t.Error("健康檢查訊息沒被翻譯（它的數字是欄位，所以該走精確鍵）")
	}
	if got := translateMessage(cat, "totally unknown message from upstream"); got != "totally unknown message from upstream" {
		t.Errorf("不認識的訊息必須原樣留著，實際: %q", got)
	}
}

// 兩份表的鍵必須完全一致：差一個鍵的症狀是「繁體翻得出來、簡體留英文」，
// 光看日誌很難發現，所以在源頭鎖住。
func TestCatalogsAreInSync(t *testing.T) {
	hant, hans := catalogs["tc"], catalogs["sc"]
	pairs := map[string][2]map[string]string{
		"exact":     {hant.exact, hans.exact},
		"prefix":    {hant.prefix, hans.prefix},
		"errExact":  {hant.errExact, hans.errExact},
		"errPrefix": {hant.errPrefix, hans.errPrefix},
	}
	for name, pair := range pairs {
		got, want := pair[0], pair[1]
		for k := range got {
			if _, ok := want[k]; !ok {
				t.Errorf("%s：簡體那份少了鍵 %q", name, k)
			}
		}
		for k := range want {
			if _, ok := got[k]; !ok {
				t.Errorf("%s：繁體那份少了鍵 %q", name, k)
			}
		}
		for k, v := range want {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s：簡體鍵 %q 的值是空的", name, k)
			}
		}
	}
}

// 簡繁要真的差在字形**與**術語，否則其中一份只是抄來的。
func TestVariantsDiffer(t *testing.T) {
	hant := translateMessage(catalogs["tc"], "Connectivity Check Failed")
	hans := translateMessage(catalogs["sc"], "Connectivity Check Failed")
	if hant == hans {
		t.Fatalf("繁簡翻出同一句：%q", hant)
	}
	if !strings.Contains(hant, "節點") || !strings.Contains(hans, "节点") {
		t.Errorf("字形沒對上：繁 %q／簡 %q", hant, hans)
	}
	// 同一個英文字在兩地的习惯叫法不同（cache → 快取／缓存）。
	h2 := translateMessage(catalogs["tc"], "[StickyIP] Cache entry expired")
	s2 := translateMessage(catalogs["sc"], "[StickyIP] Cache entry expired")
	if !strings.Contains(h2, "快取") || !strings.Contains(s2, "缓存") {
		t.Errorf("術語沒對上：繁 %q／簡 %q", h2, s2)
	}
}

func TestChineseVariant(t *testing.T) {
	for lang, want := range map[string]string{
		"tc": "tc", "sc": "sc", "TC": "tc", "SC": "sc",
		"zh": "tc", "zh-TW": "tc", "zh-HK": "tc", "zh_hant": "tc",
		"zh-CN": "sc", "zh-Hans": "sc", "zh_hans_cn": "sc", "zh-SG": "sc",
		"en": "", "": "", "sg": "", "ja": "",
	} {
		if got := chineseVariant(lang); got != want {
			t.Errorf("chineseVariant(%q) = %q，應為 %q", lang, got, want)
		}
	}
	// 設定值可能被人手動打的時候帶了空白，也要能吃（放變數而不是 map 鍵，
	// 否則 gocritic 的 mapKey 會報「鍵裡有可疑空白」）。
	if got := chineseVariant(" sc "); got != "sc" {
		t.Errorf("帶前後空白的值沒被 trim：chineseVariant(\" sc \") = %q", got)
	}
}

func TestTranslateErr(t *testing.T) {
	cat := catalogs["tc"]
	if got := translateErr(cat, "no applicable IP for this network type"); got == "no applicable IP for this network type" {
		t.Error("常見錯誤沒被翻譯")
	}
	got := translateErr(cat, `Head "https://www.youtube.com/generate_204": EOF`)
	if !strings.HasPrefix(got, "對 HEAD 請求沒回應 \"") {
		t.Errorf("Head 型錯誤應走前綴翻譯，實際: %q", got)
	}
	if !strings.Contains(got, "youtube.com") {
		t.Errorf("翻譯後要把靶子留著，實際: %q", got)
	}
	// 引號要成對：前綴吃掉 `Head "` 之後，替換值得把開引號補回來，
	// 否則會印成「…：http://x": EOF」這種半個引號的樣子。
	if !strings.Contains(got, "\"https://www.youtube.com") {
		t.Errorf("開引號沒補回來: %q", got)
	}
	// 兜底句也分繁簡，不能兩邊冒出同一種字形。
	if h := translateErr(catalogs["tc"], "read tcp: EOF"); !strings.Contains(h, "對端") {
		t.Errorf("繁體兜底句冒出簡體: %q", h)
	}
	if h := translateErr(catalogs["sc"], "read tcp: EOF"); !strings.Contains(h, "对端") {
		t.Errorf("簡體兜底句冒出繁體: %q", h)
	}
	if got := translateErr(cat, "some random Go error"); got != "some random Go error" {
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

	SetLanguage("sc")
	if err := (i18nHook{}).Fire(e); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.Message, "节点") {
		t.Errorf("簡體模式下訊息沒被改成簡體: %q", e.Message)
	}
	if e.Data["err"] == "i/o timeout" {
		t.Error("簡體模式下 err 欄位沒被改寫")
	}
}
