package subscription

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// 真實世界訂閱打出來的三個坑，留在這裡當防線。

// 現實裡有商家把 port 寫成字串（chromego 就是 port: '80'）、cipher 寫成 auto。
// port 宣告成 int 會讓整份 YAML 解析失敗，然後掉進 base64 那條把檔案亂切——
// 錯誤以「一堆詭異節點」的形式出現，而不是以錯誤的形式出現。
const clashStringPort = `proxies:
  - name: vmess-strport
    type: vmess
    server: 127.0.0.53
    port: '80'
    uuid: 3ad286d4-1b91-42fc-aaa6-83ff47452168
    alterId: 0
    cipher: auto
    network: tcp
  - name: ss-numport
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: p
`

func TestClashAcceptsStringPortAndAutoCipher(t *testing.T) {
	nodes, err := ResolveSubscriptionAsClash(logrus.New(), []byte(clashStringPort))
	if err != nil {
		t.Fatalf("port 寫成字串不該讓整份訂閱解析失敗：%v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d: %v", len(nodes), nodes)
	}
	// 這一步同時擋住兩個坑：字串 port 有帶進去，且 cipher=auto 沒被誤塞進 dae 的
	// type 欄位（dae 只認 none/""/http，否則回 unexpected field: type: auto）。
	mustParseAll(t, nodes)
	// vmess 的 host:port 在 base64 的 JSON 裡，要解開才看得到字串 port 有沒有帶過去
	var vmessDecoded string
	for _, n := range nodes {
		if strings.HasPrefix(n, "vmess://") {
			raw, e := base64.StdEncoding.DecodeString(strings.TrimPrefix(n, "vmess://"))
			if e != nil {
				t.Fatalf("vmess link 解不開：%v", e)
			}
			vmessDecoded = string(raw)
		}
	}
	if !strings.Contains(vmessDecoded, `"port":"80"`) {
		t.Errorf("字串 port 沒帶進 vmess JSON：%s", vmessDecoded)
	}
	if !strings.Contains(vmessDecoded, `"type":""`) {
		t.Errorf("cipher=auto 不該出現在 dae 的 type 欄位：%s", vmessDecoded)
	}
}

// 一份只有 selector 骨架、節點放在 profile 裡的 sing-box 配置：正確行為是
// 「0 可用節點」並讓呼叫端續試下一種格式，而不是讓 base64 那條把 JSON 行
// 當成節點吐出來（實測曾吐 34 個 "address": "https 之類的神秘東東）。
const singBoxSelectorOnly = `{"outbounds":[
 {"tag":"node-select","type":"selector","outbounds":["auto","direct"]},
 {"tag":"auto","type":"urltest","outbounds":["direct"]},
 {"type":"direct"}
]}`

func TestBase64DoesNotInventNodesFromOtherFormats(t *testing.T) {
	if _, err := ResolveSubscriptionAsSingBox(logrus.New(), []byte(singBoxSelectorOnly)); err == nil {
		t.Fatalf("純骨架的 sing-box 該回報 0 可用節點")
	}
	log := logrus.New()
	for _, payload := range []string{
		singBoxSelectorOnly,
		"port: 7890\nproxies:\n  - {name: a, type: vmess}\n",
		`{"url": "https://example.com/sub"}`,
	} {
		if n := ResolveSubscriptionAsBase64(log, []byte(payload)); len(n) != 0 {
			t.Errorf("base64 不該從這份內容 invent 出節點，卻拿到 %v", n)
		}
	}
}

// 合法 scheme 仍要照常通過（含帶加號的 naive+https）。
func TestBase64StillAcceptsRealLinks(t *testing.T) {
	payload := "ss://YWVzLTI1Ni1nY206cA@1.2.3.4:8388#ok\nnaive+https://u:p@1.2.3.4:443#n2\nvmess://eyJhZGQiOiIxLjIuMy40In0=#v3\n"
	nodes := ResolveSubscriptionAsBase64(logrus.New(), []byte(payload))
	if len(nodes) != 3 {
		t.Fatalf("三條合法 link 都該留下，拿到 %v", nodes)
	}
}
