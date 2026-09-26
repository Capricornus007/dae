package subscription

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// mihomo 的 proxies 型別全集，逐種丟進去，看 dae 吃不吃得下。
const mihomoMatrix = `proxies:
  - {name: a-ss, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: p}
  - {name: b-ssr, type: ssr, server: 1.2.3.4, port: 8388, cipher: aes-256-cfb, password: p, protocol: auth_aes128_md5, obfs: plain}
  - {name: c-vmess, type: vmess, server: 1.2.3.4, port: 443, uuid: 3ad286d4-1b91-42fc-aaa6-83ff47452168, alterId: 0, cipher: auto}
  - {name: d-vless, type: vless, server: 1.2.3.4, port: 443, uuid: 3ad286d4-1b91-42fc-aaa6-83ff47452168, tls: true, servername: example.com}
  - {name: e-trojan, type: trojan, server: 1.2.3.4, port: 443, password: p, sni: example.com, tls: true}
  - {name: f-hy2, type: hysteria2, server: 1.2.3.4, port: 443, password: p, sni: example.com}
  - {name: g-hy1, type: hysteria, server: 1.2.3.4, port: 443, auth-str: p, up: 10, down: 50}
  - {name: h-tuic, type: tuic, server: 1.2.3.4, port: 443, uuid: 3ad286d4-1b91-42fc-aaa6-83ff47452168, password: p}
  - {name: i-snell, type: snell, server: 1.2.3.4, port: 443, psk: p, version: 4}
  - {name: j-wg, type: wireguard, server: 1.2.3.4, port: 51820, private-key: "4AO1l9F1F4B1V4B4=", public-key: "l3pIET7H2gI4B0=", ip: 10.0.0.2}
  - {name: k-socks, type: socks5, server: 1.2.3.4, port: 1080, username: u, password: p}
  - {name: l-http, type: http, server: 1.2.3.4, port: 8080, username: u, password: p}
  - {name: m-ssh, type: ssh, server: 1.2.3.4, port: 22, username: root, password: p}
  - {name: n-anytls, type: anytls, server: 1.2.3.4, port: 8443, password: p, sni: example.com}
  - {name: o-direct, type: direct}
  - {name: p-reject, type: reject}
`

func TestMihomoTypeMatrix(t *testing.T) {
	nodes, err := ResolveSubscriptionAsClash(logrus.New(), []byte(mihomoMatrix))
	if err != nil {
		t.Fatalf("clash 解析失敗：%v", err)
	}
	got := map[string]string{}
	for _, n := range nodes {
		k := strings.SplitN(n, "://", 2)[0]
		got[k] = n
	}
	t.Logf("mihomo 16 種型別 → dae 吃下 %d 種：%v", len(nodes), func() []string {
		var s []string
		for k := range got {
			s = append(s, k)
		}
		return s
	}())
	for _, want := range []string{"ss", "ssr", "vmess", "vless", "trojan", "hy2", "tuic", "anytls", "socks5", "http"} {
		if _, ok := got[want]; !ok {
			t.Errorf("mihomo 有 %s 型別，dae 這邊翻不出來", want)
		}
	}
}
