package subscription

import (
	"net/url"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// NB4A（sing-box）能吃的協定，dae 這邊也要能從訂閱翻出來。
// 驗收方式只有一個：生成的 link 餵回 dae 自己的 NewNetproxyDialerFromLink。
//
// 兩條「寧可不生成」的底線，都是讀 dae 的 dialer 原始碼定的：
//   - naive+quic：dialer/naive/naive.go 的 toDialer 直接回 "naive+quic is not supported yet"
//   - juicity：link 的 username 位置會被當 UUID 解析，沒有合法 UUID 就建不起 dialer
const singBoxExoticSample = `{"outbounds":[
 {"tag":"ssr1","type":"shadowsocksr","server":"ssr.example.com","server_port":8388,
  "password":"p@ss","method":"aes-256-cfb","protocol":"auth_aes128_md5",
  "protocol_param":"1024:fake","obfs":"http_simple","obfs_param":"host=bing.com"},
 {"tag":"anytls1","type":"anytls","server":"any.example.com","server_port":8443,
  "passwords":["secret1"],"tls":{"enabled":true,"server_name":"any.example.com"}},
 {"tag":"naive1","type":"naive","server":"naive.example.com","server_port":443,
  "protocol":"https","username":"nuser","password":"npass","tls":{"enabled":true}},
 {"tag":"juic1","type":"juicity","server":"example.com","server_port":443,
  "uuid":"3ad286d4-1b91-42fc-aaa6-83ff47452168","password":"jpass",
  "congestion_control":"bbr","tls":{"enabled":true,"server_name":"example.com","insecure":true}},
 {"tag":"naive-h3","type":"naive","server":"h3.example.com","server_port":443,
  "protocol":"http3","password":"npass2","tls":{"enabled":true}},
 {"tag":"juic-noUUID","type":"juicity","server":"bad.example.com","server_port":443,
  "username":"juser","password":"jpass2","tls":{"enabled":true}},
 {"tag":"ss-obfs","type":"shadowsocks","server":"a.example.com","server_port":8388,
  "method":"chacha20-ietf","password":"x",
  "plugin":"obfs-local","plugin-opts":{"mode":"http","host":"bing.com"}}
]}`

const clashExoticSample = `proxies:
  - name: ssr1
    type: ssr
    server: ssr.example.com
    port: 8388
    cipher: aes-256-cfb
    password: "p@ss"
    protocol: auth_aes128_md5
    protocolparam: "1024:fake"
    obfs: http_simple
    obfsparam: host=bing.com
  - name: anytls1
    type: anytls
    server: any.example.com
    port: 8443
    password: secret1
    sni: any.example.com
  - name: juic1
    type: juicity
    server: example.com
    port: 443
    username: 3ad286d4-1b91-42fc-aaa6-83ff47452168
    password: jpass
    sni: example.com
    allow-insecure: true
    congestion_control: bbr
`

func TestResolveSingBoxExoticProtocols(t *testing.T) {
	nodes, err := ResolveSubscriptionAsSingBox(logrus.New(), []byte(singBoxExoticSample))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// 7 條裡 5 條可用：ssr / anytls / naive(https) / juicity(有 uuid) / ss+obfs。
	// naive+quic 與沒 uuid 的 juicity 必須被跳過，不能吐建不起來的 link。
	if len(nodes) != 5 {
		t.Fatalf("want 5 nodes, got %d: %v", len(nodes), nodes)
	}
	mustParseAll(t, nodes)
	for _, want := range []string{"ssr://", "anytls://", "naive+https://", "juicity://"} {
		found := false
		for _, n := range nodes {
			if strings.HasPrefix(n, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("少了 %s 型別的 link：%v", want, nodes)
		}
	}
	for _, n := range nodes {
		if strings.HasPrefix(n, "naive+quic://") {
			t.Errorf("不該生成 naive+quic（dae 沒實作）：%s", n)
		}
	}
}

func TestResolveClashExoticProtocols(t *testing.T) {
	nodes, err := ResolveSubscriptionAsClash(logrus.New(), []byte(clashExoticSample))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(nodes) != 3 {
		t.Fatalf("want 3 nodes, got %d: %v", len(nodes), nodes)
	}
	mustParseAll(t, nodes)
}

// SSR 的 obfs 跟 SS 的 obfs 在 sing-box 裡是同一個 key 的兩種型別（字串 vs 不存在/走 plugin），
// 兩邊都要能解，而且不能互相污染。
func TestObfsKeyDoesNotCollideBetweenSSAndSSR(t *testing.T) {
	sample := `{"outbounds":[
	 {"tag":"ss-obfs","type":"shadowsocks","server":"a.example.com","server_port":8388,
	  "method":"chacha20-ietf","password":"x",
	  "plugin":"obfs-local","plugin-opts":{"mode":"http","host":"bing.com"}},
	 {"tag":"ssr-node","type":"shadowsocksr","server":"b.example.com","server_port":8389,
	  "method":"aes-128-cfb","password":"y","protocol":"auth_chain_a","obfs":"tls1.2_ticket_auth","obfs_param":""}
	]}`
	nodes, err := ResolveSubscriptionAsSingBox(logrus.New(), []byte(sample))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d: %v", len(nodes), nodes)
	}
	mustParseAll(t, nodes)
	var ssr, ss string
	for _, n := range nodes {
		switch {
		case strings.HasPrefix(n, "ssr://"):
			ssr = n
		case strings.HasPrefix(n, "ss://"):
			ss = n
		}
	}
	if ssr == "" || ss == "" {
		t.Fatalf("兩條都要有：%v", nodes)
	}
	if !strings.Contains(ssr, "tls1.2_ticket_auth") {
		t.Errorf("ssr 的 obfs 沒帶過去：%s", ssr)
	}
	if strings.Contains(ss, "tls1.2_ticket_auth") {
		t.Errorf("ss 那條被 ssr 的 obfs 污染了：%s", ss)
	}
	// sing-box 的 mode 要換成 dae 認得的 obfs 名稱，否則 dae 回 unsupported obfs。
	// link 的 query 是 URL 編碼的，要比對就得先還原。
	if !strings.Contains(mustUnescape(ss), "obfs=http") {
		t.Errorf("ss 的 plugin-opts mode 沒換名成 obfs：%s", ss)
	}
}

func mustUnescape(s string) string {
	v, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return v
}
